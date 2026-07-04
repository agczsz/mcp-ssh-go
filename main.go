// Command mcp-ssh-go is a minimal, security-first SSH MCP server: a single
// static Go binary (no Node/npm, no runtime) that exposes exactly seven
// least-privilege tools over stdio. It deliberately omits interactive PTY,
// sudo/su, port-forwarding and shell-escape surfaces — every call is a
// discrete, loggable operation.
//
// Tools: ssh_connect, ssh_disconnect, ssh_exec, ssh_quick_exec, ssh_list_dir,
// ssh_upload, ssh_download.
//
// Env knobs:
//   SSH_MCP_ALLOWED_KEY_DIRS  colon/comma-separated extra dirs from which private
//                             keys and ssh_config may be read (in addition to
//                             ~/.ssh and /etc/ssh). Needed where $HOME is a
//                             symlink to an NFS/AD home.
//   SSH_MCP_ENABLED_TOOLS     comma-separated allow-list to further restrict the
//                             seven tools at runtime (default: all seven).
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kevinburke/ssh_config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const dialTimeout = 20 * time.Second

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

type session struct {
	client *ssh.Client
	jump   *ssh.Client // non-nil when reached via ProxyJump; closed with the session
}

type store struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newStore() *store { return &store{sessions: map[string]*session{}} }

func (s *store) put(id string, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.sessions[id]; old != nil {
		old.close()
	}
	s.sessions[id] = sess
}

func (s *store) get(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *store) del(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	return sess, ok
}

func (sess *session) close() {
	if sess.client != nil {
		_ = sess.client.Close()
	}
	if sess.jump != nil {
		_ = sess.jump.Close()
	}
}

// ---------------------------------------------------------------------------
// Key / config file guard
// ---------------------------------------------------------------------------

// allowedDirs returns the real paths of directories from which key and config
// files may be read: ~/.ssh, /etc/ssh, plus SSH_MCP_ALLOWED_KEY_DIRS. Both the
// symlinked and resolved forms are included so a symlinked $HOME (NFS/AD) works.
func allowedDirs() []string {
	var dirs []string
	add := func(p string) {
		if p == "" {
			return
		}
		dirs = append(dirs, filepath.Clean(p))
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			dirs = append(dirs, filepath.Clean(rp))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".ssh"))
	}
	add("/etc/ssh")
	for _, extra := range strings.FieldsFunc(os.Getenv("SSH_MCP_ALLOWED_KEY_DIRS"), func(r rune) bool {
		return r == ':' || r == ','
	}) {
		add(strings.TrimSpace(extra))
	}
	return dirs
}

// readGuarded reads a file only if its resolved path is within an allowed dir.
func readGuarded(path string) ([]byte, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", path, err)
	}
	dir := filepath.Dir(real)
	for _, ad := range allowedDirs() {
		if dir == ad || strings.HasPrefix(dir+string(os.PathSeparator), ad+string(os.PathSeparator)) {
			return os.ReadFile(real)
		}
	}
	return nil, fmt.Errorf("path %q is outside the allowed key/config directories", path)
}

// ---------------------------------------------------------------------------
// ssh_config resolution
// ---------------------------------------------------------------------------

func userSSHConfig() *ssh_config.Config {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	f, err := os.Open(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return nil
	}
	defer f.Close()
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return nil
	}
	return cfg
}

// stripQuotes removes a single pair of surrounding single or double quotes, the
// way OpenSSH does. mcp-ssh's original parser kept them, breaking IdentityFile.
func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func localUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// resolved holds the connection parameters for a host after config + overrides.
type resolved struct {
	hostName  string
	port      string
	user      string
	identity  []string // candidate private-key paths, in order
	proxyJump string   // host alias to jump through (single hop), or ""
}

func resolveHost(cfg *ssh_config.Config, alias, userOverride, portOverride string) resolved {
	get := func(key string) string {
		if cfg == nil {
			return ""
		}
		v, _ := cfg.Get(alias, key)
		return stripQuotes(v)
	}
	r := resolved{
		hostName:  firstNonEmpty(get("HostName"), alias),
		port:      firstNonEmpty(portOverride, get("Port"), "22"),
		user:      firstNonEmpty(userOverride, get("User"), localUsername()),
		proxyJump: get("ProxyJump"),
	}
	// Collect IdentityFile from ALL matching Host blocks, the way OpenSSH does
	// (the directive is cumulative). Taking only the first match meant a broad
	// "Host *" IdentityFile shadowed a host-specific key later in the file, so
	// the wrong key was offered and target auth failed even though plain ssh
	// (which offers every candidate) succeeded.
	if cfg != nil {
		if idfs, err := cfg.GetAll(alias, "IdentityFile"); err == nil {
			for _, idf := range idfs {
				if idf = stripQuotes(idf); idf != "" {
					r.identity = append(r.identity, expandHome(idf))
				}
			}
		}
	}
	// Fall back to common default keys if the config specified none.
	if len(r.identity) == 0 {
		if home, err := os.UserHomeDir(); err == nil {
			for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
				p := filepath.Join(home, ".ssh", name)
				if _, err := os.Stat(p); err == nil {
					r.identity = append(r.identity, p)
				}
			}
		}
	}
	return r
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Auth + host-key verification
// ---------------------------------------------------------------------------

func authMethods(identity []string) ([]ssh.AuthMethod, error) {
	var signers []ssh.Signer
	for _, path := range identity {
		key, err := readGuarded(path)
		if err != nil {
			continue // skip unreadable/guarded keys; try the next
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no usable private key found (checked: %s)", strings.Join(identity, ", "))
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

// hostKeyCallback verifies against ~/.ssh/known_hosts, adding unknown hosts
// (accept-new, matching OpenSSH StrictHostKeyChecking=accept-new). A key that
// CHANGED for a known host is rejected.
func hostKeyCallback() ssh.HostKeyCallback {
	home, err := os.UserHomeDir()
	if err != nil {
		return ssh.InsecureIgnoreHostKey() // no home: degrade rather than fail
	}
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	_ = os.MkdirAll(filepath.Dir(khPath), 0o700)
	if _, err := os.Stat(khPath); os.IsNotExist(err) {
		_ = os.WriteFile(khPath, nil, 0o600)
	}
	verify, err := knownhosts.New(khPath)
	if err != nil {
		return ssh.InsecureIgnoreHostKey()
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		// KeyError with no known keys = unknown host → accept-new (append).
		if ok := asKeyError(err, &keyErr); ok && len(keyErr.Want) == 0 {
			return appendKnownHost(khPath, hostname, remote, key)
		}
		return err // changed/mismatched key → reject
	}
}

func asKeyError(err error, target **knownhosts.KeyError) bool {
	if ke, ok := err.(*knownhosts.KeyError); ok {
		*target = ke
		return true
	}
	return false
}

func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	addrs := []string{hostname}
	if remote != nil {
		addrs = append(addrs, remote.String())
	}
	line := knownhosts.Line(addrs, key)
	_, err = f.WriteString(line + "\n")
	return err
}

// ---------------------------------------------------------------------------
// Dial (with single-hop ProxyJump)
// ---------------------------------------------------------------------------

func dial(cfg *ssh_config.Config, alias, userOverride, portOverride string) (*session, error) {
	r := resolveHost(cfg, alias, userOverride, portOverride)
	auth, err := authMethods(r.identity)
	if err != nil {
		return nil, err
	}
	clientCfg := &ssh.ClientConfig{
		User:            r.user,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback(),
		Timeout:         dialTimeout,
	}
	target := net.JoinHostPort(r.hostName, r.port)

	if r.proxyJump == "" || strings.EqualFold(r.proxyJump, "none") {
		client, err := ssh.Dial("tcp", target, clientCfg)
		if err != nil {
			return nil, fmt.Errorf("dial %s@%s: %w", r.user, target, err)
		}
		return &session{client: client}, nil
	}

	// Jump through the ProxyJump host, then open the target over that channel.
	jr := resolveHost(cfg, r.proxyJump, "", "")
	jAuth, err := authMethods(jr.identity)
	if err != nil {
		return nil, fmt.Errorf("proxyjump %s: %w", r.proxyJump, err)
	}
	jCfg := &ssh.ClientConfig{
		User:            jr.user,
		Auth:            jAuth,
		HostKeyCallback: hostKeyCallback(),
		Timeout:         dialTimeout,
	}
	jumpClient, err := ssh.Dial("tcp", net.JoinHostPort(jr.hostName, jr.port), jCfg)
	if err != nil {
		return nil, fmt.Errorf("dial jump %s@%s: %w", jr.user, net.JoinHostPort(jr.hostName, jr.port), err)
	}
	conn, err := jumpClient.Dial("tcp", target)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("tunnel to %s via %s: %w", target, r.proxyJump, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, target, clientCfg)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("handshake to %s via %s: %w", target, r.proxyJump, err)
	}
	return &session{client: ssh.NewClient(ncc, chans, reqs), jump: jumpClient}, nil
}

// ---------------------------------------------------------------------------
// Tool I/O types
// ---------------------------------------------------------------------------

type connectIn struct {
	Host string `json:"host" jsonschema:"host alias (resolved via ~/.ssh/config) or hostname"`
	ID   string `json:"id,omitempty" jsonschema:"session id to store the connection under (default: host)"`
	User string `json:"user,omitempty" jsonschema:"login user override (default: config User, else local username)"`
	Port string `json:"port,omitempty" jsonschema:"port override (default: config Port, else 22)"`
}
type connectOut struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type disconnectIn struct {
	ID string `json:"id" jsonschema:"session id returned by ssh_connect"`
}
type statusOut struct {
	Status string `json:"status"`
}

type execIn struct {
	ID      string `json:"id" jsonschema:"session id returned by ssh_connect"`
	Command string `json:"command" jsonschema:"command to run on the remote host"`
}
type quickExecIn struct {
	Host    string `json:"host" jsonschema:"host alias or hostname"`
	Command string `json:"command" jsonschema:"command to run"`
	User    string `json:"user,omitempty"`
	Port    string `json:"port,omitempty"`
}
type execOut struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

type listDirIn struct {
	ID   string `json:"id" jsonschema:"session id returned by ssh_connect"`
	Path string `json:"path" jsonschema:"remote directory to list"`
}
type dirEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	IsDir bool   `json:"is_dir"`
}
type listDirOut struct {
	Path    string     `json:"path"`
	Entries []dirEntry `json:"entries"`
}

type uploadIn struct {
	ID        string `json:"id" jsonschema:"session id returned by ssh_connect"`
	LocalPath string `json:"local_path" jsonschema:"local file path to upload"`
	RemotePath string `json:"remote_path" jsonschema:"destination path on the remote host"`
}
type downloadIn struct {
	ID         string `json:"id" jsonschema:"session id returned by ssh_connect"`
	RemotePath string `json:"remote_path" jsonschema:"remote file path to download"`
	LocalPath  string `json:"local_path" jsonschema:"local destination path"`
}
type xferOut struct {
	Status string `json:"status"`
	Bytes  int64  `json:"bytes"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

type server struct {
	cfg   *ssh_config.Config
	store *store
}

func (s *server) connect(_ context.Context, _ *mcp.CallToolRequest, in connectIn) (*mcp.CallToolResult, connectOut, error) {
	if strings.TrimSpace(in.Host) == "" {
		return nil, connectOut{}, fmt.Errorf("host is required")
	}
	sess, err := dial(s.cfg, in.Host, in.User, in.Port)
	if err != nil {
		return nil, connectOut{}, err
	}
	id := firstNonEmpty(in.ID, in.Host)
	s.store.put(id, sess)
	return nil, connectOut{ID: id, Status: "connected"}, nil
}

func (s *server) disconnect(_ context.Context, _ *mcp.CallToolRequest, in disconnectIn) (*mcp.CallToolResult, statusOut, error) {
	sess, ok := s.store.del(in.ID)
	if !ok {
		return nil, statusOut{}, fmt.Errorf("no session with id %q", in.ID)
	}
	sess.close()
	return nil, statusOut{Status: "disconnected"}, nil
}

func runCommand(client *ssh.Client, command string) (execOut, error) {
	sshSession, err := client.NewSession()
	if err != nil {
		return execOut{}, err
	}
	defer sshSession.Close()
	var stdout, stderr strings.Builder
	sshSession.Stdout = &stdout
	sshSession.Stderr = &stderr
	runErr := sshSession.Run(command)
	out := execOut{Stdout: stdout.String(), Stderr: stderr.String()}
	if runErr == nil {
		return out, nil
	}
	if exitErr, ok := runErr.(*ssh.ExitError); ok {
		out.ExitCode = exitErr.ExitStatus()
		return out, nil // non-zero exit is a result, not a tool error
	}
	return out, runErr
}

func (s *server) exec(_ context.Context, _ *mcp.CallToolRequest, in execIn) (*mcp.CallToolResult, execOut, error) {
	sess, ok := s.store.get(in.ID)
	if !ok {
		return nil, execOut{}, fmt.Errorf("no session with id %q; call ssh_connect first", in.ID)
	}
	out, err := runCommand(sess.client, in.Command)
	return nil, out, err
}

func (s *server) quickExec(_ context.Context, _ *mcp.CallToolRequest, in quickExecIn) (*mcp.CallToolResult, execOut, error) {
	sess, err := dial(s.cfg, in.Host, in.User, in.Port)
	if err != nil {
		return nil, execOut{}, err
	}
	defer sess.close()
	out, err := runCommand(sess.client, in.Command)
	return nil, out, err
}

func (s *server) listDir(_ context.Context, _ *mcp.CallToolRequest, in listDirIn) (*mcp.CallToolResult, listDirOut, error) {
	sess, ok := s.store.get(in.ID)
	if !ok {
		return nil, listDirOut{}, fmt.Errorf("no session with id %q", in.ID)
	}
	sc, err := sftp.NewClient(sess.client)
	if err != nil {
		return nil, listDirOut{}, err
	}
	defer sc.Close()
	infos, err := sc.ReadDir(in.Path)
	if err != nil {
		return nil, listDirOut{}, err
	}
	out := listDirOut{Path: in.Path}
	for _, fi := range infos {
		out.Entries = append(out.Entries, dirEntry{
			Name:  fi.Name(),
			Size:  fi.Size(),
			Mode:  fi.Mode().String(),
			IsDir: fi.IsDir(),
		})
	}
	return nil, out, nil
}

func (s *server) upload(_ context.Context, _ *mcp.CallToolRequest, in uploadIn) (*mcp.CallToolResult, xferOut, error) {
	sess, ok := s.store.get(in.ID)
	if !ok {
		return nil, xferOut{}, fmt.Errorf("no session with id %q", in.ID)
	}
	sc, err := sftp.NewClient(sess.client)
	if err != nil {
		return nil, xferOut{}, err
	}
	defer sc.Close()
	src, err := os.Open(in.LocalPath)
	if err != nil {
		return nil, xferOut{}, err
	}
	defer src.Close()
	dst, err := sc.Create(in.RemotePath)
	if err != nil {
		return nil, xferOut{}, err
	}
	defer dst.Close()
	n, err := dst.ReadFrom(src)
	if err != nil {
		return nil, xferOut{}, err
	}
	return nil, xferOut{Status: "uploaded", Bytes: n}, nil
}

func (s *server) download(_ context.Context, _ *mcp.CallToolRequest, in downloadIn) (*mcp.CallToolResult, xferOut, error) {
	sess, ok := s.store.get(in.ID)
	if !ok {
		return nil, xferOut{}, fmt.Errorf("no session with id %q", in.ID)
	}
	sc, err := sftp.NewClient(sess.client)
	if err != nil {
		return nil, xferOut{}, err
	}
	defer sc.Close()
	src, err := sc.Open(in.RemotePath)
	if err != nil {
		return nil, xferOut{}, err
	}
	defer src.Close()
	dst, err := os.Create(in.LocalPath)
	if err != nil {
		return nil, xferOut{}, err
	}
	defer dst.Close()
	n, err := src.WriteTo(dst)
	if err != nil {
		return nil, xferOut{}, err
	}
	return nil, xferOut{Status: "downloaded", Bytes: n}, nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func enabledTools() map[string]bool {
	all := []string{"ssh_connect", "ssh_disconnect", "ssh_exec", "ssh_quick_exec", "ssh_list_dir", "ssh_upload", "ssh_download"}
	raw := strings.TrimSpace(os.Getenv("SSH_MCP_ENABLED_TOOLS"))
	if raw == "" {
		m := map[string]bool{}
		for _, t := range all {
			m[t] = true
		}
		return m
	}
	m := map[string]bool{}
	for _, t := range strings.Split(raw, ",") {
		m[strings.TrimSpace(t)] = true
	}
	return m
}

func main() {
	// Line-buffered stderr for diagnostics; stdout is the MCP transport.
	log := bufio.NewWriter(os.Stderr)
	defer log.Flush()

	s := &server{cfg: userSSHConfig(), store: newStore()}
	srv := mcp.NewServer(&mcp.Implementation{Name: "mcp-ssh-go", Version: version}, nil)

	on := enabledTools()
	if on["ssh_connect"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "ssh_connect", Description: "Open an SSH session (resolves ~/.ssh/config incl. ProxyJump) and store it under an id."}, s.connect)
	}
	if on["ssh_disconnect"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "ssh_disconnect", Description: "Close a stored SSH session."}, s.disconnect)
	}
	if on["ssh_exec"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "ssh_exec", Description: "Run a command on a stored SSH session and return stdout, stderr and exit code."}, s.exec)
	}
	if on["ssh_quick_exec"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "ssh_quick_exec", Description: "Connect, run one command, and disconnect (stateless)."}, s.quickExec)
	}
	if on["ssh_list_dir"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "ssh_list_dir", Description: "List a remote directory over SFTP."}, s.listDir)
	}
	if on["ssh_upload"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "ssh_upload", Description: "Upload a local file to the remote host over SFTP."}, s.upload)
	}
	if on["ssh_download"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "ssh_download", Description: "Download a remote file to the local host over SFTP."}, s.download)
	}

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-ssh-go:", err)
		os.Exit(1)
	}
}
