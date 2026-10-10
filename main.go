// Command mcp-ssh-go is a minimal, security-first SSH MCP server: a single
// static Go binary (no Node/npm, no runtime) that exposes eight least-privilege
// tools over stdio. It deliberately omits interactive PTY, sudo/su,
// port-forwarding and shell-escape surfaces — every call is a discrete,
// loggable operation.
//
// Tools: ssh_list_servers, ssh_connect, ssh_disconnect, ssh_exec, ssh_quick_exec,
// ssh_list_dir, ssh_upload, ssh_download.
//
// The optional local GUI listens on 127.0.0.1:2224. JSON data is stored beside
// this executable.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"os/signal"

	"github.com/kevinburke/ssh_config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"
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

func resolveHost(cfg *ssh_config.Config, alias, userOverride, portOverride string) resolved {
	get := func(key string) string {
		if cfg == nil {
			return ""
		}
		v, _ := cfg.Get(alias, key)
		return stripQuotes(v)
	}
	r := resolved{
		hostName:   firstNonEmpty(get("HostName"), alias),
		port:       firstNonEmpty(portOverride, get("Port"), "22"),
		user:       firstNonEmpty(userOverride, get("User"), localUsername()),
		proxyJump:  get("ProxyJump"),
		authMethod: "key",
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

func serverAddress(item serverConfig) string {
	port := item.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(item.Host, fmt.Sprint(port))
	if user := firstNonEmpty(item.User, localUsername()); user != "" {
		return user + "@" + address
	}
	return address
}

// ---------------------------------------------------------------------------
// Auth + host-key verification
// ---------------------------------------------------------------------------

// hostKeyCallback verifies against ~/.ssh/known_hosts, adding unknown hosts
// (accept-new, matching OpenSSH StrictHostKeyChecking=accept-new). A key that
// CHANGED for a known host is rejected.
func hostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("find home directory for known_hosts: %w", err)
	}
	return hostKeyCallbackAt(filepath.Join(home, ".ssh", "known_hosts"))
}

func hostKeyCallbackAt(path string) (ssh.HostKeyCallback, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create known_hosts directory: %w", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil && !os.IsExist(createErr) {
			return nil, fmt.Errorf("create known_hosts: %w", createErr)
		}
		if f != nil {
			if err := f.Close(); err != nil {
				return nil, fmt.Errorf("close known_hosts: %w", err)
			}
		}
	} else if err != nil {
		return nil, fmt.Errorf("stat known_hosts: %w", err)
	}
	verify, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if ok := asKeyError(err, &keyErr); ok && len(keyErr.Want) == 0 {
			return appendKnownHost(path, hostname, remote, key)
		}
		return err
	}, nil
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

func resolveInventoryTarget(item serverConfig, userOverride, portOverride string) resolved {
	port := fmt.Sprint(item.Port)
	if item.Port == 0 {
		port = "22"
	}
	identity := []string(nil)
	if item.IdentityFile != "" {
		identity = []string{expandHome(item.IdentityFile)}
	}
	return resolved{
		hostName:       item.Host,
		port:           firstNonEmpty(portOverride, port),
		user:           firstNonEmpty(userOverride, item.User, localUsername()),
		identity:       identity,
		proxyJump:      item.Jump,
		socks5Host:     item.Socks5Host,
		socks5Port:     item.Socks5Port,
		socks5Username: item.Socks5Username,
		authMethod:     item.AuthMethod,
		credentialID:   item.ID,
		timeoutSec:     item.ConnectTimeoutSec,
	}
}

func (s *server) resolveTarget(serverID, host, user, port string, allowDisabled bool) (resolved, error) {
	name := strings.TrimSpace(serverID)
	if name == "" {
		name = strings.TrimSpace(host)
	}
	if name == "" {
		return resolved{}, fmt.Errorf("server or host is required")
	}
	if item, ok := s.inventory.get(name); ok {
		if !allowDisabled && !item.Enabled {
			return resolved{}, fmt.Errorf("server %q is disabled in the local inventory", name)
		}
		return resolveInventoryTarget(item, user, port), nil
	}
	if serverID != "" {
		return resolved{}, fmt.Errorf("server %q was not found in the local inventory", serverID)
	}
	if !s.settings.get().AllowAdhocHost {
		return resolved{}, fmt.Errorf("ad-hoc hosts are disabled; add this host to the local inventory")
	}
	return resolveHost(s.cfg, name, user, port), nil
}

type proxyTimeoutDialer time.Duration

func (d proxyTimeoutDialer) Dial(network, address string) (net.Conn, error) {
	timeout := time.Duration(d)
	conn, err := (&net.Dialer{Timeout: timeout}).Dial(network, address)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func sshClientFromConn(conn net.Conn, address string, clientConfig *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, address, clientConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = ncc.Close()
		return nil, err
	}
	return ssh.NewClient(ncc, chans, reqs), nil
}

func dialSSHClient(target resolved, clientConfig *ssh.ClientConfig, timeout time.Duration, secrets secretStore) (*ssh.Client, error) {
	address := net.JoinHostPort(target.hostName, target.port)
	if target.socks5Host == "" {
		return ssh.Dial("tcp", address, clientConfig)
	}
	port := target.socks5Port
	if port == 0 {
		port = 1080
	}
	host := target.socks5Host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	var auth *proxy.Auth
	if target.socks5Username != "" {
		if target.credentialID == "" {
			return nil, fmt.Errorf("SOCKS5 authentication requires an inventory server")
		}
		password, err := secrets.Get(socks5PasswordKey(target.credentialID))
		if err != nil {
			if errors.Is(err, errSecretNotFound) {
				return nil, fmt.Errorf("no SOCKS5 password is stored for server %q; set it in the local GUI", target.credentialID)
			}
			return nil, fmt.Errorf("read SOCKS5 password from the system keyring: %w", err)
		}
		auth = &proxy.Auth{User: target.socks5Username, Password: password}
	}
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, fmt.Sprint(port)), auth, proxyTimeoutDialer(timeout))
	if err != nil {
		return nil, fmt.Errorf("configure SOCKS5 proxy: %w", err)
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect through SOCKS5 proxy %s: %w", net.JoinHostPort(host, fmt.Sprint(port)), err)
	}
	return sshClientFromConn(conn, address, clientConfig, timeout)
}

func dialResolved(cfg *ssh_config.Config, inventory *inventoryStore, settings *settingsStore, secrets secretStore, target resolved) (*session, error) {
	auth, closeAuth, err := authMethods(target, secrets)
	if err != nil {
		return nil, err
	}
	defer closeAuth()
	callback, err := hostKeyCallback()
	if err != nil {
		return nil, err
	}
	timeout := dialTimeout
	if target.timeoutSec > 0 {
		timeout = time.Duration(target.timeoutSec) * time.Second
	}
	clientCfg := &ssh.ClientConfig{User: target.user, Auth: auth, HostKeyCallback: callback, Timeout: timeout}
	destination := net.JoinHostPort(target.hostName, target.port)
	if target.socks5Host != "" && target.proxyJump != "" && !strings.EqualFold(target.proxyJump, "none") {
		return nil, fmt.Errorf("a target cannot use both SOCKS5 and ProxyJump; configure SOCKS5 on the jump host instead")
	}

	if target.proxyJump == "" || strings.EqualFold(target.proxyJump, "none") {
		client, err := dialSSHClient(target, clientCfg, timeout, secrets)
		if err != nil {
			return nil, fmt.Errorf("dial %s@%s: %w", target.user, destination, err)
		}
		return &session{client: client}, nil
	}

	jump, err := (&server{cfg: cfg, inventory: inventory, settings: settings}).resolveTarget("", target.proxyJump, "", "", false)
	if err != nil {
		return nil, fmt.Errorf("resolve proxyjump %q: %w", target.proxyJump, err)
	}
	if jump.proxyJump != "" && !strings.EqualFold(jump.proxyJump, "none") {
		return nil, fmt.Errorf("proxyjump %q also has a jump configured; only one jump is supported", target.proxyJump)
	}
	jumpAuth, closeJumpAuth, err := authMethods(jump, secrets)
	if err != nil {
		return nil, fmt.Errorf("proxyjump %s: %w", target.proxyJump, err)
	}
	defer closeJumpAuth()
	jumpCallback, err := hostKeyCallback()
	if err != nil {
		return nil, err
	}
	jumpConfig := &ssh.ClientConfig{
		User:            jump.user,
		Auth:            jumpAuth,
		HostKeyCallback: jumpCallback,
		Timeout:         timeout,
	}
	jumpAddress := net.JoinHostPort(jump.hostName, jump.port)
	jumpClient, err := dialSSHClient(jump, jumpConfig, timeout, secrets)
	if err != nil {
		return nil, fmt.Errorf("dial jump %s@%s: %w", jump.user, jumpAddress, err)
	}
	conn, err := jumpClient.Dial("tcp", destination)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("tunnel to %s via %s: %w", destination, target.proxyJump, err)
	}
	client, err := sshClientFromConn(conn, destination, clientCfg, timeout)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("handshake to %s via %s: %w", destination, target.proxyJump, err)
	}
	return &session{client: client, jump: jumpClient}, nil
}

// ---------------------------------------------------------------------------
// Tool I/O types
// ---------------------------------------------------------------------------

type connectIn struct {
	Server string `json:"server,omitempty" jsonschema:"named server id from ssh_list_servers; takes priority over host"`
	Host   string `json:"host,omitempty" jsonschema:"ssh_config host alias or hostname when ad-hoc hosts are enabled"`
	ID     string `json:"id,omitempty" jsonschema:"session id to store the connection under (default: server id or host)"`
	User   string `json:"user,omitempty" jsonschema:"login user override"`
	Port   string `json:"port,omitempty" jsonschema:"port override"`
}
type connectOut struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type listServersIn struct{}
type serverSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	AuthMethod string `json:"auth_method"`
	Enabled    bool   `json:"enabled"`
}
type listServersOut struct {
	Servers []serverSummary `json:"servers"`
}

type disconnectIn struct {
	ID string `json:"id" jsonschema:"session id returned by ssh_connect"`
}
type statusOut struct {
	Status string `json:"status"`
}

type execIn struct {
	ID             string `json:"id" jsonschema:"session id returned by ssh_connect"`
	Command        string `json:"command" jsonschema:"command to run on the remote host"`
	MaxOutputBytes int    `json:"max_output_bytes,omitempty" jsonschema:"per-stream cap on returned bytes (default 131072, max 524288); overflow returns head+tail with a truncation marker"`
}
type quickExecIn struct {
	Server         string `json:"server,omitempty" jsonschema:"named server id from ssh_list_servers; takes priority over host"`
	Host           string `json:"host,omitempty" jsonschema:"ssh_config host alias or hostname when ad-hoc hosts are enabled"`
	Command        string `json:"command" jsonschema:"command to run"`
	User           string `json:"user,omitempty"`
	Port           string `json:"port,omitempty"`
	MaxOutputBytes int    `json:"max_output_bytes,omitempty" jsonschema:"per-stream cap on returned bytes (default 131072, max 524288); overflow returns head+tail with a truncation marker"`
}
type execOut struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
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
	Total   int        `json:"total"`
	Note    string     `json:"note,omitempty"`
}

type uploadIn struct {
	ID         string `json:"id" jsonschema:"session id returned by ssh_connect"`
	LocalPath  string `json:"local_path" jsonschema:"local file path to upload"`
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
	cfg       *ssh_config.Config
	store     *store
	inventory *inventoryStore
	settings  *settingsStore
	secrets   secretStore
}

func (s *server) connect(_ context.Context, _ *mcp.CallToolRequest, in connectIn) (*mcp.CallToolResult, connectOut, error) {
	target, err := s.resolveTarget(in.Server, in.Host, in.User, in.Port, false)
	if err != nil {
		return nil, connectOut{}, err
	}
	sess, err := dialResolved(s.cfg, s.inventory, s.settings, s.secrets, target)
	if err != nil {
		return nil, connectOut{}, err
	}
	id := firstNonEmpty(in.ID, in.Server, in.Host)
	s.store.put(id, sess)
	return nil, connectOut{ID: id, Status: "connected"}, nil
}

func (s *server) listServers(_ context.Context, _ *mcp.CallToolRequest, _ listServersIn) (*mcp.CallToolResult, listServersOut, error) {
	out := listServersOut{Servers: make([]serverSummary, 0)}
	for _, item := range s.inventory.list() {
		out.Servers = append(out.Servers, serverSummary{
			ID: item.ID, Name: item.Name, Address: serverAddress(item),
			AuthMethod: item.AuthMethod, Enabled: item.Enabled,
		})
	}
	return nil, out, nil
}

func (s *server) disconnect(_ context.Context, _ *mcp.CallToolRequest, in disconnectIn) (*mcp.CallToolResult, statusOut, error) {
	sess, ok := s.store.del(in.ID)
	if !ok {
		return nil, statusOut{}, fmt.Errorf("no session with id %q", in.ID)
	}
	sess.close()
	return nil, statusOut{Status: "disconnected"}, nil
}

func runCommand(client *ssh.Client, command string, maxOutputBytes int) (execOut, error) {
	sshSession, err := client.NewSession()
	if err != nil {
		return execOut{}, err
	}
	defer sshSession.Close()
	limit := clampOutputCap(maxOutputBytes)
	stdout, stderr := newCapWriter(limit), newCapWriter(limit)
	sshSession.Stdout = stdout
	sshSession.Stderr = stderr
	runErr := sshSession.Run(command)
	var out execOut
	out.Stdout, out.StdoutTruncated = stdout.result()
	out.Stderr, out.StderrTruncated = stderr.result()
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
	out, err := runCommand(sess.client, in.Command, in.MaxOutputBytes)
	return nil, out, err
}

func (s *server) quickExec(_ context.Context, _ *mcp.CallToolRequest, in quickExecIn) (*mcp.CallToolResult, execOut, error) {
	target, err := s.resolveTarget(in.Server, in.Host, in.User, in.Port, false)
	if err != nil {
		return nil, execOut{}, err
	}
	sess, err := dialResolved(s.cfg, s.inventory, s.settings, s.secrets, target)
	if err != nil {
		return nil, execOut{}, err
	}
	defer sess.close()
	out, err := runCommand(sess.client, in.Command, in.MaxOutputBytes)
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
	out := listDirOut{Path: in.Path, Total: len(infos)}
	if len(infos) > maxDirEntries {
		out.Note = fmt.Sprintf("returned first %d of %d entries; list a subdirectory or filter with ssh_exec (ls pattern, find)", maxDirEntries, len(infos))
		infos = infos[:maxDirEntries]
	}
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

func ensureWritableDataDir(path string) error {
	probe, err := os.CreateTemp(path, ".mcp-ssh-go-write-test-*")
	if err != nil {
		return fmt.Errorf("data directory %q is not writable: %w", path, err)
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove data directory write test: %w", err)
	}
	return nil
}

func run() error {
	base, err := executableDir()
	if err != nil {
		return fmt.Errorf("resolve executable directory: %w", err)
	}
	if err := ensureWritableDataDir(base); err != nil {
		return err
	}
	inventory, err := openInventory(filepath.Join(base, "servers.json"))
	if err != nil {
		return err
	}
	settings, err := openSettings(filepath.Join(base, "settings.json"))
	if err != nil {
		return err
	}
	secrets := systemKeyring{}
	s := &server{cfg: userSSHConfig(), store: newStore(), inventory: inventory, settings: settings, secrets: secrets}
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "mcp-ssh-go", Version: version}, nil)
	registeredTools := enabledTools(settings.get())
	registerTools(mcpServer, s, registeredTools)

	var guiHTTP *http.Server
	var guiListener net.Listener
	if os.Getenv("SSH_MCP_GUI") != "0" {
		guiHTTP, guiListener, err = startGUI(s, mcpServer, registeredTools)
		if err != nil {
			return fmt.Errorf("start local GUI: %w", err)
		}
		defer guiListener.Close()
		guiHTTP.ErrorLog = log.New(os.Stderr, "mcp-ssh-go GUI: ", 0)
		fmt.Fprintf(os.Stderr, "mcp-ssh-go GUI: http://%s\n", guiListener.Addr())
		go func() {
			if err := guiHTTP.Serve(guiListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(os.Stderr, "mcp-ssh-go GUI stopped: %v\n", err)
			}
		}()
	}
	fmt.Fprintln(os.Stderr, "mcp-ssh-go MCP: stdio")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = mcpServer.Run(ctx, &mcp.StdioTransport{})
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	if guiHTTP != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := guiHTTP.Shutdown(shutdownCtx); shutdownErr != nil {
			err = errors.Join(err, shutdownErr)
		}
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-ssh-go:", err)
		os.Exit(1)
	}
}
