package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed web/index.html
var webFiles embed.FS

type guiState struct {
	app             *server
	settings        *settingsStore
	mcpServer       *mcp.Server
	registeredTools map[string]bool
	writeMu         sync.Mutex
	toolsMu         sync.Mutex
}

type guiServerWrite struct {
	ID                string `json:"id,omitempty"`
	Name              string `json:"name"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	User              string `json:"user,omitempty"`
	AuthMethod        string `json:"auth_method"`
	IdentityFile      string `json:"identity_file,omitempty"`
	Jump              string `json:"jump,omitempty"`
	Socks5Host        string `json:"socks5_host,omitempty"`
	Socks5Port        int    `json:"socks5_port,omitempty"`
	Socks5Username    string `json:"socks5_username,omitempty"`
	Socks5Password    string `json:"socks5_password,omitempty"`
	ClearSocks5Pass   bool   `json:"clear_socks5_password,omitempty"`
	Enabled           bool   `json:"enabled"`
	Notes             string `json:"notes,omitempty"`
	ConnectTimeoutSec int    `json:"connect_timeout_sec,omitempty"`
	Password          string `json:"password,omitempty"`
	Passphrase        string `json:"passphrase,omitempty"`
	ClearPassword     bool   `json:"clear_password,omitempty"`
	ClearPassphrase   bool   `json:"clear_passphrase,omitempty"`
}

type guiServerView struct {
	serverConfig
	Address           string `json:"address"`
	HasPassword       bool   `json:"has_password"`
	HasPassphrase     bool   `json:"has_passphrase"`
	HasSocks5Password bool   `json:"has_socks5_password"`
}

type guiSettingsView struct {
	appSettings
	EffectiveTools []string `json:"effective_enabled_tools"`
	EnvOverride    bool     `json:"environment_override"`
}

const guiAddr = "127.0.0.1:2224"

func startGUI(app *server, mcpServer *mcp.Server, registeredTools map[string]bool) (*http.Server, net.Listener, error) {
	listener, err := net.Listen("tcp", guiAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on %s: %w", guiAddr, err)
	}
	state := &guiState{
		app: app, settings: app.settings, mcpServer: mcpServer,
		registeredTools: registeredTools,
	}
	return &http.Server{Handler: state.handler(), ReadHeaderTimeout: 5 * time.Second}, listener, nil
}

func (g *guiState) syncEnabledTools() {
	if g.mcpServer == nil {
		return
	}
	g.toolsMu.Lock()
	defer g.toolsMu.Unlock()
	next := enabledTools(g.settings.get())
	syncTools(g.mcpServer, g.app, g.registeredTools, next)
	g.registeredTools = next
}

func (g *guiState) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.index)
	mux.HandleFunc("/api/servers", g.servers)
	mux.HandleFunc("/api/servers/", g.serverByID)
	mux.HandleFunc("/api/settings", g.settingsAPI)
	mux.HandleFunc("/api/agent", g.agentAPI)
	mux.HandleFunc("/api/tools", g.toolsAPI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(remoteHost) == nil || !net.ParseIP(remoteHost).IsLoopback() {
			http.Error(w, "loopback access only", http.StatusForbidden)
			return
		}
		host := r.Host
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		if host != "127.0.0.1" && !strings.EqualFold(host, "localhost") {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete {
			if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
				http.Error(w, "cross-site request rejected", http.StatusForbidden)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Scheme != "http" || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (g *guiState) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	data, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (g *guiState) servers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := g.app.inventory.list()
		out := make([]guiServerView, 0, len(items))
		for _, item := range items {
			view := guiServerView{serverConfig: item, Address: serverAddress(item)}
			_, err := g.app.secrets.Get(passwordKey(item.ID))
			view.HasPassword = err == nil
			_, err = g.app.secrets.Get(passphraseKey(item.ID))
			view.HasPassphrase = err == nil
			_, err = g.app.secrets.Get(socks5PasswordKey(item.ID))
			view.HasSocks5Password = err == nil
			out = append(out, view)
		}
		writeJSON(w, out)
	case http.MethodPut:
		var body inventoryFile
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Servers == nil || (body.Version != 0 && body.Version != 1) {
			writeError(w, http.StatusBadRequest, "servers and supported inventory version are required")
			return
		}
		g.writeMu.Lock()
		defer g.writeMu.Unlock()
		old := g.app.inventory.list()
		keep := make(map[string]serverConfig, len(body.Servers))
		for _, item := range body.Servers {
			if err := validateServer(item); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if _, exists := keep[item.ID]; exists {
				writeError(w, http.StatusBadRequest, "duplicate server id")
				return
			}
			keep[item.ID] = item
		}
		var changes []secretChange
		for _, item := range old {
			updated, ok := keep[item.ID]
			if !ok {
				changes = append(changes,
					secretChange{key: passwordKey(item.ID), clear: true},
					secretChange{key: passphraseKey(item.ID), clear: true},
					secretChange{key: socks5PasswordKey(item.ID), clear: true},
				)
				continue
			}
			if item.AuthMethod == "password" && updated.AuthMethod != "password" {
				changes = append(changes, secretChange{key: passwordKey(item.ID), clear: true})
			}
			if item.AuthMethod == "key" && updated.AuthMethod != "key" {
				changes = append(changes, secretChange{key: passphraseKey(item.ID), clear: true})
			}
			if item.Socks5Username != "" && updated.Socks5Username == "" {
				changes = append(changes, secretChange{key: socks5PasswordKey(item.ID), clear: true})
			}
		}
		rollback, err := g.applySecrets(changes)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "cannot update the system keyring")
			return
		}
		for _, item := range body.Servers {
			if item.AuthMethod == "password" {
				if _, err := g.app.secrets.Get(passwordKey(item.ID)); err != nil {
					rollback()
					writeError(w, http.StatusBadRequest, "password authentication requires a password saved in the system keyring")
					return
				}
			}
			if item.Socks5Username != "" {
				if _, err := g.app.secrets.Get(socks5PasswordKey(item.ID)); err != nil {
					rollback()
					if errors.Is(err, errSecretNotFound) {
						writeError(w, http.StatusBadRequest, "SOCKS5 authentication requires a password saved in the system keyring")
					} else {
						writeError(w, http.StatusServiceUnavailable, "cannot read SOCKS5 credentials from the system keyring")
					}
					return
				}
			}
		}
		if err := g.app.inventory.replace(body.Servers); err != nil {
			rollback()
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (g *guiState) serverByID(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/servers/"), "/"), "/")
	if len(parts) == 2 && parts[1] == "test" {
		g.testServer(w, r, parts[0])
		return
	}
	if len(parts) != 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	switch r.Method {
	case http.MethodGet:
		item, ok := g.app.inventory.get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		view := guiServerView{serverConfig: item}
		_, err := g.app.secrets.Get(passwordKey(item.ID))
		view.HasPassword = err == nil
		_, err = g.app.secrets.Get(passphraseKey(item.ID))
		view.HasPassphrase = err == nil
		_, err = g.app.secrets.Get(socks5PasswordKey(item.ID))
		view.HasSocks5Password = err == nil
		writeJSON(w, view)
	case http.MethodPut:
		var body guiServerWrite
		if !decodeJSON(w, r, &body) {
			return
		}
		g.writeMu.Lock()
		defer g.writeMu.Unlock()
		if body.ID != "" && body.ID != id {
			writeError(w, http.StatusBadRequest, "server id cannot be changed")
			return
		}
		old, existed := g.app.inventory.get(id)
		body.ID = id
		item := serverConfig{
			ID: body.ID, Name: body.Name, Host: body.Host, Port: body.Port, User: body.User,
			AuthMethod: body.AuthMethod, IdentityFile: body.IdentityFile, Jump: body.Jump,
			Socks5Host: body.Socks5Host, Socks5Port: body.Socks5Port, Socks5Username: body.Socks5Username,
			Enabled: body.Enabled, Notes: body.Notes, ConnectTimeoutSec: body.ConnectTimeoutSec,
		}
		if err := validateServer(item); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if body.Password != "" && item.AuthMethod != "password" {
			writeError(w, http.StatusBadRequest, "password is only accepted for password authentication")
			return
		}
		if body.Passphrase != "" && item.AuthMethod != "key" {
			writeError(w, http.StatusBadRequest, "passphrase is only accepted for key authentication")
			return
		}
		if body.Socks5Password != "" && item.Socks5Username == "" {
			writeError(w, http.StatusBadRequest, "SOCKS5 password requires a SOCKS5 username")
			return
		}
		changes := []secretChange{
			{key: passwordKey(id), value: body.Password, set: body.Password != "", clear: body.ClearPassword || (existed && old.AuthMethod == "password" && item.AuthMethod != "password")},
			{key: passphraseKey(id), value: body.Passphrase, set: body.Passphrase != "", clear: body.ClearPassphrase || (existed && old.AuthMethod == "key" && item.AuthMethod != "key")},
			{key: socks5PasswordKey(id), value: body.Socks5Password, set: body.Socks5Password != "", clear: body.ClearSocks5Pass || (existed && old.Socks5Username != "" && item.Socks5Username == "")},
		}
		rollback, err := g.applySecrets(changes)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "cannot update the system keyring")
			return
		}
		if item.AuthMethod == "password" {
			if _, err := g.app.secrets.Get(passwordKey(id)); err != nil {
				rollback()
				writeError(w, http.StatusBadRequest, "password authentication requires a password saved in the system keyring")
				return
			}
		}
		if item.Socks5Username != "" {
			if _, err := g.app.secrets.Get(socks5PasswordKey(id)); err != nil {
				rollback()
				if errors.Is(err, errSecretNotFound) {
					writeError(w, http.StatusBadRequest, "SOCKS5 authentication requires a password saved in the system keyring")
				} else {
					writeError(w, http.StatusServiceUnavailable, "cannot read SOCKS5 credentials from the system keyring")
				}
				return
			}
		}
		if err := g.app.inventory.put(item); err != nil {
			rollback()
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"saved": true})
	case http.MethodDelete:
		g.writeMu.Lock()
		defer g.writeMu.Unlock()
		if _, ok := g.app.inventory.get(id); !ok {
			http.NotFound(w, r)
			return
		}
		rollback, err := g.applySecrets([]secretChange{{key: passwordKey(id), clear: true}, {key: passphraseKey(id), clear: true}, {key: socks5PasswordKey(id), clear: true}})
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "cannot update the system keyring")
			return
		}
		if _, ok, err := g.app.inventory.delete(id); err != nil {
			rollback()
			writeError(w, http.StatusInternalServerError, "cannot save the server inventory")
			return
		} else if !ok {
			rollback()
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

type secretChange struct {
	key   string
	value string
	set   bool
	clear bool
}

type secretSnapshot struct {
	key     string
	value   string
	present bool
}

func (g *guiState) applySecrets(changes []secretChange) (func(), error) {
	snapshots := make([]secretSnapshot, 0, len(changes))
	rollback := func() {
		for i := len(snapshots) - 1; i >= 0; i-- {
			_ = restoreSecret(g.app.secrets, snapshots[i])
		}
	}
	for _, change := range changes {
		old, err := g.app.secrets.Get(change.key)
		if err != nil && !errors.Is(err, errSecretNotFound) {
			rollback()
			return nil, err
		}
		snapshot := secretSnapshot{key: change.key, value: old, present: err == nil}
		if !change.set && !change.clear {
			continue
		}
		if change.clear {
			err = g.app.secrets.Delete(change.key)
		} else {
			err = g.app.secrets.Set(change.key, change.value)
		}
		if err != nil {
			_ = restoreSecret(g.app.secrets, snapshot)
			rollback()
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return rollback, nil
}

func restoreSecret(secrets secretStore, snapshot secretSnapshot) error {
	if snapshot.present {
		return secrets.Set(snapshot.key, snapshot.value)
	}
	return secrets.Delete(snapshot.key)
}

func (g *guiState) testServer(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	target, err := g.app.resolveTarget(id, "", "", "", true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, err := dialResolved(g.app.cfg, g.app.inventory, g.settings, g.app.secrets, target)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer sess.close()
	writeJSON(w, map[string]any{"ok": true, "server_version": string(sess.client.ServerVersion())})
}

func (g *guiState) settingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := g.settings.get()
		effective := enabledTools(data)
		tools := make([]string, 0, len(effective))
		for _, name := range allToolNames {
			if effective[name] {
				tools = append(tools, name)
			}
		}
		writeJSON(w, guiSettingsView{
			appSettings: data, EffectiveTools: tools,
			EnvOverride: strings.TrimSpace(os.Getenv("SSH_MCP_ENABLED_TOOLS")) != "",
		})
	case http.MethodPut:
		var data appSettings
		if !decodeJSON(w, r, &data) {
			return
		}
		if err := g.settings.update(data); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		g.syncEnabledTools()
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (g *guiState) toolsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	enabled := enabledTools(g.settings.get())
	type toolView struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
	}
	out := make([]toolView, 0, len(toolDefinitions))
	for _, tool := range toolDefinitions {
		out = append(out, toolView{Name: tool.name, Description: tool.description, Enabled: enabled[tool.name]})
	}
	writeJSON(w, out)
}

func (g *guiState) agentAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	available, count, message := agentStatus()
	writeJSON(w, map[string]any{"available": available, "signer_count": count, "message": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain one JSON value")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", "GET, PUT, POST, DELETE")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
