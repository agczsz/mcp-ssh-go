package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var serverIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

var allToolNames = []string{
	"ssh_list_servers", "ssh_connect", "ssh_disconnect", "ssh_exec",
	"ssh_quick_exec", "ssh_list_dir", "ssh_upload", "ssh_download",
}

type serverConfig struct {
	ID                string `json:"id"`
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
	Enabled           bool   `json:"enabled"`
	Notes             string `json:"notes,omitempty"`
	ConnectTimeoutSec int    `json:"connect_timeout_sec,omitempty"`
}

type inventoryFile struct {
	Version int            `json:"version"`
	Servers []serverConfig `json:"servers"`
}

type inventoryStore struct {
	mu      sync.RWMutex
	path    string
	servers map[string]serverConfig
}

type appSettings struct {
	EnabledTools   []string `json:"enabled_tools"`
	AllowAdhocHost bool     `json:"allow_adhoc_host"`
}

type settingsFile struct {
	EnabledTools   []string `json:"enabled_tools"`
	AllowAdhocHost *bool    `json:"allow_adhoc_host"`
}

type settingsStore struct {
	mu   sync.RWMutex
	path string
	data appSettings
}

func executableDir() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(path), nil
}

func openInventory(path string) (*inventoryStore, error) {
	store := &inventoryStore{path: path, servers: make(map[string]serverConfig)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read server inventory: %w", err)
	}
	var file inventoryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse server inventory: %w", err)
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported server inventory version %d", file.Version)
	}
	for _, item := range file.Servers {
		item = normalizeServer(item)
		if err := validateServer(item); err != nil {
			return nil, fmt.Errorf("invalid server %q: %w", item.ID, err)
		}
		if _, exists := store.servers[item.ID]; exists {
			return nil, fmt.Errorf("duplicate server id %q", item.ID)
		}
		store.servers[item.ID] = item
	}
	return store, nil
}

func normalizeServer(item serverConfig) serverConfig {
	if item.Port == 0 {
		item.Port = 22
	}
	if item.Socks5Host != "" && item.Socks5Port == 0 {
		item.Socks5Port = 1080
	}
	return item
}

func validateServer(item serverConfig) error {
	if !serverIDPattern.MatchString(item.ID) {
		return fmt.Errorf("id must contain only letters, digits, dot, underscore, or hyphen")
	}
	if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Host) == "" {
		return fmt.Errorf("name and host are required")
	}
	if item.Port == 0 {
		item.Port = 22
	}
	if item.Port < 1 || item.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	switch item.AuthMethod {
	case "agent", "password":
		if item.IdentityFile != "" {
			return fmt.Errorf("identity_file is only valid for key authentication")
		}
	case "key":
		if strings.TrimSpace(item.IdentityFile) == "" {
			return fmt.Errorf("identity_file is required for key authentication")
		}
	default:
		return fmt.Errorf("auth_method must be agent, key, or password")
	}
	if item.Jump == item.ID {
		return fmt.Errorf("a server cannot jump through itself")
	}
	if item.Socks5Host == "" {
		if item.Socks5Port != 0 || item.Socks5Username != "" {
			return fmt.Errorf("SOCKS5 port and username require a SOCKS5 host")
		}
	} else {
		if strings.TrimSpace(item.Socks5Host) != item.Socks5Host || strings.ContainsAny(item.Socks5Host, "\t\r\n /") {
			return fmt.Errorf("SOCKS5 host must be a hostname or IP without a port")
		}
		host := item.Socks5Host
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if strings.Contains(host, ":") {
			if _, err := netip.ParseAddr(host); err != nil {
				return fmt.Errorf("SOCKS5 host must be a hostname or IP without a port")
			}
		}
		if item.Socks5Port != 0 && (item.Socks5Port < 1 || item.Socks5Port > 65535) {
			return fmt.Errorf("SOCKS5 port must be between 1 and 65535")
		}
		if strings.TrimSpace(item.Jump) != "" && !strings.EqualFold(strings.TrimSpace(item.Jump), "none") {
			return fmt.Errorf("a target cannot use both SOCKS5 and ProxyJump; configure SOCKS5 on the jump host instead")
		}
	}
	if item.ConnectTimeoutSec < 0 || item.ConnectTimeoutSec > 300 {
		return fmt.Errorf("connect_timeout_sec must be between 0 and 300")
	}
	return nil
}

func (s *inventoryStore) list() []serverConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]serverConfig, 0, len(s.servers))
	for _, item := range s.servers {
		items = append(items, item)
	}
	sortServers(items)
	return items
}

func (s *inventoryStore) get(id string) (serverConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.servers[id]
	return item, ok
}

func (s *inventoryStore) put(item serverConfig) error {
	item = normalizeServer(item)
	if err := validateServer(item); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := make(map[string]serverConfig, len(s.servers)+1)
	for id, current := range s.servers {
		updated[id] = current
	}
	updated[item.ID] = item
	if err := writeJSONAtomic(s.path, inventoryFile{Version: 1, Servers: mapServers(updated)}); err != nil {
		return fmt.Errorf("save server inventory: %w", err)
	}
	s.servers = updated
	return nil
}

func (s *inventoryStore) delete(id string) (serverConfig, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.servers[id]
	if !ok {
		return serverConfig{}, false, nil
	}
	updated := make(map[string]serverConfig, len(s.servers)-1)
	for key, current := range s.servers {
		if key != id {
			updated[key] = current
		}
	}
	if err := writeJSONAtomic(s.path, inventoryFile{Version: 1, Servers: mapServers(updated)}); err != nil {
		return serverConfig{}, false, fmt.Errorf("save server inventory: %w", err)
	}
	s.servers = updated
	return item, true, nil
}

func (s *inventoryStore) replace(items []serverConfig) error {
	updated := make(map[string]serverConfig, len(items))
	for _, item := range items {
		item = normalizeServer(item)
		if err := validateServer(item); err != nil {
			return fmt.Errorf("invalid server %q: %w", item.ID, err)
		}
		if _, exists := updated[item.ID]; exists {
			return fmt.Errorf("duplicate server id %q", item.ID)
		}
		updated[item.ID] = item
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeJSONAtomic(s.path, inventoryFile{Version: 1, Servers: mapServers(updated)}); err != nil {
		return fmt.Errorf("save server inventory: %w", err)
	}
	s.servers = updated
	return nil
}

func openSettings(path string) (*settingsStore, error) {
	defaults := appSettings{EnabledTools: append([]string{}, allToolNames...), AllowAdhocHost: true}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &settingsStore{path: path, data: defaults}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	var file settingsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}
	if file.EnabledTools != nil {
		defaults.EnabledTools = file.EnabledTools
	}
	if file.AllowAdhocHost != nil {
		defaults.AllowAdhocHost = *file.AllowAdhocHost
	}
	if err := validateSettings(defaults); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}
	return &settingsStore{path: path, data: defaults}, nil
}

func validateSettings(settings appSettings) error {
	known := make(map[string]bool, len(allToolNames))
	for _, name := range allToolNames {
		known[name] = true
	}
	seen := make(map[string]bool, len(settings.EnabledTools))
	for _, name := range settings.EnabledTools {
		if !known[name] {
			return fmt.Errorf("unknown enabled tool %q", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate enabled tool %q", name)
		}
		seen[name] = true
	}
	return nil
}

func (s *settingsStore) get() appSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data := s.data
	data.EnabledTools = append([]string{}, data.EnabledTools...)
	return data
}

func (s *settingsStore) update(data appSettings) error {
	if err := validateSettings(data); err != nil {
		return err
	}
	data.EnabledTools = append([]string{}, data.EnabledTools...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeJSONAtomic(s.path, data); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	s.data = data
	return nil
}

func enabledTools(settings appSettings) map[string]bool {
	names := settings.EnabledTools
	if raw := strings.TrimSpace(os.Getenv("SSH_MCP_ENABLED_TOOLS")); raw != "" {
		names = strings.Split(raw, ",")
	}
	enabled := make(map[string]bool, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		for _, known := range allToolNames {
			if name == known {
				enabled[name] = true
				break
			}
		}
	}
	return enabled
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mcp-ssh-go-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func mapServers(servers map[string]serverConfig) []serverConfig {
	items := make([]serverConfig, 0, len(servers))
	for _, item := range servers {
		items = append(items, item)
	}
	sortServers(items)
	return items
}

func sortServers(items []serverConfig) {
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
}
