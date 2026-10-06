package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type memorySecrets map[string]string

func (s memorySecrets) Get(key string) (string, error) {
	value, ok := s[key]
	if !ok {
		return "", errSecretNotFound
	}
	return value, nil
}

func (s memorySecrets) Set(key, value string) error {
	s[key] = value
	return nil
}

func (s memorySecrets) Delete(key string) error {
	delete(s, key)
	return nil
}

func TestGUISettingsAndSecrets(t *testing.T) {
	inventory, err := openInventory(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	item := serverConfig{ID: "edge", Name: "Edge", Host: "2001:db8::8", Port: 22, User: "root", AuthMethod: "password", Enabled: true}
	if err := inventory.put(item); err != nil {
		t.Fatal(err)
	}
	settings, err := openSettings(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	secrets := memorySecrets{passwordKey(item.ID): "gui-secret-canary"}
	app := &server{store: newStore(), inventory: inventory, settings: settings, secrets: secrets}
	handler := (&guiState{app: app, settings: settings}).handler()

	for host, want := range map[string]int{"localhost:2224": http.StatusOK, "evil.example": http.StatusForbidden} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "127.0.0.1:12345"
		request.Host = host
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Errorf("Host %q returned %d, want %d", host, response.Code, want)
		}
	}

	response := guiRequest(handler, http.MethodGet, "/api/servers", "", "")
	body, _ := io.ReadAll(response.Body)
	if response.Code != http.StatusOK || !strings.Contains(string(body), `"address":"root@[2001:db8::8]:22"`) || !strings.Contains(string(body), `"has_password":true`) {
		t.Fatalf("unexpected server response: status=%d body=%s", response.Code, body)
	}
	if strings.Contains(string(body), "gui-secret-canary") {
		t.Fatal("server response exposed a saved password")
	}

	response = guiRequest(handler, http.MethodPut, "/api/settings", `{"enabled_tools":["ssh_exec"],"allow_adhoc_host":false}`, "http://127.0.0.1:2224")
	if response.Code != http.StatusNoContent {
		t.Fatalf("settings update failed: status=%d", response.Code)
	}
	if got := settings.get(); got.AllowAdhocHost || len(got.EnabledTools) != 1 || got.EnabledTools[0] != "ssh_exec" {
		t.Fatalf("settings were not saved: %+v", got)
	}

	response = guiRequest(handler, http.MethodPut, "/api/settings", `{"enabled_tools":[],"allow_adhoc_host":true}`, "http://evil.example")
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin settings update returned %d", response.Code)
	}

	const newSecret = "another-gui-secret-canary"
	payload := `{"id":"new","name":"New server","host":"ssh.example","port":22,"user":"root","auth_method":"password","password":"` + newSecret + `","enabled":true}`
	response = guiRequest(handler, http.MethodPut, "/api/servers/new", payload, "http://127.0.0.1:2224")
	if response.Code != http.StatusOK {
		t.Fatalf("server creation failed: status=%d", response.Code)
	}
	stored, err := os.ReadFile(inventory.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), newSecret) {
		t.Fatal("inventory file persisted a password")
	}
	if secrets[passwordKey("new")] != newSecret {
		t.Fatal("password was not saved to the secret store")
	}
	response = guiRequest(handler, http.MethodGet, "/api/servers/new", "", "")
	body, _ = io.ReadAll(response.Body)
	if strings.Contains(string(body), newSecret) {
		t.Fatal("server response exposed the submitted password")
	}
}

func guiRequest(handler http.Handler, method, path, body, origin string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Host = "127.0.0.1:2224"
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
