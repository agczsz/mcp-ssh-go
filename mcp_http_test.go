package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (t bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header = request.Header.Clone()
	request.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(request)
}

func TestMCPHTTPBearerAndLiveTools(t *testing.T) {
	settings, err := openSettings(t.TempDir() + "/settings.json")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := openInventory(t.TempDir() + "/servers.json")
	if err != nil {
		t.Fatal(err)
	}
	app := &server{store: newStore(), inventory: inventory, settings: settings, secrets: memorySecrets{}}
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	registeredTools := enabledTools(settings.get())
	registerTools(mcpServer, app, registeredTools)
	guiHandler := (&guiState{
		app: app, settings: settings, mcpServer: mcpServer, registeredTools: registeredTools,
	}).handler()
	const token = "test-secret-token"
	httpServer := httptest.NewServer(newMCPHTTPHandler(mcpServer, token))
	defer httpServer.Close()

	request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	response := httptest.NewRecorder()
	httpServer.Config.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("unauthenticated request returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/wrong", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	httpServer.Config.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("non-MCP path returned %d, want 404", response.Code)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	httpClient := &http.Client{Transport: bearerRoundTripper{token: token, base: http.DefaultTransport}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientSession, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL + "/mcp", HTTPClient: httpClient, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect to Streamable HTTP endpoint: %v", err)
	}
	defer clientSession.Close()

	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != len(allToolNames) {
		t.Fatalf("initial tool count = %d, want %d", len(listed.Tools), len(allToolNames))
	}

	guiRequest := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"enabled_tools":["ssh_exec"],"allow_adhoc_host":false}`))
	guiRequest.RemoteAddr = "127.0.0.1:12345"
	guiRequest.Host = "127.0.0.1:2224"
	guiRequest.Header.Set("Origin", "http://127.0.0.1:2224")
	guiResponse := httptest.NewRecorder()
	guiHandler.ServeHTTP(guiResponse, guiRequest)
	if guiResponse.Code != http.StatusNoContent {
		t.Fatalf("save settings returned %d: %s", guiResponse.Code, guiResponse.Body.String())
	}

	listed, err = clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 1 || listed.Tools[0].Name != "ssh_exec" {
		t.Fatalf("live tool list = %v, want only ssh_exec", listed.Tools)
	}
}
