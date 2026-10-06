package main

import (
	"os"
	"strings"
	"testing"
)

func TestAuthorizedAgentSmoke(t *testing.T) {
	host := strings.TrimSpace(os.Getenv("SSH_MCP_SMOKE_HOST"))
	if host == "" {
		t.Skip("set SSH_MCP_SMOKE_HOST to run the authorized SSH-agent smoke test")
	}
	target := resolved{
		hostName:   host,
		port:       firstNonEmpty(os.Getenv("SSH_MCP_SMOKE_PORT"), "22"),
		user:       firstNonEmpty(os.Getenv("SSH_MCP_SMOKE_USER"), "root"),
		authMethod: "agent",
	}
	sess, err := dialResolved(nil, nil, nil, systemKeyring{}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.close()

	out, err := runCommand(sess.client, "id -un && hostname", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("remote read-only smoke command exited %d: %s", out.ExitCode, out.Stderr)
	}
	t.Logf("remote identity and host: %s", strings.TrimSpace(out.Stdout))
}
