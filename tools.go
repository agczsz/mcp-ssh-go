package main

import "github.com/modelcontextprotocol/go-sdk/mcp"

type toolDefinition struct {
	name        string
	description string
	annotations *mcp.ToolAnnotations
}

func boolHint(value bool) *bool { return &value }

var toolDefinitions = []toolDefinition{
	{"ssh_list_servers", "List named SSH servers from the local inventory (id, display name, user@host:port, authentication method, and enabled state). Does not return secrets or key paths. Call this before ssh_connect when using saved servers.", &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolHint(false)}},
	{"ssh_connect", "Open an SSH session and store it under an id. Prefer server (an inventory id from ssh_list_servers). Authentication comes from the inventory (ssh-agent, key file, or stored password); never pass secrets. Falls back to ~/.ssh/config host aliases when ad-hoc hosts are enabled. Host keys use ~/.ssh/known_hosts with accept-new behavior. Use the returned id with ssh_exec, ssh_list_dir, ssh_upload, and ssh_download.", &mcp.ToolAnnotations{DestructiveHint: boolHint(false), OpenWorldHint: boolHint(true)}},
	{"ssh_disconnect", "Close a stored SSH session returned by ssh_connect. This does not affect remote files or processes.", &mcp.ToolAnnotations{DestructiveHint: boolHint(false), IdempotentHint: true, OpenWorldHint: boolHint(false)}},
	{"ssh_exec", "Run a non-interactive command on a stored SSH session. Returns stdout, stderr, and exit code. Output over the per-stream cap (default 128 KB) is returned as head+tail with a truncation marker; narrow with head/tail/grep, or raise max_output_bytes (max 512 KB). The command may modify or delete remote data; use ssh_list_dir or ssh_download for inspection. No PTY is available.", &mcp.ToolAnnotations{DestructiveHint: boolHint(true), OpenWorldHint: boolHint(true)}},
	{"ssh_quick_exec", "Connect to a saved server or enabled ad-hoc host, run one non-interactive command, and disconnect. Authentication and output-cap rules match ssh_connect and ssh_exec. The command may modify or delete remote data; no PTY is available.", &mcp.ToolAnnotations{DestructiveHint: boolHint(true), OpenWorldHint: boolHint(true)}},
	{"ssh_list_dir", "List entries in a remote directory over SFTP using a stored SSH session id. Returns at most 2000 entries and the total count. Credentials come from the session established by ssh_connect; do not pass secrets.", &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolHint(true)}},
	{"ssh_upload", "Upload a local file to a remote path over SFTP using a stored SSH session id. The destination file is overwritten if it already exists. Credentials come from the session established by ssh_connect; do not pass secrets.", &mcp.ToolAnnotations{DestructiveHint: boolHint(true), OpenWorldHint: boolHint(true)}},
	{"ssh_download", "Download a remote file to a local path over SFTP using a stored SSH session id. The local destination is created or overwritten. Credentials come from the session established by ssh_connect; do not pass secrets.", &mcp.ToolAnnotations{DestructiveHint: boolHint(true), OpenWorldHint: boolHint(true)}},
}

func registerTools(srv *mcp.Server, s *server, enabled map[string]bool) {
	for _, def := range toolDefinitions {
		if enabled[def.name] {
			registerTool(srv, s, def)
		}
	}
}

func syncTools(srv *mcp.Server, s *server, current, next map[string]bool) {
	for name, enabled := range current {
		if enabled && !next[name] {
			srv.RemoveTools(name)
		}
	}
	for _, def := range toolDefinitions {
		if next[def.name] && !current[def.name] {
			registerTool(srv, s, def)
		}
	}
}

func registerTool(srv *mcp.Server, s *server, def toolDefinition) {
	tool := &mcp.Tool{Name: def.name, Description: def.description, Annotations: def.annotations}
	switch def.name {
	case "ssh_list_servers":
		mcp.AddTool(srv, tool, s.listServers)
	case "ssh_connect":
		mcp.AddTool(srv, tool, s.connect)
	case "ssh_disconnect":
		mcp.AddTool(srv, tool, s.disconnect)
	case "ssh_exec":
		mcp.AddTool(srv, tool, s.exec)
	case "ssh_quick_exec":
		mcp.AddTool(srv, tool, s.quickExec)
	case "ssh_list_dir":
		mcp.AddTool(srv, tool, s.listDir)
	case "ssh_upload":
		mcp.AddTool(srv, tool, s.upload)
	case "ssh_download":
		mcp.AddTool(srv, tool, s.download)
	}
}
