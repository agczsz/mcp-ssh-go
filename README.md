# mcp-ssh-go

A minimal, **security-first SSH [MCP](https://modelcontextprotocol.io) server** — a
single static Go binary (no Node/npm, no Python, no runtime) that gives an AI agent
a deliberately small, auditable set of SSH capabilities over stdio.

Most SSH MCP servers expose *everything*: interactive PTYs, `sudo`/`su`, port
forwarding, dozens of tools. That's a large, hard-to-audit authority surface. This
one takes the opposite stance: **seven discrete, loggable operations and nothing
else.** No interactive terminal, no privilege escalation, no tunnels, no shell-escape
vectors. Every tool call is one bounded action with a captured result.

## Tools

| Tool | Purpose |
|------|---------|
| `ssh_connect` | Open a session (resolves `~/.ssh/config`, incl. ProxyJump) and store it under an id |
| `ssh_disconnect` | Close a stored session |
| `ssh_exec` | Run a command on a stored session; returns stdout, stderr, exit code |
| `ssh_quick_exec` | Connect, run one command, disconnect (stateless) |
| `ssh_list_dir` | List a remote directory over SFTP |
| `ssh_upload` | Upload a local file over SFTP |
| `ssh_download` | Download a remote file over SFTP |

Deliberately **not** included: PTY / interactive shells, `sudo`/`su`, port
forwarding, batch/parallel exec. Command execution is non-interactive by design.

## Why single-binary

- **No package-manager runtime.** No `node_modules`, no `pip` tree — nothing to
  supply-chain-compromise at install time. Just one compiled binary you can hash and
  pin.
- **Static and portable.** `CGO_ENABLED=0` builds run anywhere with no dependencies;
  cross-compiles to Linux, Windows, and macOS from one host.
- **Small and auditable.** ~550 lines; you can read the whole thing.

## Configuration

Connections resolve through `~/.ssh/config` like OpenSSH — `HostName`, `User`,
`Port`, `IdentityFile` (surrounding quotes stripped), and single-hop `ProxyJump`
are honored. When no user is configured, it falls back to the local username. Host
keys are verified against `~/.ssh/known_hosts` with accept-new semantics (unknown
hosts are added; a *changed* key is rejected).

### Environment variables

| Variable | Effect |
|----------|--------|
| `SSH_MCP_ALLOWED_KEY_DIRS` | Colon/comma-separated extra directories from which private keys and `ssh_config` may be read, in addition to `~/.ssh` and `/etc/ssh`. Useful where `$HOME` is a symlink to an NFS/AD home. |
| `SSH_MCP_ENABLED_TOOLS` | Comma-separated allow-list to further restrict which of the seven tools are exposed (default: all seven). |
| `SSH_MCP_MAX_OUTPUT_BYTES` | Default per-stream (stdout, stderr) cap on exec output returned to the client (default 131072, clamped to [1024, 524288]). |

### Output caps

`ssh_exec` / `ssh_quick_exec` results are capped per stream (default 128 KB,
per-call override `max_output_bytes` up to 512 KB). Overflowing output comes back
as the first ~75% + last ~25% of the cap with an inline marker stating how much
was dropped and how to narrow the command (`head`/`tail`/`grep`) — so an agent
that `cat`s a multi-MB log gets a usable, self-correcting result instead of a
tool result larger than its context window. `ssh_list_dir` similarly returns at
most 2000 entries (plus the true total).

#### Sizing the cap for your model

The cap is denominated in **bytes**, but the limit it protects is denominated in
**tokens** — and the ratio between them depends heavily on what the command
prints:

| Output | Approx. bytes/token | 128 KB is roughly |
|--------|--------------------|-------------------|
| Prose, source code, ordinary logs | ~4 | 32k tokens |
| Dense numeric / tabular output (e.g. `2.651954E+02` columns) | ~1.7 | 78k tokens |

So the same 128 KB default that is comfortable for logs can be **over half the
context window of a 128k model, and larger than the entire window of a 32k or
64k one** — the deployments most likely to point this server at solver output, a
data dump, or a wide CSV. Two such results in one session will exceed a 128k
window on their own.

**Size `SSH_MCP_MAX_OUTPUT_BYTES` against your model's context window, not
against the byte figure.** A rough rule for numeric-heavy workloads: pick a cap
of about `context_tokens × 1.7 ÷ 4` bytes, so that a capped result costs at most
a quarter of the window and several fit in one session alongside the
conversation. Worked example: a 128k-token model reading numeric output gives
~54 KB; rounding down to **48 KB** (`SSH_MCP_MAX_OUTPUT_BYTES=49152`) adds
headroom and leaves a 36 KB head + 12 KB tail — roughly four capped reads per
session.

The head+tail split matters for the same reason: batch and solver output tends
to put its banner and configuration at the top and its results and summary
statistics at the bottom, so keeping both ends usually preserves the parts a
question is actually about. Head-only truncation of such a file returns the
configuration and discards every result.

Raise the limit for a single call with the `max_output_bytes` parameter (up to
512 KB) rather than raising the default for every call.

## Build

```sh
go build -o mcp-ssh-go .
# cross-compile:
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o mcp-ssh-go .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o mcp-ssh-go.exe .
```

## Use with an MCP client

Register it as a stdio MCP server. Example (Crush / Claude-style `mcp` config):

```json
{
  "mcp": {
    "ssh": {
      "type": "stdio",
      "command": "/usr/local/bin/mcp-ssh-go",
      "env": { "SSH_MCP_ALLOWED_KEY_DIRS": "/uhome/EXAMPLE" },
      "timeout": 600
    }
  }
}
```

The agent still needs the user's own `~/.ssh/config` host entries and keys.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
