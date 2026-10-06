# mcp-ssh-go

A minimal, **security-first SSH [MCP](https://modelcontextprotocol.io) server** — a
single static Go binary (no Node/npm, no Python, no runtime) that gives an AI agent
a deliberately small, auditable set of SSH capabilities over authenticated Streamable HTTP.

Most SSH MCP servers expose *everything*: interactive PTYs, `sudo`/`su`, port
forwarding, dozens of tools. That's a large, hard-to-audit authority surface. This
one takes the opposite stance: **eight discrete, loggable operations and nothing
else.** No interactive terminal, no privilege escalation, no tunnels, no shell-escape
vectors. Every tool call is one bounded action with a captured result.

## Tools

| Tool | Purpose |
|------|---------|
| `ssh_list_servers` | List named local servers without exposing secrets or key paths |
| `ssh_connect` | Open a session from the inventory or `~/.ssh/config` (incl. ProxyJump) and store it under an id |
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
- **Small and auditable.** The Go implementation is split into focused files for transport, authentication, inventory, and file transfer.

## Configuration

Connections resolve first from the local server inventory, then from `~/.ssh/config`
when ad-hoc hosts are enabled. Inventory entries support `ssh-agent`, private-key,
and password authentication; passwords and encrypted-key passphrases are stored only
in the operating system keyring. Agent authentication uses `SSH_AUTH_SOCK` on Unix or
the OpenSSH agent pipe on Windows and never falls back to password authentication.

Start the executable manually. It serves the MCP Streamable HTTP endpoint at
`http://127.0.0.1:2223/mcp` and the embedded GUI at `http://127.0.0.1:2224`.
Both addresses are fixed; startup fails if either required port is unavailable.
The MCP endpoint requires `Authorization: Bearer <token>` from
`SSH_MCP_AUTH_TOKEN`. The GUI can be disabled with `SSH_MCP_GUI=0`.

`servers.json` and `settings.json` live beside the running executable. The GUI
shares the same stores as MCP, so saved server and tool settings apply immediately.
Claude Desktop's Tool permissions are a separate permission layer; this server does
not implement Ask/Allow. Host keys use `~/.ssh/known_hosts` with accept-new semantics
(unknown hosts are recorded; a *changed* key is rejected).

Each inventory server can optionally use a SOCKS5 host and port. SOCKS5 usernames
are stored in `servers.json`; their passwords remain in the OS keyring. A server
cannot combine SOCKS5 with ProxyJump, but a jump host can use its own SOCKS5 route.

The previous Windows data directory was
`%APPDATA%\mcp-ssh-go`. Copy `servers.json` and
`settings.json` from there beside the new executable if present; leave the old
folder intact. Passwords and key passphrases are in the OS keyring, not those files.

### Environment variables

| Variable | Effect |
|----------|--------|
| `SSH_MCP_AUTH_TOKEN` | Required bearer token for MCP HTTP requests; use a high-entropy value with no whitespace. |
| `SSH_MCP_ALLOWED_KEY_DIRS` | Colon/comma-separated extra directories from which private keys and `ssh_config` may be read, in addition to `~/.ssh` and `/etc/ssh`. Useful where `$HOME` is a symlink to an NFS/AD home. |
| `SSH_MCP_ENABLED_TOOLS` | Comma-separated tool list that overrides `settings.json` when non-empty (default: all eight). |
| `SSH_MCP_GUI` | Set to `0` to disable the local management GUI. |
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

## Docker (Linux/amd64)

Build on Linux or with Docker Buildx:

```sh
docker buildx build --platform linux/amd64 --load -t mcp-ssh-go:local .
```

Run on a Linux host with host networking so the fixed loopback listeners are
available on the host. The named volume at `/app` keeps JSON data beside the
binary; the entrypoint refreshes that binary from the image each start.

```sh
docker volume create mcp-ssh-go-data
docker run --rm --network host \
  --env-file "$HOME/.config/mcp-ssh-go.env" \
  -v mcp-ssh-go-data:/app \
  -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \
  mcp-ssh-go:local
```

The env file must contain `SSH_MCP_AUTH_TOKEN=<high-entropy-token>` and should
be readable only by its owner. Omit the agent socket mount when using key-file
authentication; mount the key directory read-only and set
`SSH_MCP_ALLOWED_KEY_DIRS` to its container path. Do not bake keys or tokens into
the image. The container does not include or automatically share the host's
Secret Service; host networking does not expose session D-Bus. SSH password
authentication, encrypted-key passphrases, and SOCKS5 passwords require a
reachable Linux Secret Service and D-Bus session, explicitly mounted/configured
with an allowed container UID. Otherwise, use the mounted SSH agent or key files.

## Use with an MCP client

Configure the MCP client to connect to the already-running HTTP endpoint. Adapt this
shape to the client's HTTP transport configuration and provide the same bearer token
without committing it to a shared config file:

```json
{
  "mcpServers": {
    "ssh": {
      "type": "http",
      "url": "http://127.0.0.1:2223/mcp",
      "headers": {
        "Authorization": "Bearer <SSH_MCP_AUTH_TOKEN>"
      }
    }
  }
}
```

When exposing the service beyond localhost, keep the process bound to loopback and
use a reverse proxy to terminate TLS and forward the Authorization header. The
container example below is for Linux hosts and uses host networking so the same
loopback endpoints remain available.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
