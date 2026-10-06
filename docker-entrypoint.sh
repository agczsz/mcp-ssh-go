#!/bin/sh
set -eu

cp /usr/local/bin/mcp-ssh-go /app/mcp-ssh-go
chmod 0755 /app/mcp-ssh-go
exec /app/mcp-ssh-go "$@"
