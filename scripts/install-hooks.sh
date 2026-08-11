#!/usr/bin/env bash
# Points this clone's git hooks at .githooks/ and checks that the redaction
# pattern file exists.
#
# Run once per clone:  scripts/install-hooks.sh
#
# Hooks are per-clone and never travel with a push, so every machine that
# commits to this repo needs this. The CI check in
# .github/workflows/redaction-check.yml is the backstop for machines that skip
# it, and for merges made in the web UI where no hook can run.

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

chmod +x .githooks/*
git config core.hooksPath .githooks
echo "Hooks enabled: core.hooksPath -> .githooks"

PATTERNS="${SNAP_MCP_PATTERNS:-}"
if [ -n "$PATTERNS" ] && [ -s "$PATTERNS" ]; then
  echo "Pattern file found ($(wc -l < "$PATTERNS" | tr -d ' ') patterns)."
elif [ -n "$PATTERNS" ]; then
  echo ""
  echo "WARNING: SNAP_MCP_PATTERNS points at a missing or empty file."
  echo "  The pre-commit redaction check will refuse to run until it exists."
else
  echo ""
  echo "WARNING: SNAP_MCP_PATTERNS is not set."
  echo "  Export it from your shell profile, pointing at a file of redaction"
  echo "  patterns, one per line, mode 600. The pre-commit check will refuse to"
  echo "  run without it."
  echo "  Keep that file OUTSIDE this repo -- the denylist is itself sensitive,"
  echo "  and there is no default path here for the same reason."
fi
