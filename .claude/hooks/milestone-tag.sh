#!/usr/bin/env bash
# milestone-tag.sh — PostToolUse hook: auto-tag on milestone completion
#
# Watches for gsd_complete_milestone / gsd_milestone_complete MCP calls.
# Extracts the milestone title, parses a version from it (e.g. "v0.3 — …"),
# and creates an annotated git tag if one doesn't already exist.
#
# Expects JSON on stdin with tool_input containing milestoneId, title, etc.

set -euo pipefail

INPUT=$(cat)

# Extract milestone title from tool input
TITLE=$(echo "$INPUT" | node -e "
  let d='';
  process.stdin.on('data', c => d += c);
  process.stdin.on('end', () => {
    try {
      const inp = JSON.parse(d);
      process.stdout.write(inp.tool_input?.title || '');
    } catch { }
  });
" 2>/dev/null)

if [ -z "$TITLE" ]; then
  exit 0
fi

# Extract version tag from title (matches v0.3, v1.0, v2.1.4, etc.)
VERSION=$(echo "$TITLE" | grep -oE 'v[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)

if [ -z "$VERSION" ]; then
  exit 0
fi

# Don't re-tag if it already exists
if git rev-parse "$VERSION" >/dev/null 2>&1; then
  exit 0
fi

# Create annotated tag
git tag -a "$VERSION" -m "$TITLE"

node -e '
  const version = process.argv[1];
  const title = process.argv[2];
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: "Auto-tagged " + version + " (" + title + ")",
      tagged: true,
      version: version,
    },
  }));
' "$VERSION" "$TITLE"
