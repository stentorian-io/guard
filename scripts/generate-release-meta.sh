#!/usr/bin/env bash
# Generate release-meta.json for a tagged release.
# Usage: scripts/generate-release-meta.sh v1.0.0 [v0.9.0]
# Args:  $1 = new tag (required), $2 = previous tag (auto-detected if omitted)
set -euo pipefail

NEW_TAG="${1:?usage: generate-release-meta.sh <new-tag> [previous-tag]}"
VERSION="${NEW_TAG#v}"

# Auto-detect previous tag if not provided
if [ -n "${2:-}" ]; then
    PREV_TAG="$2"
else
    PREV_TAG=$(git describe --tags --abbrev=0 "${NEW_TAG}^" 2>/dev/null || echo "")
fi

RANGE="${PREV_TAG:+${PREV_TAG}..}${NEW_TAG}"

# Count new deny rules added in malicious-*.yaml files
DENY_RULE_COUNT=0
if [ -n "$PREV_TAG" ]; then
    DENY_RULE_COUNT=$(git diff "$PREV_TAG" "$NEW_TAG" -- \
        'crates/guard-core/data/malicious-*.yaml' \
        | grep -c '^+  - ' || true)
fi

SECURITY_FIXES=false
if git rev-parse --verify --quiet "${NEW_TAG}^{commit}" >/dev/null; then
    if git log --oneline "$RANGE" | grep -qi 'fix(security)'; then
        SECURITY_FIXES=true
    fi
fi

# Determine severity
SEVERITY="informational"
if [ "$DENY_RULE_COUNT" -gt 0 ] || [ "$SECURITY_FIXES" = "true" ]; then
    SEVERITY="critical"
fi

# Build one-line summary from git-cliff
if command -v git-cliff >/dev/null 2>&1 && [ -n "$PREV_TAG" ]; then
    SUMMARY=$(git cliff "$RANGE" --strip all 2>/dev/null \
        | head -20 \
        | grep -E '^\- ' \
        | head -3 \
        | sed 's/^- //' \
        | paste -sd '; ' -)
else
    COMMIT_COUNT=$(git rev-list --count "$RANGE" 2>/dev/null || echo "0")
    SUMMARY="${COMMIT_COUNT} commits since ${PREV_TAG:-initial}"
fi

if [ -z "$SUMMARY" ]; then
    SUMMARY="Release ${VERSION}"
fi

PUBLISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CHANGELOG_URL="https://github.com/stentorian-io/guard/releases/tag/${NEW_TAG}"

cat <<EOF
{
  "version": "${VERSION}",
  "severity": "${SEVERITY}",
  "summary": "${SUMMARY}",
  "deny_rule_count": ${DENY_RULE_COUNT},
  "security_fixes": ${SECURITY_FIXES},
  "published_at": "${PUBLISHED_AT}",
  "changelog_url": "${CHANGELOG_URL}"
}
EOF
