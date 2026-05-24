#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${HEAD_SHA:?HEAD_SHA is required}"

for _ in {1..60}; do
  run_json=$(gh run list \
    --repo "$GITHUB_REPOSITORY" \
    --workflow pr-validation.yml \
    --event pull_request \
    --commit "$HEAD_SHA" \
    --limit 1 \
    --json databaseId,status,conclusion,url \
    --jq '.[0] // empty')

  if [ -z "$run_json" ]; then
    echo "Waiting for PR validation run for $HEAD_SHA..."
    sleep 10
    continue
  fi

  status=$(jq -r '.status' <<< "$run_json")
  conclusion=$(jq -r '.conclusion // ""' <<< "$run_json")
  url=$(jq -r '.url' <<< "$run_json")
  echo "PR validation: status=$status conclusion=${conclusion:-pending} url=$url"

  if [ "$status" = "completed" ] && [ "$conclusion" = "success" ]; then
    exit 0
  fi
  if [ "$status" = "completed" ]; then
    echo "::error::PR validation did not pass for $HEAD_SHA: $conclusion"
    exit 1
  fi
  sleep 10
done

echo "::error::Timed out waiting for PR validation for $HEAD_SHA"
exit 1
