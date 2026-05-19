#!/bin/bash
# Turn this fixture directory into a real .git repo so gix can clone it via
# file://. Tests call this script with $1 = absolute path of a tempdir copy
# of the fixture (so the source tree never carries .git/).
set -euo pipefail
cd "${1:?absolute path required}"

if [ ! -d .git ]; then
    git init --quiet --initial-branch=main
    git config user.email "fixture@sentinel.test"
    git config user.name "Sentinel Fixture"
fi

git add -A
git commit --quiet -m "fixture commit" || true

git rev-parse HEAD
