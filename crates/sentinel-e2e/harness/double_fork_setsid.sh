#!/bin/sh
# E2E harness: double-fork + setsid pattern for TREE-05 reparenting test.
#
# Process tree at fork-time:
#   sh (root)               <- sentinel run wraps this
#     └── sh (intermediate, exits immediately after setsid)
#         └── sh (grandchild, attempts a connection)
#
# When the intermediate exits, the grandchild is reparented to launchd.
# Sentinel's process tree (plan 02-04) records tracked_root at fork time only,
# so the grandchild's tracked_root still points at the original root sh —
# the grandchild's connect must therefore be subject to enforcement.
#
# This harness is a SOFT smoke test for the dispatch path; the hard
# data-structure-level invariant for TREE-05 lives in plan 02-04's
# process_tree_tests::tree_05_grandchild_inherits_original_root.

# Spawn a backgrounded subshell that double-forks via setsid and probes a
# deny target. We don't assert on the grandchild's exit code — its stdout
# is consumed by the wrapping sentinel run's pipe. The wrapped sh root's
# job is simply to NOT fail-closed at fork (which would happen if the
# daemon were unreachable; D-33 / fail-closed-on-fork).
(
    setsid sh -c '
        # In the grandchild now (setsid creates a new session). Try to connect
        # to a deny target. python3 is always present on macOS (Apple-shipped
        # /usr/bin/python3 is hardened-runtime; harness/python under setsid
        # may or may not see DYLD env vars depending on macOS version, so we
        # treat ANY exit as acceptable — the test asserts the wrapping sh
        # itself completed cleanly).
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "
import socket, sys
try:
    s = socket.create_connection(('"'"'discord.com'"'"', 443), timeout=2)
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
" 2>/dev/null
        else
            true
        fi
    ' </dev/null >/dev/null 2>&1
) &

# Wait briefly for the grandchild to start its connect attempt, then exit
# the root sh. The intermediate (the setsid sh) exits as soon as it execs
# the grandchild python3; the grandchild gets reparented.
sleep 1
exit 0
