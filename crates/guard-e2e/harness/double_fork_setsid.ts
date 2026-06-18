#!/usr/bin/env bun
// E2E harness: double-fork + setsid pattern for TREE-05 reparenting test.

const probe = `
if command -v python3 >/dev/null 2>&1; then
  python3 -c "
import socket, sys
try:
    s = socket.create_connection(('discord.com', 443), timeout=2)
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
" 2>/dev/null
else
  true
fi
`;

Bun.spawn(["setsid", "sh", "-c", probe], {
  stdin: "ignore",
  stdout: "ignore",
  stderr: "ignore",
});

await Bun.sleep(1000);
process.exit(0);
