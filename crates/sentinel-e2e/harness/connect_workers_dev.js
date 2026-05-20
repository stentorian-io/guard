// E2E harness: attempt a TLS connect to a hostname provided via env var.
// Used by curated_deny.rs to verify ALLOW-06 abuse-pattern deny.
//
// Exit codes:
//   0 = connect succeeded (TEST FAIL — sentinel didn't block)
//   1 = connect failed with a Sentinel-deny errno class (TEST PASS)
//   2 = connect failed with an unexpected errno (TEST INDETERMINATE — investigate)
//   3 = timeout
//
// SENTINEL_TEST_DENY_HOST env var sets the host (default: sentinel-test.workers.dev).
// SENTINEL_TEST_DENY_PORT env var sets the port (default: 443).
//
// Why this harness exists distinctly from connect_evil.js:
//   connect_evil.js connects to discord.com (a host that resolves outside
//   Sentinel and is NOT in the curated allowlist). The deny path there fires
//   at default-deny (no entry matches).
//
//   connect_workers_dev.js connects to a *.workers.dev host. The deny path
//   here fires at the curated YAML's BuiltinDeny tier — a SUFFIX-MATCH deny
//   for ".workers.dev" with reason "Cloudflare Workers C2/exfil shared
//   subdomain (ALLOW-06)". The differential point is the suffix-match rule
//   firing on a host the user never explicitly listed.

const net = require('net');

const host = process.env.SENTINEL_TEST_DENY_HOST || 'sentinel-test.workers.dev';
const port = parseInt(process.env.SENTINEL_TEST_DENY_PORT || '443', 10);

const sock = net.connect({ host, port }, () => {
  // Connect succeeded — sentinel did NOT block. TEST FAIL.
  console.log('UNEXPECTED-CONNECT-SUCCESS', host, port);
  sock.destroy();
  process.exit(0);
});

sock.on('error', (err) => {
  console.log('CONNECT-FAILED', err.code, err.message);
  // EHOSTUNREACH:  Sentinel libc connect() deny path
  // ENOTFOUND:     Sentinel getaddrinfo deny path OR DNS NXDOMAIN
  //                (sentinel-test.workers.dev is fictional; either is acceptable —
  //                the assertion is "deny path fired", not the specific errno)
  // EAI_FAIL:      Sentinel policy-deny at Resolve gate (daemon rejected before DNS)
  // ECONNREFUSED:  kernel refused — should not happen for a non-loopback host
  if (err.code === 'EHOSTUNREACH' || err.code === 'ENOTFOUND' || err.code === 'EAI_FAIL') {
    process.exit(1);
  }
  process.stderr.write(`unexpected error: ${err.code} ${err.message}\n`);
  process.exit(2);
});

setTimeout(() => {
  console.log('TIMEOUT');
  sock.destroy();
  process.exit(3);
}, 5000);
