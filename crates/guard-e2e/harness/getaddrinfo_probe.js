// E2E harness: exercise the getaddrinfo → daemon Resolve → connect flow.
//
// Performs a DNS-level lookup via Node's dns module (which calls getaddrinfo),
// then optionally attempts a connect to the resolved address.
//
// Modes (set via PROBE_MODE env var):
//   "resolve_only"  — call dns.lookup, report success/failure, exit
//   "resolve_connect" (default) — dns.lookup, then net.connect to resolved IP
//
// Environment:
//   PROBE_HOST  — hostname to resolve (required)
//   PROBE_PORT  — port for connect (default: 443)
//   PROBE_MODE  — "resolve_only" or "resolve_connect"
//
// Exit codes:
//   0 = resolve (and optional connect) succeeded
//   1 = resolve failed (getaddrinfo denied or DNS error)
//   2 = resolve succeeded but connect failed
//   3 = timeout
//
// stdout protocol (one marker per line):
//   RESOLVE-OK <ip>         — dns.lookup succeeded
//   RESOLVE-FAILED <code>   — dns.lookup failed
//   CONNECT-OK              — net.connect succeeded
//   CONNECT-FAILED <code>   — net.connect failed

const dns = require('dns');
const net = require('net');

const host = process.env.PROBE_HOST;
const port = parseInt(process.env.PROBE_PORT || '443', 10);
const mode = process.env.PROBE_MODE || 'resolve_connect';

if (!host) {
  console.error('PROBE_HOST is required');
  process.exit(255);
}

// Safety timeout.
setTimeout(() => { console.log('TIMEOUT'); process.exit(3); }, 8000);

dns.lookup(host, { family: 0 }, (err, address, family) => {
  if (err) {
    console.log('RESOLVE-FAILED', err.code, err.message);
    process.exit(1);
  }
  console.log('RESOLVE-OK', address, 'family=' + family);

  if (mode === 'resolve_only') {
    process.exit(0);
  }

  // Connect to the resolved address.
  const sock = net.connect({ host: address, port }, () => {
    console.log('CONNECT-OK');
    sock.destroy();
    process.exit(0);
  });
  sock.on('error', (e) => {
    console.log('CONNECT-FAILED', e.code, e.message);
    process.exit(2);
  });
});
