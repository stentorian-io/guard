// This script attempts to connect to a host that resolves successfully via
// DNS but is NOT in the curated allowlist. The Stentorian Guard hook must intercept
// (at getaddrinfo or connect) and deny.
//
// We use `discord.com` instead of `evil.example.com` because
// `evil.example.com` is a non-existent subdomain of RFC-2606 reserved
// `example.com` and a real DNS resolver returns NXDOMAIN for it (Node
// surfaces as ENOTFOUND). That made the original assertion indistinguishable
// from "Stentorian Guard didn't fire -- the host just doesn't resolve".
// `discord.com` (a) resolves successfully outside Stentorian Guard, (b) is NOT in
// the curated allowlist, so the only failure path is Stentorian Guard-induced. The
// companion test in deny.rs additionally exercises a loopback (allowlisted)
// host -- the differential proves Stentorian Guard discriminated.
//
// STT_GUARD_TEST_DENY_HOST env var lets the test override the host.
// STT_GUARD_TEST_DENY_PORT env var lets the test override the port.

const net = require('net');

const host = process.env.STT_GUARD_TEST_DENY_HOST || 'discord.com';
const port = parseInt(process.env.STT_GUARD_TEST_DENY_PORT || '443', 10);

const sock = net.connect({ host, port }, () => {
  // We should NEVER reach here under Stentorian Guard. If we do, exit 0 to surface
  // the "Stentorian Guard did not deny" failure clearly.
  console.log('UNEXPECTED-CONNECT-SUCCESS', host, port);
  sock.destroy();
  process.exit(0);
});

sock.on('error', (err) => {
  // Stentorian Guard deny shows up here. Print the error code so deny.rs can
  // discriminate between Stentorian Guard-deny errnos (EHOSTUNREACH, EAI_FAIL) and
  // genuine network errors (ECONNREFUSED -- would indicate Stentorian Guard let the
  // connect through to the network layer where it was refused).
  console.log('CONNECT-FAILED', err.code, err.message);
  process.exit(2);
});

// Safety: if neither connect nor error fires within 8s, exit 3.
setTimeout(() => { console.log('TIMEOUT'); process.exit(3); }, 8000);
