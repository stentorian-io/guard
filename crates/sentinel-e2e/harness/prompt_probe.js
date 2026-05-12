// E2E harness: trigger getaddrinfo for a non-allowlisted hostname so the
// daemon's prompt-parking logic fires in TTY mode.
//
// dns.lookup() calls getaddrinfo → hook proxies to daemon → daemon parks
// on prompt channel → CLI renders prompt → user responds → daemon unparks.
//
// On Allow: dns.lookup succeeds, then connect is attempted (may fail for
// network reasons but NOT because Sentinel denied it).
// On Deny: dns.lookup fails with ENOTFOUND (from EAI_FAIL).
//
// Exit codes:
//   0 = resolve succeeded (Allow verdict from prompt)
//   1 = resolve failed (Deny verdict, daemon down, or EAI_FAIL)
//   2 = resolve succeeded but connect failed
//   3 = timeout
//
// stdout markers:
//   RESOLVE-OK <ip>       — dns.lookup succeeded (user chose Allow)
//   RESOLVE-FAILED <code> — dns.lookup failed (user chose Deny, or denied)
//   CONNECT-OK            — connect succeeded after Allow
//   CONNECT-FAILED <code> — connect failed after Allow (network error, not Sentinel)

const dns = require('dns');
const net = require('net');

const host = process.env.PROBE_HOST || 'discord.com';
const port = parseInt(process.env.PROBE_PORT || '443', 10);
const connectAfter = process.env.PROBE_CONNECT_AFTER !== '0';

setTimeout(() => { console.log('TIMEOUT'); process.exit(3); }, 45000);

dns.lookup(host, { family: 0 }, (err, address, family) => {
  if (err) {
    console.log('RESOLVE-FAILED', err.code, err.message);
    process.exit(1);
  }
  console.log('RESOLVE-OK', address, 'family=' + family);

  if (!connectAfter) {
    process.exit(0);
  }

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
