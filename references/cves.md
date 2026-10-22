# Node.js 2026-10-21 security release: CVEs and mitigations

Patched: 22.23.4, 24.22.1, 26.12.1. Mitigations below are defense in depth; upgrading is the fix.

| CVE | Severity | Lines | Issue |
|---|---|---|---|
| CVE-2026-111497 | high | 26, 24, 22 | Brotli decoder out-of-bounds write permits remote code execution |
| CVE-2026-105482 | high | 26, 24, 22 | `dns.resolve` truncates names containing a NUL char |
| CVE-2026-105483 | high | 26, 24 | TLS hostname check bypass when IP written in fullwidth digits |
| CVE-2026-106069 | high | 26, 24, 22 | TLS hostname check bypass when host loosely resolves to an IP |
| CVE-2026-105481 | medium | 26, 24, 22 | Keep-alive socket processes a response written before the request was sent |
| CVE-2026-106072 | medium | 26, 24, 22 | DNS SAN can authenticate IP endpoints for non-canonical IPv4 hostnames |
| CVE-2026-106074 | medium | 26, 24, 22 | `crypto.randomUUID()` / `randomInt()` entropy cache saved into snapshots and SEAs, so processes repeat values |
| CVE-2026-106070 | low | 26 | ZipFile returns attacker-controlled prefix bytes after failed header validation |
| CVE-2026-106071 | low | 26 | Permission Model filesystem over-grant via wildcard radix lookup |
| CVE-2026-106073 | low | 26, 24, 22 | Permission Model bypass with `fs.realpathSync` |

Dependency updates in the same release: c-ares, OpenSSL (24, 22), SQLite (22), Undici,
and removal of the compromised eMudhra intermediate CA from the bundled certificate store.

## Code patterns the scanner flags and what to do

**Brotli (`brotliDecompress`, `createBrotliDecompress`, `zlib.brotli*`, `Accept-Encoding: br` handling)**
Highest priority. If input is untrusted (uploads, proxied responses, user-supplied archives), upgrade Node first.
Interim mitigation: cap input size, and disable `br` in `Accept-Encoding` for outbound fetches to untrusted hosts.

**`dns.resolve*` / `dns.promises.resolve*` / `dns.lookup` with variable input**
Reject hostnames containing `\0` before resolving:
```js
if (typeof host !== 'string' || host.includes('\0')) throw new Error('invalid hostname');
```

**TLS connections to hostnames/IPs from user input (`tls.connect`, `https.request`, `checkServerIdentity`)**
Allow only canonical hostnames or canonical IPs. Reject anything where `net.isIP(host) === 0` but the string
looks numeric, contains non-ASCII digits, or uses non-canonical IPv4 forms (`0x7f.1`, `127.1`, decimal-integer hosts):
```js
import net from 'node:net';
function safeHost(h) {
  if (!/^[\x21-\x7e]+$/.test(h)) throw new Error('non-ASCII host'); // blocks fullwidth digits
  // dotted decimal/hex forms only (127.1, 0x7f.1, 2130706433); a real hostname never matches
  if (/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$/i.test(h) && !net.isIPv4(h)) throw new Error('non-canonical IP');
  return h;
}
```
Never disable certificate verification (`rejectUnauthorized: false`) to work around this.

**`crypto.randomUUID` / `randomInt` in code run from `--build-snapshot` or Single Executable Applications (SEA)**
Do not call them at snapshot build time. Generate IDs only at runtime after startup. Upgrade Node.

**Permission Model (`--permission`, `--allow-fs-read`, `--allow-fs-write`)**
Avoid wildcard grants; grant exact directories. Do not rely on `fs.realpathSync` as a containment check.

**Keep-alive agents (`http.Agent({ keepAlive: true })`, `https.globalAgent`)**
No safe code-level workaround; upgrade Node. Interim: disable keep-alive for requests to untrusted servers.
