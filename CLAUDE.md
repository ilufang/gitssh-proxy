# CLAUDE.md

## Project overview

gitssh-proxy is an SSH reverse proxy for git servers. It relays git SSH
connections from a proxy host to a backend git server (Gogs, Gitea, etc.)
over a lightweight TCP protocol. Node.js, zero external dependencies.

## Build and test

```sh
npm test          # runs node --test test/
npm link          # installs the three binaries globally
```

## Architecture

Three separate binaries, shared libraries in `lib/`:

- `bin/gitssh-proxy-server.js` — TCP listener on the git machine
- `bin/gitssh-proxy-client.js` — invoked by sshd on proxy, pipes stdio
- `bin/gitssh-proxy-authkeys.js` — sshd's AuthorizedKeysCommand helper

Shared modules:
- `lib/config.js` — JSON config file loading (`-C` flag)
- `lib/log.js` — stderr-only logger
- `lib/transport.js` — transport pipeline (identity passthrough, PSK-ready)
- `lib/protocol.js` — NDJSON framing (sendMessage/recvMessage)
- `lib/authkeys.js` — authorized_keys parsing, serialization, transformation
- `lib/connection.js` — TCP connect + transport wrapping

## Key conventions

- Zero external dependencies. Only Node.js builtins.
- All logging goes to stderr, never stdout (stdout is the data channel).
- Transport abstraction: all protocol code uses `{reader, writer}` from
  `wrapTransport()`, never the raw socket for data I/O.
- `recvMessage()` uses a manual line reader (not `readline`) to avoid
  consuming bytes beyond the `\n` delimiter — critical for the raw stdio
  transition after `exec`.
- Config via JSON file at `/etc/gitssh-proxy/config.json` (override `-C`).
- Tests use Node.js built-in `node:test` and `node:assert`.

## Protocol reference

See DESIGN.md. Key points:
- NDJSON over TCP. One JSON line per message.
- After successful `exec` response, stream becomes raw binary stdio.
- `getkey` uses SHA-256 caching. `exec` re-authenticates the SSH key.
- Multiple operations can be bundled in a single message.
