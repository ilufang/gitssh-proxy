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
- `lib/transport.js` — AES-128-GCM encrypted frame codec (PSK, per-direction salt)
- `lib/mux.js` — channel numbers + `pipeChannel` (data frames, then EOF)
- `lib/protocol.js` — JSON control messages on channel 15 (sendMessage/recvMessage)
- `lib/authkeys.js` — authorized_keys parsing, proxy entry building, cache
  writing, `from=`/`expiry-time=` checks
- `lib/command.js` — server exec policy: command tokenizer/allowlist,
  `origcmd` validation, child environment
- `lib/connection.js` — TCP connect + transport wrapping

## Key conventions

- Zero external dependencies. Only Node.js builtins.
- All logging goes to stderr, never stdout (stdout is the data channel).
- Transport abstraction: all I/O goes through `{reader, writer}` from
  `wrapTransport(socket, psk)`, never the raw socket. `writer.send(channel,
  buf)` / `writer.sendEof(channel)` write frames; `reader` is an object-mode
  stream of `{channel, payload}` (`payload === null` means EOF).
- The server writes nothing until the first request authenticates and passes
  the `ts`/salt replay check.
- Config via JSON files (`/etc/gitssh-proxy/server.json` / `client.json`,
  override `-C`). `psk` is required.
- Tests use Node.js built-in `node:test` and `node:assert`.

## Protocol reference

See DESIGN.md. Key points:
- Encrypted frames over TCP; header is u32 LE `(channel << 28) | length`.
  Channels: 0 stdin, 1 stdout, 2 stderr, 15 control (one JSON object/frame).
- Requests carry `ts`. After `exec` succeeds, stdio flows on channels 0–2,
  then the server sends `{"exit": {"code": n}}`.
- Only public keys cross the wire: `getkey` returns `{keys: [{t, k}], etag}`;
  the client builds its own restricted `authorized_keys`. `exec` sends
  `{t, k, addr, origcmd}`; the server looks up and runs its own `command=`.
- Each side owns its own security: the client never runs server-provided
  text; the server decides what to execute from its local file and config.
- Multiple operations can be bundled in a single message.
