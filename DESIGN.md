# Design

## Key propagation

sshd supports an `AuthorizedKeysCommand` setting in `sshd_config` that runs a
program and uses its stdout as the authorized keys (instead of reading from a
file). We use this as a fallback behind the cached `authorized_keys` file:

1. sshd first reads `AuthorizedKeysFile` (the cache). On cache hit, login
   proceeds immediately.
2. On cache miss, sshd invokes `AuthorizedKeysCommand` (`gitssh-proxy-authkeys`).
3. The helper connects to the server and sends a `getkey` request with the
   etag stored in `<cacheFile>.etag`.
   - If the server returns updated keys: the helper builds its own
     `authorized_keys` from them (see below), writes the cache and etag
     atomically, and outputs the result.
   - If the server returns `notmodified`: the cache is current and the key is
     genuinely not authorized. The helper outputs the existing cache so sshd
     can confirm the miss.
4. On successful login, `gitssh-proxy-client` piggybacks a `getkey` request
   alongside `exec` to opportunistically refresh the cache.

The user's SSH public key is passed to the client via `environment=` options
in the proxy's `authorized_keys` entries. This requires
`PermitUserEnvironment GITSSH_PROXY_*` in sshd_config.

## Responsibilities

Only public keys cross the wire between client and server. Each side is
responsible for its own security and treats the other's data as untrusted:

- **Client (proxy host).** Builds its `authorized_keys` from scratch with
  fixed, restrictive options; the server cannot influence what runs on the
  proxy. Whatever passes pubkey auth is forwarded to the server as-is.
- **Server (git host).** Decides from its own `authorized_keys` and config
  whether anything runs and what. The key named in a request is just a lookup
  key; the server never relies on the proxy for its own security.

Residual risk, inherent to a proxy that terminates SSH:

- A compromised proxy (or leaked `psk`) can present any servable key, with
  any `addr` and any acceptable `origcmd`, since public keys are not secret.
  It can act as any git user, but only through the git server's own command.
  `from=` holds only as long as the proxy reports `addr` honestly.
- A compromised server decides which keys may log in to the proxy and what
  bytes are relayed to them. Those users can still only run
  `gitssh-proxy-client`.

## Transport layer

The protocol runs over TCP. Every byte in both directions is carried in
encrypted, authenticated frames using AES-128-GCM, keyed from a preshared
secret (`psk` in both config files). The two directions are independent
streams, each with its own salt, key and nonce counter.

```
stream: [salt 16B] [frame] [frame] ...

frame:  seal(header) seal(payload)    length > 0
        seal(header)                  length = 0 (EOF)

header  = u32 little-endian: (channel << 28) | length
seal(m) = AES-128-GCM ciphertext of m (same length as m) || 16-byte tag
```

**Key derivation.** The sender picks a random 16-byte salt and sends it
in clear as the first bytes of its stream. Both sides then derive the
direction's key:

```
key = HKDF-SHA256(ikm = UTF-8 bytes of psk, salt = salt, info = "gitssh-proxy-subkey", length = 16)
```

**Nonces.** Each direction keeps a 12-byte nonce. It starts at all zeros
and is incremented as a little-endian integer after every `seal` (sender)
or `open` (receiver). The header and the payload are separate `seal`
operations, so a data frame uses two nonces and an EOF frame uses one. No
additional authenticated data is used.

**Receiving.** The receiver reads the 16-byte salt, then loops:

1. Read 4 + 16 bytes and open the header. Channel = `header >>> 28`,
   length = `header & 0x0FFFFFFF`.
2. If length is 0, it is an EOF for that channel. Go to 1.
3. Otherwise read length + 16 bytes, open the payload, and deliver it.

Notes:

- The header is authenticated before the payload is read, so the length field
  can be trusted before buffering. The maximum payload is `0x0FFFFFFF` bytes.
  Every message fits in a single frame, so frames are never reassembled.
- The header is authenticated before the payload is read, so the length field
  can be trusted before buffering. The maximum payload is `0x0FFFFFFF` bytes.
  Every message fits in a single frame, so frames are never reassembled.
- A frame with length 0 is an authenticated EOF for its channel. No payload
  chunk follows it, and the TCP connection stays open.
- Any authentication failure closes the connection.
- The server sends nothing, not even its salt, until the client's first frame
  has authenticated and passed the replay check (see below). An
  unauthenticated peer gets a silent close.

### Channels

| Channel | Direction       | Content                          |
|---------|-----------------|----------------------------------|
| 0       | client → server | stdin of the spawned command     |
| 1       | server → client | stdout of the spawned command    |
| 2       | server → client | stderr of the spawned command    |
| 15      | both            | control messages (one JSON object per frame) |

## Application protocol

Control messages are JSON objects, each sent as one frame on channel 15.
Multiple operations can be bundled as top-level keys in a single message.

Every request carries `ts`, the client's Unix time in milliseconds. The
server rejects a request when `|now - ts| > 30000` (30 seconds). It also
remembers each accepted request's salt until any request with that `ts`
would be stale (twice the window) and rejects any salt it has already seen,
so a captured connection cannot be replayed.

After a successful `exec` response, the client sends stdin on channel 0 and
ends it with an EOF frame. The server streams stdout and stderr on channels 1
and 2, sends an EOF frame for each, then sends the `exit` message on channel
15 and closes the connection.

### getkey

Retrieve the list of public keys the server will serve.

**Request**

```json
{"ts": 1760000000000, "getkey": {"match": "<etag>"}}
```

- `match` (optional): the `etag` from the last full response, as stored in
  `<cacheFile>.etag`. If omitted, the server always returns the full list.

**Response**

If the etag is stale or no match was provided:

```json
{"getkey": {"keys": [{"t": "ssh-ed25519", "k": "AAAA..."}], "etag": "<opaque>"}}
```

- `keys`: servable keys only (see *Server execution policy*), deduplicated.
  No options, commands or comments.
- `etag`: opaque to the client. The server uses the SHA-256 base64 digest of
  the JSON-encoded `keys`.

If `match` equals the current etag:

```json
{"getkey": {"notmodified": true}}
```

### exec

Run a command on the server with re-authentication.

Re-authentication is necessary because sshd may have authenticated the user
against a stale cache. The server looks the key up in its own current
`authorized_keys` and runs that entry's `command=`; the client never names a
command.

**Request**

```json
{"ts": 1760000000000, "exec": {"t": "<key-type>", "k": "<key-data>", "addr": "<client IP>", "origcmd": "<SSH_ORIGINAL_COMMAND>"}}
```

- `t`: SSH key type (e.g., `ssh-rsa`, `ecdsa-sha2-nistp256`, `ssh-ed25519`)
- `k`: SSH public key data (base64)
- `addr`: the SSH client's address (first field of `$SSH_CONNECTION`), used
  for `from=`
- `origcmd`: The value of `$SSH_ORIGINAL_COMMAND` from the SSH session (e.g.,
  `git-upload-pack 'user/repo.git'`)

**Response**

On success (stdio streaming on channels 0–2 begins):

```json
{"exec": {"ok": true}}
```

On failure (`Key not authorized` or `Command not allowed`):

```json
{"exec": {"error": "<reason>"}}
```

When the command finishes, after the EOF frames for stdout and stderr:

```json
{"exit": {"code": 0}}
```

The client exits with this code.

### Bundled requests

The client typically sends `exec` and `getkey` together in a single message:

```json
{"ts": 1760000000000, "exec": {"t": "ssh-rsa", "k": "AAAA...", "addr": "203.0.113.5", "origcmd": "git-upload-pack 'user/repo.git'"}, "getkey": {"match": "abcdef..."}}
```

The server processes both and returns a single combined response:

```json
{"exec": {"ok": true}, "getkey": {"notmodified": true}}
```

After this response, stdio streaming begins (if exec succeeded). The client uses
the `getkey` result to update its cache.

## Proxy authorized_keys

The client writes one line per key from a fixed template:

```
restrict,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="<clientPath>",environment="GITSSH_PROXY_KEY_TYPE=<t>",environment="GITSSH_PROXY_KEY_DATA=<k>" <t> <k>
```

- A key is kept only if `t` is a known key type (`ssh-ed25519`, `ssh-rsa`,
  `ecdsa-sha2-nistp{256,384,521}`, `sk-ssh-ed25519@openssh.com`,
  `sk-ecdsa-sha2-nistp256@openssh.com`) and `k` is strict base64. Anything
  else from the server is dropped.
- `clientPath` is restricted to `[A-Za-z0-9._/-]` at config load. No
  interpolated value can contain `"`, `\`, `,` or whitespace, so no escaping
  is ever needed.
- `restrict` (OpenSSH ≥ 7.2) disables forwarding, pty and `~/.ssh/rc`; the
  explicit `no-*` options are redundant with it.
- The environment variables let the client send the authenticated key in the
  `exec` request. This requires `PermitUserEnvironment GITSSH_PROXY_*`.

## Server execution policy

The server mirrors what sshd would allow for the same `authorized_keys`, and
blocks more only where the operator opts in.

**Servable entries.** On each reload, entries are classified; unservable ones
are logged and neither advertised by `getkey` nor matched by `exec`:

- no `command=` (over SSH this would be a shell), or more than one;
- `cert-authority` or `principals=` (a CA key, not a user key);
- with `allowedCommands` set: a `command=` that does not tokenize, or whose
  executable is not listed.

`authorized_keys` is not loaded if it is group/world-writable or owned by
anyone but the server's user or root. The server refuses to run as root.

**Key options.** Checked at `exec` time; as in sshd, the first entry for the
key whose options allow it is used:

- `expiry-time="YYYYMMDD[HHMM[SS]][Z]"`: denied once past (local time unless
  `Z`).
- `from="pattern-list"`: matched against `addr` as sshd does with
  `UseDNS no`: addresses and CIDR ranges, `*`/`?` globs, and `!` negation
  (any negated match denies). A missing or invalid `addr` denies.
- Other options (`no-*`, `restrict`, `environment=`, …) govern the SSH session,
  which belongs to the proxy, and are ignored.

**Command.** Without `allowedCommands`, `command=` runs through
`/bin/sh -c`, as sshd would. With it, `command=` is split by a strict
tokenizer (bare words of `[A-Za-z0-9_@%+=:,./-]`, `'single-quoted'` runs, and
their concatenation) and run without a shell.

**origcmd.** Must be empty or a single line whose first word matches
`git-[a-z0-9-]+`; otherwise `exec` fails with `Command not allowed`.

**Environment.** The child gets only `PATH`, `HOME`, `USER`, `LOGNAME`,
`LANG`, `TZ` from the server's environment, plus `SSH_ORIGINAL_COMMAND`.
