# Design

## Key propagation

sshd supports an `AuthorizedKeysCommand` setting in `sshd_config` that runs a
program and uses its stdout as the authorized keys (instead of reading from a
file). We use this as a fallback behind the cached `authorized_keys` file:

1. sshd first reads `AuthorizedKeysFile` (the cache). On cache hit, login
   proceeds immediately.
2. On cache miss, sshd invokes `AuthorizedKeysCommand` (`gitssh-proxy-authkeys`).
3. The helper connects to the server and sends a `getkey` request with the
   hash of the current cache file.
   - If the server returns updated keys: the helper transforms them (rewrites
     `command=`, injects `environment=` vars), writes the cache atomically,
     and outputs the result.
   - If the server returns `notmodified`: the cache is current and the key is
     genuinely not authorized. The helper outputs the existing cache so sshd
     can confirm the miss.
4. On successful login, `gitssh-proxy-client` piggybacks a `getkey` request
   alongside `exec` to opportunistically refresh the cache.

The user's SSH public key is passed to the client via `environment=` options
injected into the transformed `authorized_keys` entries. This requires
`PermitUserEnvironment GITSSH_PROXY_*` in sshd_config.

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

Every request carries `ts`, the client's Unix time in seconds. The server
rejects a request when `|now - ts| > 60`. It also remembers each request's
salt for the length of that window and rejects any salt it has already seen,
so a captured connection cannot be replayed.

After a successful `exec` response, the client sends stdin on channel 0 and
ends it with an EOF frame. The server streams stdout and stderr on channels 1
and 2, sends an EOF frame for each, then sends the `exit` message on channel
15 and closes the connection.

### getkey

Retrieve the server's `authorized_keys`.

**Request**

```json
{"ts": 1760000000, "getkey": {"match": "<sha-256 digest of local cache>"}}
```

- `match` (optional): SHA-256 digest of the local `authorized_keys` cache
  file content. If omitted, the server always returns the full keys.

**Response**

If the cache is stale or no match was provided:

```json
{"getkey": {"keys": "<authorized_keys file content>"}}
```

If the provided hash matches the current file:

```json
{"getkey": {"notmodified": true}}
```

### exec

Run a command on the server with re-authentication.

Re-authentication is necessary because sshd may have authenticated the user
against a stale cache. The server verifies the key against its current
`authorized_keys` before executing.

The server looks up the key by type and data in its own `authorized_keys` to
determine the correct `command=` to execute. The client-supplied `cmd` field
is informational and not used for command execution (prevents injection).

**Request**

```json
{"ts": 1760000000, "exec": {"t": "<key-type>", "k": "<key-data>", "cmd": "<forcecommand>", "origcmd": "<SSH_ORIGINAL_COMMAND>"}}
```

- `t`: SSH key type (e.g., `ssh-rsa`, `ecdsa-sha2-nistp256`, `ssh-ed25519`)
- `k`: SSH public key data (base64)
- `cmd`: The original `command=` value from the server's `authorized_keys`
  (informational; the server uses its own lookup)
- `origcmd`: The value of `$SSH_ORIGINAL_COMMAND` from the SSH session (e.g.,
  `git-upload-pack 'user/repo.git'`)

**Response**

On success (stdio streaming on channels 0–2 begins):

```json
{"exec": {"ok": true}}
```

On failure:

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
{"ts": 1760000000, "exec": {"t": "ssh-rsa", "k": "AAAA...", "cmd": "gogs serv key-1", "origcmd": "git-upload-pack 'user/repo.git'"}, "getkey": {"match": "abcdef..."}}
```

The server processes both and returns a single combined response:

```json
{"exec": {"ok": true}, "getkey": {"notmodified": true}}
```

After this response, stdio streaming begins (if exec succeeded). The client uses the `getkey` result to update its cache
asynchronously.

## authorized_keys transformation

Each entry in the server's `authorized_keys` is transformed for the proxy:

**Original (server)**:
```
command="/opt/gogs/gogs serv key-1 --config='/opt/gogs/custom/conf/app.ini'",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-rsa AAAA... user@host
```

**Transformed (proxy)**:
```
command="gitssh-proxy-client /opt/gogs/gogs serv key-1 --config='/opt/gogs/custom/conf/app.ini'",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,environment="GITSSH_PROXY_KEY_TYPE=ssh-rsa",environment="GITSSH_PROXY_KEY_DATA=AAAA..." ssh-rsa AAAA... user@host
```

Changes:
1. The `command=` value is prefixed with the path to `gitssh-proxy-client`.
2. `environment="GITSSH_PROXY_KEY_TYPE=<type>"` is appended to the options.
3. `environment="GITSSH_PROXY_KEY_DATA=<data>"` is appended to the options.
4. All other options (port forwarding restrictions, etc.) are preserved.

The environment variables allow the client to retrieve the connecting user's
SSH key at runtime for the `exec` re-authentication request.
