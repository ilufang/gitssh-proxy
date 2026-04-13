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

The protocol runs over TCP. The transport layer is a pipeline of stream
transforms applied to the raw socket:

```
Application  <-->  Transport Transform  <-->  TCP Socket
```

Currently the transform is identity (passthrough). When transport security is
needed (e.g., proxy and server on different networks), a PSK-based cipher
transform can be inserted into the pipeline without changes to the application
layer. All application code reads from and writes to the `{reader, writer}`
interface returned by the transport, never the raw socket.

## Application protocol

Newline-delimited JSON (NDJSON) is used for message framing. Each message is
a single JSON object terminated by `\n`. Multiple operations can be bundled as
top-level keys in a single message.

After a successful `exec` response, the TCP stream transitions from NDJSON to
raw binary: the stream becomes the stdio of the spawned process. This means
the JSON message reader must not consume any bytes beyond the terminating
newline.

### getkey

Retrieve the server's `authorized_keys`.

**Request**

```json
{"getkey": {"match": "<sha-256 hex digest of local cache>"}}
```

- `match` (optional): SHA-256 hex digest of the local `authorized_keys` cache
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
{"exec": {"t": "<key-type>", "k": "<key-data>", "cmd": "<forcecommand>", "origcmd": "<SSH_ORIGINAL_COMMAND>"}}
```

- `t`: SSH key type (e.g., `ssh-rsa`, `ecdsa-sha2-nistp256`, `ssh-ed25519`)
- `k`: SSH public key data (base64)
- `cmd`: The original `command=` value from the server's `authorized_keys`
  (informational; the server uses its own lookup)
- `origcmd`: The value of `$SSH_ORIGINAL_COMMAND` from the SSH session (e.g.,
  `git-upload-pack 'user/repo.git'`)

**Response**

On success (stream transitions to raw stdio after this line):

```json
{"exec": {"ok": true}}
```

On failure:

```json
{"exec": {"error": "<reason>"}}
```

### Bundled requests

The client typically sends `exec` and `getkey` together in a single message:

```json
{"exec": {"t": "ssh-rsa", "k": "AAAA...", "cmd": "gogs serv key-1", "origcmd": "git-upload-pack 'user/repo.git'"}, "getkey": {"match": "abcdef..."}}
```

The server processes both and returns a single combined response:

```json
{"exec": {"ok": true}, "getkey": {"notmodified": true}}
```

After this response, the stream transitions to raw binary stdio (if exec
succeeded). The client uses the `getkey` result to update its cache
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
