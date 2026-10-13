# gitssh-proxy

SSH reverse proxy for git servers behind HTTP reverse proxies.

For git services inside a container or VM exposed to the public through a
reverse HTTP proxy, git+ssh becomes a problem since there is no equivalent
"vhost" in SSH. This project solves it by manipulating the `authorized_keys`
of the git user on the proxy host to transparently relay SSH connections to
the actual git server over a lightweight encrypted TCP protocol.

## How it works

Most git servers (Gogs, Gitea, GitLab, etc.) don't manually handle SSH.
They write users' public keys into the git user's `authorized_keys` with a
`command=` forced command that invokes the git server. For example:

```
command="/opt/gogs/gogs serv key-1 --config='...'",no-port-forwarding,... ssh-rsa AAAA... user@host
```

See [sample_remote_authorized_keys.txt](sample_remote_authorized_keys.txt)
for a real-world example from a Gogs instance.

gitssh-proxy works by mirroring the *public keys* of these entries on the proxy
host, each with the fixed forced command `gitssh-proxy-client`, which connects
to `gitssh-proxy-server` on the git machine and relays the operation:

```
restrict,...,command="/usr/local/bin/gitssh-proxy-client",environment="GITSSH_PROXY_KEY_TYPE=ssh-rsa",... ssh-rsa AAAA...
```

Only public keys are sent to the proxy. The server looks up and runs its own
`command=` for the key at connection time, so neither side can make the other
execute anything it would not otherwise run.

## Components

### gitssh-proxy-server

Runs on (or near) the git machine. Listens on TCP and handles two operations:

- **getkey**: Serves the public keys from the git server's `authorized_keys`
  to the proxy, with etag-based caching to avoid redundant transfers.
- **exec**: Verifies an SSH key is still authorized, then spawns the git
  command and pipes its stdio through the TCP connection.

### gitssh-proxy-client

Runs on the proxy host. Invoked by sshd as the forced command when a user
connects via SSH. Connects to the server, sends the user's key for
re-authentication and the git command for execution, then pipes stdio between
the SSH session and the TCP connection.

Also piggybacks a `getkey` request to opportunistically refresh the local
authorized_keys cache.

### gitssh-proxy-authkeys

Runs on the proxy host. Called by sshd's `AuthorizedKeysCommand` when a key
is not found in the cached `authorized_keys` file. Fetches keys from the
server, builds restricted proxy entries for them, and writes the updated cache.

## Key propagation flow

1. User connects to the proxy host via SSH.
2. sshd checks the cached `authorized_keys` file (via `AuthorizedKeysFile`).
3. If key found (cache hit): sshd authenticates, runs `gitssh-proxy-client`.
4. If key not found (cache miss): sshd runs `gitssh-proxy-authkeys` (via
   `AuthorizedKeysCommand`).
   - The helper fetches keys from the server (passing the cache etag to avoid
     unnecessary re-transfers).
   - If the server returns updated keys: build proxy entries and update cache.
   - If the server says `notmodified`: the key is genuinely not authorized.
   - Output the (possibly updated) keys to stdout for sshd to match against.
5. On successful login, `gitssh-proxy-client` runs:
   - Sends `exec` request with the user's key for re-authentication (handles
     the case where a key was revoked on the server but still cached locally).
   - Bundles a `getkey` request to refresh the cache asynchronously.
   - On success, pipes stdio between the SSH session and the remote git process.

## Configuration

The server and client/authkeys binaries use separate config files. Override
the default path with `-C /path/to/config.json`.

**`/etc/gitssh-proxy/server.json`** (used by `gitssh-proxy-server`):

```json
{
  "listen": "0.0.0.0",
  "port": 9422,
  "authkeysFile": "/home/git/.ssh/authorized_keys",
  "allowedCommands": ["/opt/gogs/gogs"],
  "psk": "<shared secret>"
}
```

**`/etc/gitssh-proxy/client.json`** (used by `gitssh-proxy-client` and `gitssh-proxy-authkeys`):

```json
{
  "serverHost": "127.0.0.1",
  "serverPort": 9422,
  "cacheFile": "/home/git/.ssh/authorized_keys",
  "clientPath": "/usr/local/bin/gitssh-proxy-client",
  "psk": "<shared secret>"
}
```

### Server options

- **listen**: Bind address (default `0.0.0.0`)
- **port**: Bind port (default `9422`)
- **authkeysFile**: Path to the real `authorized_keys` file on the git server.
  Not loaded if group/world-writable or owned by another user (other than root).
- **allowedCommands** (optional): Absolute paths of executables that
  `command=` entries may run. When set, `command=` must be a plain argument
  list (words and `'single-quoted'` strings) and runs without a shell; other
  entries are not served. When unset or empty, `command=` runs through
  `/bin/sh -c`, as sshd would.
- **psk**: Preshared secret (required). Must match the client's `psk`.

### Client options

- **serverHost**: Address of `gitssh-proxy-server` (default `127.0.0.1`)
- **serverPort**: Port of `gitssh-proxy-server` (default `9422`)
- **cacheFile**: Path to the cached `authorized_keys` on the proxy host
- **psk**: Preshared secret (required). Must match the server's `psk`.

### Authkeys options

- **serverHost**, **serverPort**, **psk**: Same as client
- **cacheFile**: Same as client
- **clientPath**: Path to `gitssh-proxy-client` binary, used as the `command=`
  option (default `gitssh-proxy-client`; an absolute path is recommended).
  Only `[A-Za-z0-9._/-]` is allowed.

## Proxy host sshd setup

The proxy host's `/etc/ssh/sshd_config` needs the following for the git user:

```
PermitUserEnvironment GITSSH_PROXY_*
Match User git
    AuthorizedKeysFile /home/git/.ssh/authorized_keys
    AuthorizedKeysCommand /usr/local/bin/gitssh-proxy-authkeys
    AuthorizedKeysCommandUser git
    ForceCommand /usr/local/bin/gitssh-proxy-client
    AuthenticationMethods publickey
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no
```

The `ForceCommand` and the lines after it are defence in depth: the cached
`authorized_keys` entries already carry `restrict` and a fixed `command=`, and
`ForceCommand` ensures nothing else runs even if that file is tampered with.

`PermitUserEnvironment` is required because the transformed `authorized_keys`
entries inject `GITSSH_PROXY_KEY_TYPE` and `GITSSH_PROXY_KEY_DATA` as
environment variables (via `environment=` options in `authorized_keys`). The
pattern restriction `GITSSH_PROXY_*` limits which variables can be set.

## Server host setup

Run `gitssh-proxy-server` as a service (e.g., via systemd) as the git user,
the same user sshd would run the git server's commands as. It refuses to run
as root. It needs read access to the git server's `authorized_keys` file and
the ability to execute git server commands (e.g., `gogs serv`).

Commands receive a minimal environment (`PATH`, `HOME`, `USER`, `LOGNAME`,
`LANG`, `TZ`, `SSH_ORIGINAL_COMMAND`), and only `git-*` commands (or none) are
accepted as `SSH_ORIGINAL_COMMAND`. Entries with `from=` and `expiry-time=` are
enforced; `from=` is checked against the SSH client's address reported by the
proxy.

## Protocol

See [DESIGN.md](DESIGN.md) for the wire protocol specification.

## Installation

Clone the repository and link:

```sh
git clone <repo-url>
cd gitssh-proxy
npm link
```

This installs three binaries: `gitssh-proxy-server`, `gitssh-proxy-client`,
and `gitssh-proxy-authkeys`.
