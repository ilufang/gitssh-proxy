# gitssh-proxy

SSH reverse proxy for git servers behind HTTP reverse proxies.

For git services inside a container or VM exposed to the public through a
reverse HTTP proxy, git+ssh becomes a problem since there is no equivalent
"vhost" in SSH. This project solves it by manipulating the `authorized_keys`
of the git user on the proxy host to transparently relay SSH connections to
the actual git server over a lightweight TCP protocol.

## How it works

Most git servers (Gogs, Gitea, GitLab, etc.) don't manually handle SSH.
They write users' public keys into the git user's `authorized_keys` with a
`command=` forced command that invokes the git server. For example:

```
command="/opt/gogs/gogs serv key-1 --config='...'",no-port-forwarding,... ssh-rsa AAAA... user@host
```

See [sample_remote_authorized_keys.txt](sample_remote_authorized_keys.txt)
for a real-world example from a Gogs instance.

gitssh-proxy works by mirroring these entries on the proxy host, but replacing
the forced command with `gitssh-proxy-client`, which connects to
`gitssh-proxy-server` on the git machine and relays the operation:

```
command="gitssh-proxy-client /opt/gogs/gogs serv key-1 --config='...'",... ssh-rsa AAAA...
```

## Components

### gitssh-proxy-server

Runs on (or near) the git machine. Listens on TCP and handles two operations:

- **getkey**: Serves the git server's `authorized_keys` content to the proxy,
  with SHA-256 based caching to avoid redundant transfers.
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
server, transforms them for the proxy (rewriting `command=` and injecting
environment variables), and writes the updated cache.

## Key propagation flow

1. User connects to the proxy host via SSH.
2. sshd checks the cached `authorized_keys` file (via `AuthorizedKeysFile`).
3. If key found (cache hit): sshd authenticates, runs `gitssh-proxy-client`.
4. If key not found (cache miss): sshd runs `gitssh-proxy-authkeys` (via
   `AuthorizedKeysCommand`).
   - The helper fetches keys from the server (passing the cache hash to avoid
     unnecessary re-transfers).
   - If the server returns updated keys: transform and update cache.
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
  "authkeysFile": "/home/git/.ssh/authorized_keys"
}
```

**`/etc/gitssh-proxy/client.json`** (used by `gitssh-proxy-client` and `gitssh-proxy-authkeys`):

```json
{
  "serverHost": "127.0.0.1",
  "serverPort": 9422,
  "cacheFile": "/home/git/.ssh/authorized_keys",
  "clientPath": "gitssh-proxy-client"
}
```

### Server options

- **listen**: Bind address (default `0.0.0.0`)
- **port**: Bind port (default `9422`)
- **authkeysFile**: Path to the real `authorized_keys` file on the git server

### Client options

- **serverHost**: Address of `gitssh-proxy-server` (default `127.0.0.1`)
- **serverPort**: Port of `gitssh-proxy-server` (default `9422`)
- **cacheFile**: Path to the cached `authorized_keys` on the proxy host

### Authkeys options

- **serverHost**, **serverPort**: Same as client
- **cacheFile**: Same as client
- **clientPath**: Path to `gitssh-proxy-client` binary, used when rewriting
  the `command=` option (default `gitssh-proxy-client`)

## Proxy host sshd setup

The proxy host's `/etc/ssh/sshd_config` needs the following for the git user:

```
Match User git
    AuthorizedKeysFile /home/git/.ssh/authorized_keys
    AuthorizedKeysCommand /usr/local/bin/gitssh-proxy-authkeys
    AuthorizedKeysCommandUser git
    PermitUserEnvironment GITSSH_PROXY_*
```

`PermitUserEnvironment` is required because the transformed `authorized_keys`
entries inject `GITSSH_PROXY_KEY_TYPE` and `GITSSH_PROXY_KEY_DATA` as
environment variables (via `environment=` options in `authorized_keys`). The
pattern restriction `GITSSH_PROXY_*` limits which variables can be set.

## Server host setup

Run `gitssh-proxy-server` as a service (e.g., via systemd). It needs read
access to the git server's `authorized_keys` file and the ability to execute
git server commands (e.g., `gogs serv`).

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
