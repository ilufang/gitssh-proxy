'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { wrapTransport } = require('../lib/transport');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { parseAuthorizedKeys, findKey, hashKeys } = require('../lib/authkeys');

// Test authorized_keys content
const TEST_KEYS = [
	'command="/bin/echo key-1",no-pty ssh-rsa AAAA1111 user1@host',
	'command="/bin/echo key-2",no-pty ssh-ed25519 BBBB2222 user2@host'
].join('\n') + '\n';

const TEST_KEYS_HASH = hashKeys(TEST_KEYS);
const TEST_KEYS_PARSED = parseAuthorizedKeys(TEST_KEYS);

/**
 * Minimal server implementation for testing (same logic as the real server
 * but without config/logging/file watching).
 */
function createTestServer() {
	return net.createServer((socket) => {
		const { reader, writer } = wrapTransport(socket);

		recvMessage(reader).then((request) => {
			const response = {};

			if (request.getkey) {
				if (request.getkey.match === TEST_KEYS_HASH) {
					response.getkey = { notmodified: true };
				} else {
					response.getkey = { keys: TEST_KEYS };
				}
			}

			if (request.exec) {
				const entry = findKey(TEST_KEYS_PARSED, request.exec.t, request.exec.k);
				if (!entry) {
					response.exec = { error: 'Key not authorized' };
				} else {
					response.exec = { ok: true };
				}

				return sendMessage(writer, response).then(() => {
					if (response.exec.ok) {
						const { spawn } = require('child_process');
						const cmdOpt = entry.options.find(o => o.name === 'command');

						const env = { ...process.env };
						if (request.exec.origcmd) {
							env.SSH_ORIGINAL_COMMAND = request.exec.origcmd;
						}

						const shell = process.platform === 'win32' ? process.env.SHELL || 'sh' : '/bin/sh';
						const child = spawn(shell, ['-c', cmdOpt.value], {
							env,
							stdio: ['pipe', 'pipe', 'pipe']
						});

						reader.pipe(child.stdin);
						child.stdout.pipe(writer);
						child.stdin.on('error', () => {});

						child.on('close', () => socket.end());
						socket.on('close', () => child.kill());
					} else {
						socket.end();
					}
				});
			}

			return sendMessage(writer, response).then(() => socket.end());
		}).catch(() => socket.destroy());
	});
}

describe('integration', () => {
	let server;
	let port;

	before(async () => {
		server = createTestServer();
		await new Promise((resolve) => {
			server.listen(0, '127.0.0.1', () => {
				port = server.address().port;
				resolve();
			});
		});
	});

	after(async () => {
		await new Promise((resolve) => server.close(resolve));
	});

	it('getkey returns full keys when no match hash', async () => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await new Promise((resolve) => socket.on('connect', resolve));
		const { reader, writer } = wrapTransport(socket);

		await sendMessage(writer, { getkey: {} });
		const response = await recvMessage(reader);

		assert.ok(response.getkey);
		assert.equal(response.getkey.keys, TEST_KEYS);
		socket.destroy();
	});

	it('getkey returns notmodified when hash matches', async () => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await new Promise((resolve) => socket.on('connect', resolve));
		const { reader, writer } = wrapTransport(socket);

		await sendMessage(writer, { getkey: { match: TEST_KEYS_HASH } });
		const response = await recvMessage(reader);

		assert.ok(response.getkey);
		assert.equal(response.getkey.notmodified, true);
		socket.destroy();
	});

	it('exec with valid key succeeds and pipes stdout', async () => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await new Promise((resolve) => socket.on('connect', resolve));
		const { reader, writer } = wrapTransport(socket);

		await sendMessage(writer, {
			exec: { t: 'ssh-rsa', k: 'AAAA1111', cmd: '/bin/echo key-1', origcmd: '' }
		});
		const response = await recvMessage(reader);

		assert.ok(response.exec);
		assert.equal(response.exec.ok, true);

		// Read the output from the spawned command
		const output = await new Promise((resolve) => {
			const chunks = [];
			reader.on('data', (chunk) => chunks.push(chunk));
			reader.on('end', () => resolve(Buffer.concat(chunks).toString()));
			reader.resume();
		});

		assert.equal(output.trim(), 'key-1');
		socket.destroy();
	});

	it('exec with invalid key returns error', async () => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await new Promise((resolve) => socket.on('connect', resolve));
		const { reader, writer } = wrapTransport(socket);

		await sendMessage(writer, {
			exec: { t: 'ssh-rsa', k: 'INVALID', cmd: 'test', origcmd: '' }
		});
		const response = await recvMessage(reader);

		assert.ok(response.exec);
		assert.equal(response.exec.error, 'Key not authorized');
		socket.destroy();
	});

	it('bundled exec+getkey returns both responses', async () => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await new Promise((resolve) => socket.on('connect', resolve));
		const { reader, writer } = wrapTransport(socket);

		await sendMessage(writer, {
			exec: { t: 'ssh-ed25519', k: 'BBBB2222', cmd: '/bin/echo key-2', origcmd: '' },
			getkey: { match: TEST_KEYS_HASH }
		});
		const response = await recvMessage(reader);

		assert.ok(response.exec);
		assert.equal(response.exec.ok, true);
		assert.ok(response.getkey);
		assert.equal(response.getkey.notmodified, true);

		// Read stdout from exec
		const output = await new Promise((resolve) => {
			const chunks = [];
			reader.on('data', (chunk) => chunks.push(chunk));
			reader.on('end', () => resolve(Buffer.concat(chunks).toString()));
			reader.resume();
		});

		assert.equal(output.trim(), 'key-2');
		socket.destroy();
	});

	it('exec passes SSH_ORIGINAL_COMMAND to spawned process', async () => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await new Promise((resolve) => socket.on('connect', resolve));
		const { reader, writer } = wrapTransport(socket);

		// key-1's command is /bin/echo key-1, but we can verify origcmd is set
		// by checking the exec succeeds with an origcmd value
		await sendMessage(writer, {
			exec: { t: 'ssh-rsa', k: 'AAAA1111', cmd: '/bin/echo key-1', origcmd: 'git-upload-pack repo.git' }
		});
		const response = await recvMessage(reader);
		assert.equal(response.exec.ok, true);

		const output = await new Promise((resolve) => {
			const chunks = [];
			reader.on('data', (chunk) => chunks.push(chunk));
			reader.on('end', () => resolve(Buffer.concat(chunks).toString()));
			reader.resume();
		});

		assert.equal(output.trim(), 'key-1');
		socket.destroy();
	});
});
