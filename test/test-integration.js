'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('events');
const { spawn } = require('child_process');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { wrapTransport } = require('../lib/transport');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { STDIN, STDOUT, STDERR, CONTROL } = require('../lib/mux');
const { hashKeys } = require('../lib/authkeys');

const PSK = 'test-psk';

// Test authorized_keys content
const TEST_KEYS = [
	'command="echo key-1",no-pty ssh-rsa AAAA1111 user1@host',
	'command="echo key-2",no-pty ssh-ed25519 BBBB2222 user2@host',
	'command="cat",no-pty ssh-ed25519 CCCC3333 user3@host',
	'command="echo oops >&2; exit 3",no-pty ssh-ed25519 DDDD4444 user4@host',
	'command="echo $SSH_ORIGINAL_COMMAND",no-pty ssh-ed25519 EEEE5555 user5@host'
].join('\n') + '\n';

const TEST_KEYS_HASH = hashKeys(TEST_KEYS);

function now() {
	return Math.floor(Date.now() / 1000);
}

/** Collect stdout/stderr frames and the exit message until the server closes. */
function collectOutput(reader) {
	return new Promise((resolve, reject) => {
		const out = { stdout: '', stderr: '', exit: null };
		reader.on('data', ({ channel, payload }) => {
			if (!payload) return;
			if (channel === STDOUT) out.stdout += payload;
			else if (channel === STDERR) out.stderr += payload;
			else if (channel === CONTROL) out.exit = JSON.parse(payload.toString()).exit;
		});
		reader.on('end', () => resolve(out));
		reader.on('error', reject);
	});
}

/** Count raw bytes received on a socket until it closes. */
function bytesUntilClose(socket) {
	return new Promise((resolve) => {
		let n = 0;
		socket.on('data', (chunk) => { n += chunk.length; });
		socket.on('error', () => {});
		socket.on('close', () => resolve(n));
	});
}

describe('integration', () => {
	let tmpDir;
	let serverProc;
	let port;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitssh-proxy-test-'));
		const authkeysFile = path.join(tmpDir, 'authorized_keys');
		fs.writeFileSync(authkeysFile, TEST_KEYS);

		const probe = net.createServer().listen(0, '127.0.0.1');
		await once(probe, 'listening');
		port = probe.address().port;
		await new Promise((resolve) => probe.close(resolve));

		const configFile = path.join(tmpDir, 'server.json');
		fs.writeFileSync(configFile, JSON.stringify({ listen: '127.0.0.1', port, authkeysFile, psk: PSK }));

		serverProc = spawn(process.execPath, [
			path.join(__dirname, '..', 'bin', 'gitssh-proxy-server.js'), '-C', configFile, '--log', '-'
		], { stdio: ['ignore', 'ignore', 'pipe'] });

		await new Promise((resolve, reject) => {
			let log = '';
			serverProc.stderr.on('data', (chunk) => {
				log += chunk;
				if (log.includes('Listening')) resolve();
			});
			serverProc.on('exit', () => reject(new Error('Server exited: ' + log)));
		});
	});

	after(() => {
		serverProc.kill();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	async function open(psk = PSK) {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await once(socket, 'connect');
		return wrapTransport(socket, psk);
	}

	it('getkey returns full keys when no match hash', async () => {
		const { reader, writer, socket } = await open();
		await sendMessage(writer, { ts: now(), getkey: {} });
		const response = await recvMessage(reader);
		assert.equal(response.getkey.keys, TEST_KEYS);
		socket.destroy();
	});

	it('getkey returns notmodified when hash matches', async () => {
		const { reader, writer, socket } = await open();
		await sendMessage(writer, { ts: now(), getkey: { match: TEST_KEYS_HASH } });
		const response = await recvMessage(reader);
		assert.equal(response.getkey.notmodified, true);
		socket.destroy();
	});

	it('exec with valid key streams stdout and exit code 0', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-rsa', k: 'AAAA1111', cmd: 'echo key-1', origcmd: '' } });
		const response = await recvMessage(reader);
		assert.equal(response.exec.ok, true);

		const out = await collectOutput(reader);
		assert.equal(out.stdout.trim(), 'key-1');
		assert.deepEqual(out.exit, { code: 0 });
	});

	it('exec propagates stderr and non-zero exit code', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-ed25519', k: 'DDDD4444', cmd: '', origcmd: '' } });
		assert.equal((await recvMessage(reader)).exec.ok, true);

		const out = await collectOutput(reader);
		assert.equal(out.stderr.trim(), 'oops');
		assert.deepEqual(out.exit, { code: 3 });
	});

	it('exec relays stdin and its EOF to the child', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-ed25519', k: 'CCCC3333', cmd: 'cat', origcmd: '' } });
		assert.equal((await recvMessage(reader)).exec.ok, true);

		const output = collectOutput(reader);
		await writer.send(STDIN, Buffer.from('hello '));
		await writer.send(STDIN, Buffer.from('world'));
		await writer.sendEof(STDIN);

		const out = await output;
		assert.equal(out.stdout, 'hello world');
		assert.deepEqual(out.exit, { code: 0 });
	});

	it('exec passes SSH_ORIGINAL_COMMAND to spawned process', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, {
			ts: now(),
			exec: { t: 'ssh-ed25519', k: 'EEEE5555', cmd: '', origcmd: 'git-upload-pack repo.git' }
		});
		assert.equal((await recvMessage(reader)).exec.ok, true);

		const out = await collectOutput(reader);
		assert.equal(out.stdout.trim(), 'git-upload-pack repo.git');
	});

	it('exec with invalid key returns error', async () => {
		const { reader, writer, socket } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-rsa', k: 'INVALID', cmd: 'test', origcmd: '' } });
		const response = await recvMessage(reader);
		assert.equal(response.exec.error, 'Key not authorized');
		socket.destroy();
	});

	it('bundled exec+getkey returns both responses', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, {
			ts: now(),
			exec: { t: 'ssh-ed25519', k: 'BBBB2222', cmd: 'echo key-2', origcmd: '' },
			getkey: { match: TEST_KEYS_HASH }
		});
		const response = await recvMessage(reader);
		assert.equal(response.exec.ok, true);
		assert.equal(response.getkey.notmodified, true);

		const out = await collectOutput(reader);
		assert.equal(out.stdout.trim(), 'key-2');
	});

	it('rejects a stale timestamp without sending anything', async () => {
		const { writer, socket } = await open();
		const received = bytesUntilClose(socket);
		await sendMessage(writer, { ts: now() - 3600, getkey: {} });
		assert.equal(await received, 0);
	});

	it('rejects a request without timestamp', async () => {
		const { writer, socket } = await open();
		const received = bytesUntilClose(socket);
		await sendMessage(writer, { getkey: {} });
		assert.equal(await received, 0);
	});

	it('rejects a replayed connection without sending anything', async () => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		await once(socket, 'connect');
		const sent = [];
		const origWrite = socket.write.bind(socket);
		socket.write = (buf, cb) => { sent.push(buf); return origWrite(buf, cb); };
		const { reader, writer } = wrapTransport(socket, PSK);
		await sendMessage(writer, { ts: now(), getkey: {} });
		assert.ok((await recvMessage(reader)).getkey);
		socket.destroy();

		const replay = net.createConnection({ host: '127.0.0.1', port });
		await once(replay, 'connect');
		const received = bytesUntilClose(replay);
		replay.write(Buffer.concat(sent));
		assert.equal(await received, 0);
	});

	it('rejects a wrong psk without sending anything', async () => {
		const { writer, socket } = await open('wrong-psk');
		const received = bytesUntilClose(socket);
		await sendMessage(writer, { ts: now(), getkey: {} });
		assert.equal(await received, 0);
	});
});
