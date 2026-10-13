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

const PSK = 'test-psk';
const ADDR = '10.1.2.3';

// Test authorized_keys content
const TEST_KEYS = [
	'command="echo key-1",no-pty ssh-rsa AAAA1111 user1@host',
	'command="echo key-2",no-pty ssh-ed25519 BBBB2222 user2@host',
	'command="cat",no-pty ssh-ed25519 CCCC3333 user3@host',
	'command="echo oops >&2; exit 3",no-pty ssh-ed25519 DDDD4444 user4@host',
	'command="echo $SSH_ORIGINAL_COMMAND",no-pty ssh-ed25519 EEEE5555 user5@host',
	'no-pty ssh-ed25519 FFFF6666 shell@host',
	'cert-authority,command="echo ca" ssh-ed25519 GGGG7777 ca@host',
	'from="10.0.0.0/8,!10.9.0.0/16",command="echo from-ok" ssh-ed25519 HHHH8888',
	'expiry-time="20000101",command="echo expired" ssh-ed25519 IIII9999',
	'expiry-time="29991231Z",command="echo fresh" ssh-ed25519 JJJJ0000',
	'command="env" ssh-ed25519 KKKK1111'
].join('\n') + '\n';

const SERVABLE_KEYS = [
	{ t: 'ssh-rsa', k: 'AAAA1111' },
	{ t: 'ssh-ed25519', k: 'BBBB2222' },
	{ t: 'ssh-ed25519', k: 'CCCC3333' },
	{ t: 'ssh-ed25519', k: 'DDDD4444' },
	{ t: 'ssh-ed25519', k: 'EEEE5555' },
	{ t: 'ssh-ed25519', k: 'HHHH8888' },
	{ t: 'ssh-ed25519', k: 'IIII9999' },
	{ t: 'ssh-ed25519', k: 'JJJJ0000' },
	{ t: 'ssh-ed25519', k: 'KKKK1111' }
];

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

/**
 * Start a server process with the given config and authorized_keys content.
 * Returns { port, tmpDir, open(psk), stop() }.
 */
async function startServer(serverConfig, keys) {
	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitssh-proxy-test-'));
	const authkeysFile = path.join(tmpDir, 'authorized_keys');
	fs.writeFileSync(authkeysFile, keys, { mode: 0o600 });

	const probe = net.createServer().listen(0, '127.0.0.1');
	await once(probe, 'listening');
	const port = probe.address().port;
	await new Promise((resolve) => probe.close(resolve));

	const configFile = path.join(tmpDir, 'server.json');
	fs.writeFileSync(configFile, JSON.stringify({ listen: '127.0.0.1', port, authkeysFile, psk: PSK, ...serverConfig }));

	const proc = spawn(process.execPath, [
		path.join(__dirname, '..', 'bin', 'gitssh-proxy-server.js'), '-C', configFile, '--log', '-'
	], { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, GITSSH_TEST_SENTINEL: 'leaked' } });

	await new Promise((resolve, reject) => {
		let log = '';
		proc.stderr.on('data', (chunk) => {
			log += chunk;
			if (log.includes('Listening')) resolve();
		});
		proc.on('exit', () => reject(new Error('Server exited: ' + log)));
	});

	return {
		port,
		tmpDir,
		async open(psk = PSK) {
			const socket = net.createConnection({ host: '127.0.0.1', port });
			await once(socket, 'connect');
			return wrapTransport(socket, psk);
		},
		stop() {
			proc.kill();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	};
}

/** Send an exec request; return { response, out } where out is the collected output (if ok). */
async function exec(server, k, { t = 'ssh-ed25519', addr = ADDR, origcmd = '' } = {}) {
	const { reader, writer, socket } = await server.open();
	await sendMessage(writer, { ts: now(), exec: { t, k, addr, origcmd } });
	const response = await recvMessage(reader);
	if (!response.exec.ok) {
		socket.destroy();
		return { response };
	}
	const output = collectOutput(reader);
	await writer.sendEof(STDIN);
	return { response, out: await output };
}

describe('integration', () => {
	let server;
	let port;
	let etag;

	before(async () => {
		server = await startServer({}, TEST_KEYS);
		port = server.port;
	});

	after(() => server.stop());

	const open = (psk) => server.open(psk);

	it('getkey returns only the servable keys and an etag', async () => {
		const { reader, writer, socket } = await open();
		await sendMessage(writer, { ts: now(), getkey: {} });
		const response = await recvMessage(reader);
		assert.deepEqual(response.getkey.keys, SERVABLE_KEYS);
		assert.equal(typeof response.getkey.etag, 'string');
		etag = response.getkey.etag;
		socket.destroy();
	});

	it('getkey returns notmodified when etag matches', async () => {
		const { reader, writer, socket } = await open();
		await sendMessage(writer, { ts: now(), getkey: { match: etag } });
		const response = await recvMessage(reader);
		assert.equal(response.getkey.notmodified, true);
		socket.destroy();
	});

	it('exec with valid key streams stdout and exit code 0', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-rsa', k: 'AAAA1111', addr: ADDR, origcmd: '' } });
		const response = await recvMessage(reader);
		assert.equal(response.exec.ok, true);

		const out = await collectOutput(reader);
		assert.equal(out.stdout.trim(), 'key-1');
		assert.deepEqual(out.exit, { code: 0 });
	});

	it('exec propagates stderr and non-zero exit code', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-ed25519', k: 'DDDD4444', addr: ADDR, origcmd: '' } });
		assert.equal((await recvMessage(reader)).exec.ok, true);

		const out = await collectOutput(reader);
		assert.equal(out.stderr.trim(), 'oops');
		assert.deepEqual(out.exit, { code: 3 });
	});

	it('exec relays stdin and its EOF to the child', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-ed25519', k: 'CCCC3333', addr: ADDR, origcmd: '' } });
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
			exec: { t: 'ssh-ed25519', k: 'EEEE5555', addr: ADDR, origcmd: 'git-upload-pack repo.git' }
		});
		assert.equal((await recvMessage(reader)).exec.ok, true);

		const out = await collectOutput(reader);
		assert.equal(out.stdout.trim(), 'git-upload-pack repo.git');
	});

	it('exec with invalid key returns error', async () => {
		const { reader, writer, socket } = await open();
		await sendMessage(writer, { ts: now(), exec: { t: 'ssh-rsa', k: 'INVALID', addr: ADDR, origcmd: '' } });
		const response = await recvMessage(reader);
		assert.equal(response.exec.error, 'Key not authorized');
		socket.destroy();
	});

	it('bundled exec+getkey returns both responses', async () => {
		const { reader, writer } = await open();
		await sendMessage(writer, {
			ts: now(),
			exec: { t: 'ssh-ed25519', k: 'BBBB2222', addr: ADDR, origcmd: '' },
			getkey: { match: etag }
		});
		const response = await recvMessage(reader);
		assert.equal(response.exec.ok, true);
		assert.equal(response.getkey.notmodified, true);

		const out = await collectOutput(reader);
		assert.equal(out.stdout.trim(), 'key-2');
	});

	it('exec refuses entries without command= or with cert-authority', async () => {
		for (const k of ['FFFF6666', 'GGGG7777']) {
			const { response } = await exec(server, k);
			assert.equal(response.exec.error, 'Key not authorized', k);
		}
	});

	it('exec enforces from=', async () => {
		assert.equal((await exec(server, 'HHHH8888', { addr: '10.1.2.3' })).out.stdout.trim(), 'from-ok');
		assert.equal((await exec(server, 'HHHH8888', { addr: '::ffff:10.1.2.3' })).out.stdout.trim(), 'from-ok');
		for (const addr of ['11.1.2.3', '10.9.2.3', '', null]) {
			const { response } = await exec(server, 'HHHH8888', { addr });
			assert.equal(response.exec.error, 'Key not authorized', String(addr));
		}
	});

	it('exec enforces expiry-time=', async () => {
		assert.equal((await exec(server, 'IIII9999')).response.exec.error, 'Key not authorized');
		assert.equal((await exec(server, 'JJJJ0000')).out.stdout.trim(), 'fresh');
	});

	it('exec refuses an origcmd that is not git-* or spans lines', async () => {
		for (const origcmd of ['sh', 'ls -la', "git-upload-pack 'x'\nid", 42]) {
			const { response } = await exec(server, 'EEEE5555', { origcmd });
			assert.equal(response.exec.error, 'Command not allowed', JSON.stringify(origcmd));
		}
	});

	it('exec gives the child a minimal environment', async () => {
		const { out } = await exec(server, 'KKKK1111', { origcmd: "git-upload-pack 'r.git'" });
		assert.match(out.stdout, /^SSH_ORIGINAL_COMMAND=git-upload-pack 'r.git'$/m);
		assert.doesNotMatch(out.stdout, /GITSSH_TEST_SENTINEL/);
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

describe('integration with allowedCommands', () => {
	let server;
	let pwned;

	before(async () => {
		const keys = [
			'command="/bin/echo key-1" ssh-ed25519 AAAA1111',
			"command=\"/bin/sh -c 'echo $SSH_ORIGINAL_COMMAND'\" ssh-ed25519 BBBB2222",
			'command="/usr/bin/env" ssh-ed25519 CCCC3333',
			'command="/bin/echo a; touch PWNED" ssh-ed25519 DDDD4444',
			"command=\"/bin/echo 'a; touch PWNED'\" ssh-ed25519 EEEE5555"
		].join('\n') + '\n';
		// Marker file that the injected 'touch' would create if a shell ran
		pwned = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gitssh-proxy-pwned-')), 'pwned');
		server = await startServer({ allowedCommands: ['/bin/echo', '/bin/sh'] }, keys.replaceAll('PWNED', pwned));
	});

	after(() => {
		server.stop();
		fs.rmSync(path.dirname(pwned), { recursive: true, force: true });
	});

	it('getkey advertises only allowlisted, plain commands', async () => {
		const { reader, writer, socket } = await server.open();
		await sendMessage(writer, { ts: now(), getkey: {} });
		const response = await recvMessage(reader);
		assert.deepEqual(response.getkey.keys.map(key => key.k), ['AAAA1111', 'BBBB2222', 'EEEE5555']);
		socket.destroy();
	});

	it('runs allowlisted commands', async () => {
		assert.equal((await exec(server, 'AAAA1111')).out.stdout, 'key-1\n');
		const { out } = await exec(server, 'BBBB2222', { origcmd: "git-upload-pack 'r.git'" });
		assert.equal(out.stdout, "git-upload-pack 'r.git'\n");
	});

	it('refuses unlisted executables and shell syntax', async () => {
		for (const k of ['CCCC3333', 'DDDD4444']) {
			assert.equal((await exec(server, k)).response.exec.error, 'Key not authorized', k);
		}
		assert.equal(fs.existsSync(pwned), false);
	});

	it('passes quoted arguments without a shell', async () => {
		const { out } = await exec(server, 'EEEE5555');
		assert.equal(out.stdout, `a; touch ${pwned}\n`);
		assert.equal(fs.existsSync(pwned), false);
	});
});
