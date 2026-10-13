#!/usr/bin/env node
'use strict';

const net = require('net');
const fs = require('fs');
const { parseConfigFlag, loadConfig, resolveLogOptions, DEFAULT_SERVER_CONFIG_PATH } = require('../lib/config');
const { createLogger } = require('../lib/log');
const { wrapTransport } = require('../lib/transport');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { parseAuthorizedKeys, getOption, checkKeyOptions, hashKeys, fingerprint } = require('../lib/authkeys');
const { resolveCommand, validateOrigCmd, buildChildEnv } = require('../lib/command');
const { STDIN, STDOUT, STDERR, pipeChannel } = require('../lib/mux');

const { configPath, logFile, logLevel } = parseConfigFlag(process.argv, DEFAULT_SERVER_CONFIG_PATH);
const config = loadConfig(configPath, 'server');
const log = createLogger('server', resolveLogOptions(config, logFile, logLevel));

if (process.getuid && process.getuid() === 0) {
	log.error('Refusing to run as root; run as the git user');
	process.exit(1);
}

// Authorized keys state. Only servable entries are kept: those with a
// runnable command= (see classifyEntry). Each carries `run: {file, args}`.
let keysServable = [];
let keyList = [];   // [{t, k}] advertised to clients via getkey
let keysEtag = '';
let keysMtime = 0;
let lastLoadError = '';

/**
 * Decide whether an entry can be served through the proxy.
 * Returns { run } or { reason }.
 */
function classifyEntry(entry) {
	if (getOption(entry, 'cert-authority').length > 0 || getOption(entry, 'principals').length > 0) {
		return { reason: 'cert-authority/principals not supported' };
	}
	const commands = getOption(entry, 'command');
	if (commands.length !== 1) return { reason: commands.length ? 'multiple command=' : 'no command=' };
	const run = resolveCommand(commands[0], config.allowedCommands);
	if (run.error) return { reason: run.error };
	return { run };
}

function loadError(msg) {
	if (msg !== lastLoadError) log.error(msg);
	lastLoadError = msg;
}

function reloadKeys() {
	try {
		const stat = fs.statSync(config.authkeysFile);
		if (stat.mode & 0o022) {
			return loadError(`Not loading ${config.authkeysFile}: group/world-writable`);
		}
		if (process.getuid && stat.uid !== process.getuid() && stat.uid !== 0) {
			return loadError(`Not loading ${config.authkeysFile}: owned by uid ${stat.uid}`);
		}
		lastLoadError = '';
		if (stat.mtimeMs === keysMtime) return;

		const entries = parseAuthorizedKeys(fs.readFileSync(config.authkeysFile, 'utf8'));
		const servable = [];
		const seen = new Set();
		const list = [];
		for (const entry of entries) {
			const { run, reason } = classifyEntry(entry);
			if (reason) {
				log.info(`Not serving line ${entry.line} (${entry.keyType} ${fingerprint(entry.keyData)}): ${reason}`);
				continue;
			}
			servable.push({ ...entry, run });
			const id = `${entry.keyType} ${entry.keyData}`;
			if (!seen.has(id)) {
				seen.add(id);
				list.push({ t: entry.keyType, k: entry.keyData });
			}
		}

		keysServable = servable;
		keyList = list;
		keysEtag = hashKeys(JSON.stringify(list));
		keysMtime = stat.mtimeMs;
		log.info(`Loaded ${servable.length} of ${entries.length} keys from ${config.authkeysFile}`);
	} catch (err) {
		loadError(`Failed to read ${config.authkeysFile}: ${err.message}`);
	}
}

/**
 * Find the entry to run for an exec request. As in sshd, the first entry
 * for the key whose from=/expiry-time= options allow it is used.
 * Returns { entry } or { reason }.
 */
function authorizeExec(exec) {
	let reason = 'key not found';
	for (const entry of keysServable) {
		if (entry.keyType !== exec.t || entry.keyData !== exec.k) continue;
		reason = checkKeyOptions(entry, { addr: exec.addr, now: Date.now() });
		if (!reason) return { entry };
	}
	return { reason };
}

// Replay protection: requests must carry a fresh timestamp, and each
// request salt is accepted only once within the timestamp window.
const MAX_SKEW = 60; // seconds
const seenSalts = new Map(); // salt hex -> expiry (insertion order = expiry order)

function checkReplay(ts, salt) {
	const now = Math.floor(Date.now() / 1000);
	if (typeof ts !== 'number' || Math.abs(now - ts) > MAX_SKEW) return 'stale timestamp';
	for (const [key, expiry] of seenSalts) {
		if (expiry >= now) break;
		seenSalts.delete(key);
	}
	const key = salt.toString('hex');
	if (seenSalts.has(key)) return 'replayed salt';
	seenSalts.set(key, now + 2 * MAX_SKEW);
	return null;
}

function handleConnection(socket) {
	const remote = `${socket.remoteAddress}:${socket.remotePort}`;
	log.debug(`Connection from ${remote}`);

	// Reload keys if file changed
	reloadKeys();

	// Nothing is written to the socket until the first request has
	// authenticated and passed the replay check.
	const { reader, writer } = wrapTransport(socket, config.psk);

	socket.on('error', (err) => {
		log.debug(`Socket error from ${remote}: ${err.message}`);
	});

	recvMessage(reader).then((request) => {
		const rejected = checkReplay(request.ts, reader.salt);
		if (rejected) {
			log.info(`Rejected request from ${remote}: ${rejected}`);
			socket.destroy();
			return;
		}

		const response = {};

		// Handle getkey
		if (request.getkey) {
			if (request.getkey.match && request.getkey.match === keysEtag) {
				response.getkey = { notmodified: true };
			} else {
				response.getkey = { keys: keyList, etag: keysEtag };
			}
		}

		// Handle exec
		let execEntry = null;
		let origcmd = '';
		if (request.exec) {
			const exec = request.exec;
			origcmd = exec.origcmd ?? '';
			const { entry, reason } = authorizeExec(exec);
			const who = `${exec.t} ${fingerprint(exec.k)} addr=${JSON.stringify(exec.addr)} via ${remote}`;
			if (!entry) {
				log.info(`Exec denied for ${who}: ${reason}`);
				response.exec = { error: 'Key not authorized' };
			} else if (!validateOrigCmd(origcmd)) {
				log.info(`Exec denied for ${who}: bad origcmd ${JSON.stringify(origcmd)}`);
				response.exec = { error: 'Command not allowed' };
			} else {
				log.info(`Exec line ${entry.line} for ${who}: ${JSON.stringify(origcmd)}`);
				execEntry = entry;
				response.exec = { ok: true };
			}
		}

		return sendMessage(writer, response).then(() => {
			if (execEntry) {
				spawnCommand(execEntry, origcmd, reader, writer, socket, remote);
			} else {
				socket.end();
			}
		});
	}).catch((err) => {
		log.error(`Request error from ${remote}: ${err.message}`);
		socket.destroy();
	});
}

function spawnCommand(entry, origcmd, reader, writer, socket, remote) {
	const { spawn } = require('child_process');
	const { file, args } = entry.run;

	log.debug(`Spawning: ${file} ${JSON.stringify(args)} (SSH_ORIGINAL_COMMAND=${JSON.stringify(origcmd)})`);

	const child = spawn(file, args, {
		env: buildChildEnv(origcmd),
		stdio: ['pipe', 'pipe', 'pipe']
	});

	// Route STDIN frames to the child; stream stdout/stderr back as frames.
	// Once both output channels have sent EOF, report the exit status.
	reader.on('data', ({ channel, payload }) => {
		if (channel !== STDIN) return;
		if (payload) child.stdin.write(payload);
		else child.stdin.end();
	});
	const stdoutDone = pipeChannel(child.stdout, writer, STDOUT).catch(() => {});
	const stderrDone = pipeChannel(child.stderr, writer, STDERR).catch(() => {});

	child.on('error', (err) => {
		log.error(`Spawn error: ${err.message}`);
		socket.destroy();
	});

	child.on('close', (code) => {
		log.debug(`Child exited with code ${code} for ${remote}`);
		Promise.all([stdoutDone, stderrDone])
			.then(() => sendMessage(writer, { exit: { code: code ?? 1 } }))
			.then(() => socket.end(), () => socket.destroy());
	});

	socket.on('close', () => {
		child.kill();
	});

	// Handle stdin errors (e.g., child exits before all data is written)
	child.stdin.on('error', () => {});
}

// Initial key load
reloadKeys();

const server = net.createServer(handleConnection);

server.listen(config.port, config.listen, () => {
	log.info(`Listening on ${config.listen}:${config.port}`);
});

server.on('error', (err) => {
	log.error(`Server error: ${err.message}`);
	process.exit(1);
});
