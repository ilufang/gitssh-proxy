#!/usr/bin/env node
'use strict';

const net = require('net');
const fs = require('fs');
const { parseConfigFlag, loadConfig } = require('../lib/config');
const { createLogger } = require('../lib/log');
const { wrapTransport } = require('../lib/transport');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { parseAuthorizedKeys, findKey, hashKeys } = require('../lib/authkeys');

const log = createLogger('server');
const { configPath, remainingArgs } = parseConfigFlag(process.argv);
const config = loadConfig(configPath, 'server');

// Authorized keys state
let keysRaw = '';
let keysHash = '';
let keysParsed = [];
let keysMtime = 0;

function reloadKeys() {
	try {
		const stat = fs.statSync(config.authkeysFile);
		if (stat.mtimeMs === keysMtime) return;

		keysRaw = fs.readFileSync(config.authkeysFile, 'utf8');
		keysHash = hashKeys(keysRaw);
		keysParsed = parseAuthorizedKeys(keysRaw);
		keysMtime = stat.mtimeMs;
		log.info(`Loaded ${keysParsed.length} keys from ${config.authkeysFile}`);
	} catch (err) {
		log.error(`Failed to read ${config.authkeysFile}: ${err.message}`);
	}
}

function handleConnection(socket) {
	const remote = `${socket.remoteAddress}:${socket.remotePort}`;
	log.debug(`Connection from ${remote}`);

	// Reload keys if file changed
	reloadKeys();

	const { reader, writer } = wrapTransport(socket);

	socket.on('error', (err) => {
		log.debug(`Socket error from ${remote}: ${err.message}`);
	});

	recvMessage(reader).then((request) => {
		const response = {};

		// Handle getkey
		if (request.getkey) {
			if (request.getkey.match && request.getkey.match === keysHash) {
				response.getkey = { notmodified: true };
			} else {
				response.getkey = { keys: keysRaw };
			}
		}

		// Handle exec
		let execEntry = null;
		if (request.exec) {
			execEntry = findKey(keysParsed, request.exec.t, request.exec.k);
			if (!execEntry) {
				response.exec = { error: 'Key not authorized' };
			} else {
				response.exec = { ok: true };
			}
		}

		return sendMessage(writer, response).then(() => {
			if (execEntry && response.exec.ok) {
				spawnCommand(execEntry, request.exec.origcmd, reader, writer, socket, remote);
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

	// Extract the command= value from the entry's options
	const cmdOpt = entry.options.find(o => o.name === 'command');
	if (!cmdOpt || cmdOpt.value === true) {
		log.error(`No command= found for key from ${remote}`);
		socket.destroy();
		return;
	}

	const env = { ...process.env };
	if (origcmd) {
		env.SSH_ORIGINAL_COMMAND = origcmd;
	}

	log.debug(`Spawning: ${cmdOpt.value} (SSH_ORIGINAL_COMMAND=${origcmd || ''})`);

	const shell = process.platform === 'win32' ? process.env.SHELL || 'sh' : '/bin/sh';
	const child = spawn(shell, ['-c', cmdOpt.value], {
		env,
		stdio: ['pipe', 'pipe', 'pipe']
	});

	// Pipe stdio
	reader.pipe(child.stdin);
	child.stdout.pipe(writer);

	// Log stderr on server side
	child.stderr.on('data', (chunk) => {
		log.debug(`stderr: ${chunk.toString().trimEnd()}`);
	});

	child.on('error', (err) => {
		log.error(`Spawn error: ${err.message}`);
		socket.destroy();
	});

	child.on('close', (code) => {
		log.debug(`Child exited with code ${code} for ${remote}`);
		socket.end();
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
