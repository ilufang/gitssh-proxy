#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { parseConfigFlag, loadConfig, resolveLogOptions, DEFAULT_CLIENT_CONFIG_PATH } = require('../lib/config');
const { createLogger } = require('../lib/log');
const { connect } = require('../lib/connection');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { parseAuthorizedKeys, serializeAuthorizedKeys, transformForProxy, hashKeys } = require('../lib/authkeys');
const { STDIN, STDOUT, STDERR, CONTROL, pipeChannel } = require('../lib/mux');

const { configPath, logFile, logLevel, remainingArgs } = parseConfigFlag(process.argv, DEFAULT_CLIENT_CONFIG_PATH);
const config = loadConfig(configPath, 'client');
const log = createLogger('client', resolveLogOptions(config, logFile, logLevel));

// The original ForceCommand from the server's authorized_keys
const cmd = remainingArgs.join(' ');
const origcmd = process.env.SSH_ORIGINAL_COMMAND || '';
const keyType = process.env.GITSSH_PROXY_KEY_TYPE || '';
const keyData = process.env.GITSSH_PROXY_KEY_DATA || '';

if (!cmd) {
	log.error('No command specified');
	process.exit(1);
}

if (!keyType || !keyData) {
	log.error('GITSSH_PROXY_KEY_TYPE and GITSSH_PROXY_KEY_DATA must be set');
	process.exit(1);
}

// Compute cache file hash
let cacheHash = '';
try {
	const cacheContent = fs.readFileSync(config.cacheFile, 'utf8');
	cacheHash = hashKeys(cacheContent);
} catch (err) {
	// No cache file yet
}

async function main() {
	const { reader, writer, socket } = await connect(config.serverHost, config.serverPort, config.psk);

	let exiting = false;
	socket.on('error', (err) => {
		if (exiting) return;
		log.error(`Connection error: ${err.message}`);
		process.exit(1);
	});

	// Build bundled request
	const request = {
		ts: Math.floor(Date.now() / 1000),
		exec: { t: keyType, k: keyData, cmd, origcmd },
		getkey: {}
	};
	if (cacheHash) {
		request.getkey.match = cacheHash;
	}

	await sendMessage(writer, request);
	const response = await recvMessage(reader);

	// Handle getkey response (async, non-blocking)
	if (response.getkey && response.getkey.keys) {
		updateCache(response.getkey.keys).catch((err) => {
			log.debug(`Cache update failed: ${err.message}`);
		});
	}

	// Handle exec response
	if (response.exec && response.exec.error) {
		log.error(response.exec.error);
		socket.destroy();
		process.exit(1);
	}

	if (!response.exec || !response.exec.ok) {
		log.error('Unexpected response from server');
		socket.destroy();
		process.exit(1);
	}

	// Stream mode: stdin goes out on STDIN (then EOF); stdout/stderr come
	// back on their channels until the server sends the exit status.
	pipeChannel(process.stdin, writer, STDIN).catch((err) => {
		log.debug(`stdin relay failed: ${err.message}`);
	});

	reader.on('data', ({ channel, payload }) => {
		if (!payload) return; // EOF on stdout/stderr: nothing to do
		if (channel === STDOUT) {
			process.stdout.write(payload);
		} else if (channel === STDERR) {
			process.stderr.write(payload);
		} else if (channel === CONTROL) {
			const msg = JSON.parse(payload.toString('utf8'));
			if (msg.exit) {
				exiting = true;
				// Flush stdout before exiting
				process.stdout.write('', () => process.exit(msg.exit.code));
			}
		}
	});
	reader.on('end', () => {
		if (exiting) return;
		log.error('Connection closed before exit status');
		process.exit(1);
	});
	reader.on('error', (err) => {
		log.error(`Stream error: ${err.message}`);
		process.exit(1);
	});
}

async function updateCache(keysRaw) {
	const entries = parseAuthorizedKeys(keysRaw);
	const transformed = transformForProxy(entries, config.clientPath);
	const content = serializeAuthorizedKeys(transformed);

	// Atomic write: temp file then rename
	const tmpFile = config.cacheFile + '.tmp.' + process.pid;
	fs.writeFileSync(tmpFile, content, 'utf8');
	fs.renameSync(tmpFile, config.cacheFile);
	log.debug(`Updated cache: ${config.cacheFile}`);
}

main().catch((err) => {
	log.error(err.message);
	process.exit(1);
});
