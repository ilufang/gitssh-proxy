#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { parseConfigFlag, loadConfig, resolveLogOptions, DEFAULT_CLIENT_CONFIG_PATH } = require('../lib/config');
const { createLogger } = require('../lib/log');
const { connect } = require('../lib/connection');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { parseAuthorizedKeys, serializeAuthorizedKeys, transformForProxy, hashKeys } = require('../lib/authkeys');
const { demux } = require('../lib/mux');

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
	const { reader, writer, socket } = await connect(config.serverHost, config.serverPort);

	// Build bundled request
	const request = {
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

	// Keep socket half-open: we need to keep reading from the server
	// (demux) even after stdin ends. allowHalfOpen lets us send our FIN
	// without tearing down the receive side.
	socket.allowHalfOpen = true;

	// Stream mode: demux stdout+stderr from reader, pipe stdin to writer
	process.stdin.pipe(writer, { end: false });
	process.stdin.on('end', () => {
		// Signal EOF to server without closing the receive side
		socket.end();
	});

	demux(reader, process.stdout, process.stderr).then(() => {
		process.exit(0);
	}).catch((err) => {
		log.error(`Stream error: ${err.message}`);
		process.exit(1);
	});

	socket.on('error', (err) => {
		log.error(`Connection error: ${err.message}`);
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
