#!/usr/bin/env node
'use strict';

const { parseConfigFlag, loadConfig, resolveLogOptions, DEFAULT_CLIENT_CONFIG_PATH } = require('../lib/config');
const { createLogger } = require('../lib/log');
const { connect } = require('../lib/connection');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { buildProxyAuthorizedKeys, writeCache, readEtag } = require('../lib/authkeys');
const { STDIN, STDOUT, STDERR, CONTROL, pipeChannel } = require('../lib/mux');

const { configPath, logFile, logLevel, remainingArgs } = parseConfigFlag(process.argv, DEFAULT_CLIENT_CONFIG_PATH);
const config = loadConfig(configPath, 'client');
const log = createLogger('client', resolveLogOptions(config, logFile, logLevel));

if (remainingArgs.length > 0) {
	log.error(`Unexpected arguments: ${JSON.stringify(remainingArgs)}`);
	process.exit(1);
}

const origcmd = process.env.SSH_ORIGINAL_COMMAND || '';
const keyType = process.env.GITSSH_PROXY_KEY_TYPE || '';
const keyData = process.env.GITSSH_PROXY_KEY_DATA || '';
const addr = (process.env.SSH_CONNECTION || '').split(' ')[0];

if (!keyType || !keyData) {
	log.error('GITSSH_PROXY_KEY_TYPE and GITSSH_PROXY_KEY_DATA must be set');
	process.exit(1);
}

const etag = readEtag(config.cacheFile);

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
		exec: { t: keyType, k: keyData, addr, origcmd },
		getkey: {}
	};
	if (etag) {
		request.getkey.match = etag;
	}

	await sendMessage(writer, request);
	const response = await recvMessage(reader);

	// Refresh the local cache; a failure does not affect this session
	if (response.getkey && response.getkey.keys) {
		try {
			updateCache(response.getkey.keys, response.getkey.etag);
		} catch (err) {
			log.debug(`Cache update failed: ${err.message}`);
		}
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

function updateCache(keys, newEtag) {
	const { content, dropped } = buildProxyAuthorizedKeys(keys, config.clientPath);
	if (dropped) log.info(`Dropped ${dropped} invalid keys from server`);
	writeCache(config.cacheFile, content, newEtag);
	log.debug(`Updated cache: ${config.cacheFile}`);
}

main().catch((err) => {
	log.error(err.message);
	process.exit(1);
});
