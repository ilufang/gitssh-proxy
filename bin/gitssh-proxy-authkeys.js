#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { parseConfigFlag, loadConfig, resolveLogOptions, DEFAULT_CLIENT_CONFIG_PATH } = require('../lib/config');
const { createLogger } = require('../lib/log');
const { connect } = require('../lib/connection');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { parseAuthorizedKeys, serializeAuthorizedKeys, transformForProxy, hashKeys } = require('../lib/authkeys');

const { configPath, logFile, logLevel } = parseConfigFlag(process.argv, DEFAULT_CLIENT_CONFIG_PATH);
const config = loadConfig(configPath, 'client');
const log = createLogger('authkeys', resolveLogOptions(config, logFile, logLevel));

async function main() {
	// Read current cache hash if cache exists
	let cacheHash = '';
	let cacheContent = '';
	try {
		cacheContent = fs.readFileSync(config.cacheFile, 'utf8');
		cacheHash = hashKeys(cacheContent);
	} catch (err) {
		// No cache file yet
	}

	let keysRaw;
	try {
		const { reader, writer, socket } = await connect(config.serverHost, config.serverPort, config.psk);

		const request = { ts: Math.floor(Date.now() / 1000), getkey: {} };
		if (cacheHash) {
			request.getkey.match = cacheHash;
		}

		await sendMessage(writer, request);
		const response = await recvMessage(reader);
		socket.destroy();

		if (response.getkey && response.getkey.keys) {
			// Cache is stale, got new keys
			keysRaw = response.getkey.keys;
		} else if (response.getkey && response.getkey.notmodified) {
			// Cache is current. Key is genuinely not authorized.
			// Output existing cache for sshd (it will fail to match).
			process.stdout.write(cacheContent);
			return;
		} else {
			log.error('Unexpected response from server');
			outputFallback(cacheContent);
			return;
		}
	} catch (err) {
		log.error(`Server connection failed: ${err.message}`);
		outputFallback(cacheContent);
		return;
	}

	// Transform and cache the new keys
	const entries = parseAuthorizedKeys(keysRaw);
	const transformed = transformForProxy(entries, config.clientPath);
	const content = serializeAuthorizedKeys(transformed);

	// Atomic write to cache
	try {
		const tmpFile = config.cacheFile + '.tmp.' + process.pid;
		fs.writeFileSync(tmpFile, content, 'utf8');
		fs.renameSync(tmpFile, config.cacheFile);
		log.debug(`Updated cache: ${config.cacheFile}`);
	} catch (err) {
		log.error(`Failed to write cache: ${err.message}`);
	}

	// Output for sshd
	process.stdout.write(content);
}

function outputFallback(cacheContent) {
	if (cacheContent) {
		process.stdout.write(cacheContent);
	}
	// If no cache either, output nothing — sshd will deny access
}

main().catch((err) => {
	log.error(err.message);
	process.exit(0); // Exit 0 to avoid alarming sshd
});
