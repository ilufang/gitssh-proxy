#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { parseConfigFlag, loadConfig, resolveLogOptions, DEFAULT_CLIENT_CONFIG_PATH } = require('../lib/config');
const { createLogger } = require('../lib/log');
const { connect } = require('../lib/connection');
const { sendMessage, recvMessage, generateTsNonce } = require('../lib/protocol');
const { buildProxyAuthorizedKeys, writeCache, readEtag } = require('../lib/authkeys');

const { configPath, logFile, logLevel } = parseConfigFlag(process.argv, DEFAULT_CLIENT_CONFIG_PATH);
const config = loadConfig(configPath, 'client');
const log = createLogger('authkeys', resolveLogOptions(config, logFile, logLevel));

async function main() {
	// Read the etag of the last fetch and the existing cache
	const etag = readEtag(config.cacheFile);
	let cacheContent = '';
	try {
		cacheContent = fs.readFileSync(config.cacheFile, 'utf8');
	} catch (err) {
		// No cache file yet
	}

	let keys;
	let newEtag;
	try {
		const { reader, writer, socket } = await connect(config.serverHost, config.serverPort, config.psk);

		const request = { ts: generateTsNonce(), getkey: {} };
		if (etag) {
			request.getkey.match = etag;
		}

		await sendMessage(writer, request);
		const response = await recvMessage(reader);
		socket.destroy();

		if (response.getkey && response.getkey.keys) {
			// Cache is stale, got new keys
			keys = response.getkey.keys;
			newEtag = response.getkey.etag;
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

	// Build our own authorized_keys from the key list
	let content;
	try {
		const built = buildProxyAuthorizedKeys(keys, config.clientPath);
		if (built.dropped) log.info(`Dropped ${built.dropped} invalid keys from server`);
		content = built.content;
	} catch (err) {
		log.error(`Invalid key list from server: ${err.message}`);
		outputFallback(cacheContent);
		return;
	}

	try {
		writeCache(config.cacheFile, content, newEtag);
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
