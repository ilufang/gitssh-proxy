'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_CONFIG_PATH = '/etc/gitssh-proxy/config.json';

const DEFAULTS = {
	server: {
		listen: '0.0.0.0',
		port: 9422,
		authkeysFile: '/home/git/.ssh/authorized_keys'
	},
	client: {
		serverHost: '127.0.0.1',
		serverPort: 9422,
		cacheFile: '/home/git/.ssh/authorized_keys'
	},
	authkeys: {
		serverHost: '127.0.0.1',
		serverPort: 9422,
		cacheFile: '/home/git/.ssh/authorized_keys',
		clientPath: 'gitssh-proxy-client'
	}
};

/**
 * Parse -C flag from argv and return { configPath, remainingArgs }.
 */
function parseConfigFlag(argv) {
	const args = argv.slice(2);
	let configPath = DEFAULT_CONFIG_PATH;
	const remaining = [];

	for (let i = 0; i < args.length; i++) {
		if (args[i] === '-C' && i + 1 < args.length) {
			configPath = args[i + 1];
			i++; // skip the path argument
		} else {
			remaining.push(args[i]);
		}
	}

	return { configPath, remainingArgs: remaining };
}

/**
 * Load config file and return the requested section merged with defaults.
 */
function loadConfig(configPath, section) {
	const defaults = DEFAULTS[section];
	if (!defaults) {
		throw new Error(`Unknown config section: ${section}`);
	}

	let fileConfig = {};
	try {
		const raw = fs.readFileSync(configPath, 'utf8');
		const parsed = JSON.parse(raw);
		fileConfig = parsed[section] || {};
	} catch (err) {
		if (err.code !== 'ENOENT') {
			throw new Error(`Failed to read config ${configPath}: ${err.message}`);
		}
		// Config file not found — use defaults
	}

	return { ...defaults, ...fileConfig };
}

module.exports = { parseConfigFlag, loadConfig, DEFAULT_CONFIG_PATH };
