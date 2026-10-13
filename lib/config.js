'use strict';

const fs = require('fs');
const { isValidClientPath } = require('./authkeys');
const { checkAllowedCommands } = require('./command');

const DEFAULT_SERVER_CONFIG_PATH = '/etc/gitssh-proxy/server.json';
const DEFAULT_CLIENT_CONFIG_PATH = '/etc/gitssh-proxy/client.json';

const DEFAULTS = {
	server: {
		listen: '0.0.0.0',
		port: 9422,
		authkeysFile: '/home/git/.ssh/authorized_keys',
		logFile: '/var/log/gitssh-proxy.log',
		logLevel: 'info'
	},
	// client and authkeys share the same config file and the same defaults.
	// authkeys additionally uses clientPath.
	client: {
		serverHost: '127.0.0.1',
		serverPort: 9422,
		cacheFile: '/home/git/.ssh/authorized_keys',
		clientPath: 'gitssh-proxy-client',
		logFile: '/var/log/gitssh-proxy.log',
		logLevel: 'info'
	}
};

/**
 * Parse -C, --log, -v/--verbose flags from argv.
 * Returns { configPath, logFile, logLevel, remainingArgs }.
 *
 * --log <path>   override log file path; '--log -' means stderr
 * -v / --verbose set logLevel to 'debug'
 */
function parseConfigFlag(argv, defaultConfigPath) {
	const args = argv.slice(2);
	let configPath = defaultConfigPath;
	let logFile;    // undefined = not set on CLI
	let logLevel;   // undefined = not set on CLI
	const remaining = [];

	for (let i = 0; i < args.length; i++) {
		if (args[i] === '-C' && i + 1 < args.length) {
			configPath = args[i + 1];
			i++;
		} else if (args[i] === '--log' && i + 1 < args.length) {
			logFile = args[i + 1];
			i++;
		} else if (args[i] === '-v' || args[i] === '--verbose') {
			logLevel = 'debug';
		} else {
			remaining.push(args[i]);
		}
	}

	return { configPath, logFile, logLevel, remainingArgs: remaining };
}

/**
 * Load config file and return config merged with defaults.
 * section must be 'server' or 'client'.
 */
function loadConfig(configPath, section) {
	const defaults = DEFAULTS[section];
	if (!defaults) {
		throw new Error(`Unknown config section: ${section}`);
	}

	let fileConfig = {};
	try {
		const raw = fs.readFileSync(configPath, 'utf8');
		fileConfig = JSON.parse(raw);
	} catch (err) {
		if (err.code !== 'ENOENT') {
			throw new Error(`Failed to read config ${configPath}: ${err.message}`);
		}
		// Config file not found — use defaults
	}

	const config = { ...defaults, ...fileConfig };
	if (!config.psk) {
		throw new Error(`Missing "psk" in config ${configPath}`);
	}
	if (section === 'client' && !isValidClientPath(config.clientPath)) {
		throw new Error(`Invalid "clientPath" in config ${configPath}: only [A-Za-z0-9._/-] allowed`);
	}
	if (section === 'server') {
		const err = checkAllowedCommands(config.allowedCommands);
		if (err) throw new Error(`${err} in config ${configPath}`);
	}
	return config;
}

/**
 * Build log options from config + CLI overrides.
 * CLI values (if defined) take precedence over config file values.
 */
function resolveLogOptions(config, cliLogFile, cliLogLevel) {
	return {
		logFile: cliLogFile !== undefined ? cliLogFile : config.logFile,
		logLevel: cliLogLevel !== undefined ? cliLogLevel : config.logLevel
	};
}

module.exports = { parseConfigFlag, loadConfig, resolveLogOptions, DEFAULT_SERVER_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH };
