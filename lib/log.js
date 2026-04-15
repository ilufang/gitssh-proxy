'use strict';

const fs = require('fs');

// Log levels: 0=error only, 1=info (default), 2=debug
const LEVEL_ERROR = 0;
const LEVEL_INFO = 1;
const LEVEL_DEBUG = 2;

const LEVEL_NAMES = { error: LEVEL_ERROR, info: LEVEL_INFO, debug: LEVEL_DEBUG };

const DEFAULT_LOG_FILE = '/var/log/gitssh-proxy.log';

/**
 * Create a logger.
 *
 * options:
 *   logFile  — path to log file, or '-' / null for stderr (default: DEFAULT_LOG_FILE)
 *   logLevel — 'error' | 'info' | 'debug'  (default: 'info')
 */
function createLogger(prefix, options = {}) {
	const tag = `[${prefix}]`;

	// Resolve log level
	let level = LEVEL_INFO;
	if (options.logLevel !== undefined) {
		const l = typeof options.logLevel === 'string'
			? LEVEL_NAMES[options.logLevel.toLowerCase()]
			: options.logLevel;
		if (l !== undefined) level = l;
	} else if (process.env.GITSSH_PROXY_DEBUG === '1') {
		// Legacy env-var compat
		level = LEVEL_DEBUG;
	}

	// Resolve output destination
	let logFd = null; // null means stderr
	const logFile = options.logFile;
	if (logFile && logFile !== '-') {
		try {
			logFd = fs.openSync(logFile, 'a');
		} catch (err) {
			// Fall back to stderr if we can't open the log file
			process.stderr.write(`[log] WARNING: cannot open log file ${logFile}: ${err.message}\n`);
		}
	} else if (logFile === undefined) {
		// No explicit option: use the default log file
		try {
			logFd = fs.openSync(DEFAULT_LOG_FILE, 'a');
		} catch (err) {
			// Fall back to stderr silently (e.g. file doesn't exist yet, no permission)
		}
	}
	// logFile === '-' or logFile === null: stay on stderr (logFd remains null)

	function write(line) {
		const ts = new Date().toISOString();
		const out = `${ts} ${tag} ${line}\n`;
		if (logFd !== null) {
			fs.writeSync(logFd, out);
		} else {
			process.stderr.write(out);
		}
	}

	return {
		info(msg) {
			if (level >= LEVEL_INFO) write(`INFO: ${msg}`);
		},
		error(msg) {
			if (level >= LEVEL_ERROR) write(`ERROR: ${msg}`);
		},
		debug(msg) {
			if (level >= LEVEL_DEBUG) write(`DEBUG: ${msg}`);
		}
	};
}

module.exports = { createLogger, DEFAULT_LOG_FILE };
