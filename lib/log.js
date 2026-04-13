'use strict';

function createLogger(prefix) {
	const tag = `[${prefix}]`;
	const debugEnabled = process.env.GITSSH_PROXY_DEBUG === '1';

	return {
		info(msg) {
			process.stderr.write(`${tag} ${msg}\n`);
		},
		error(msg) {
			process.stderr.write(`${tag} ERROR: ${msg}\n`);
		},
		debug(msg) {
			if (debugEnabled) {
				process.stderr.write(`${tag} DEBUG: ${msg}\n`);
			}
		}
	};
}

module.exports = { createLogger };
