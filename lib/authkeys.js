'use strict';

const crypto = require('crypto');

const KEY_TYPE_PREFIXES = ['ssh-', 'ecdsa-', 'sk-'];

/**
 * Parse OpenSSH authorized_keys options from the start of a line.
 * Returns { options: [{name, value}], rest: string }.
 *
 * Options are comma-separated. Each is either a bare keyword or name="value".
 * Quoted values support \" and \\ escapes.
 */
function parseOptions(line) {
	const options = [];
	let i = 0;

	while (i < line.length) {
		if (line[i] === ' ') {
			i++;
			break;
		}

		// Read option name (up to '=' or ',' or ' ')
		let nameStart = i;
		while (i < line.length && line[i] !== '=' && line[i] !== ',' && line[i] !== ' ') {
			i++;
		}
		const name = line.slice(nameStart, i);

		if (i < line.length && line[i] === '=') {
			// name="value" form
			i++; // skip '='
			if (i < line.length && line[i] === '"') {
				i++; // skip opening '"'
				let value = '';
				while (i < line.length && line[i] !== '"') {
					if (line[i] === '\\' && i + 1 < line.length) {
						value += line[i + 1];
						i += 2;
					} else {
						value += line[i];
						i++;
					}
				}
				if (i < line.length) i++; // skip closing '"'
				options.push({ name, value });
			} else {
				// Unquoted value (non-standard but handle gracefully)
				let valStart = i;
				while (i < line.length && line[i] !== ',' && line[i] !== ' ') {
					i++;
				}
				options.push({ name, value: line.slice(valStart, i) });
			}
		} else {
			// Bare keyword
			options.push({ name, value: true });
		}

		if (i < line.length && line[i] === ',') {
			i++; // skip comma separator
		}
	}

	return { options, rest: line.slice(i) };
}

/**
 * Check if a string starts with a known SSH key type prefix.
 */
function startsWithKeyType(line) {
	return KEY_TYPE_PREFIXES.some(prefix => line.startsWith(prefix));
}

/**
 * Parse a single authorized_keys line into a KeyEntry.
 * Returns null for blank/comment lines.
 *
 * KeyEntry: { options: [{name, value}], keyType, keyData, comment }
 */
function parseLine(line) {
	line = line.trim();
	if (!line || line.startsWith('#')) return null;

	let options = [];
	let rest;

	if (startsWithKeyType(line)) {
		// No options, line starts with key type
		rest = line;
	} else {
		const parsed = parseOptions(line);
		options = parsed.options;
		rest = parsed.rest;
	}

	// rest should be: keyType keyData [comment]
	const parts = rest.split(' ');
	if (parts.length < 2) return null;

	const keyType = parts[0];
	const keyData = parts[1];
	const comment = parts.length > 2 ? parts.slice(2).join(' ') : '';

	return { options, keyType, keyData, comment };
}

/**
 * Parse a complete authorized_keys file into an array of KeyEntry objects.
 */
function parseAuthorizedKeys(text) {
	const entries = [];
	for (const line of text.split('\n')) {
		const entry = parseLine(line);
		if (entry) entries.push(entry);
	}
	return entries;
}

/**
 * Serialize a single option to authorized_keys format.
 */
function serializeOption(opt) {
	if (opt.value === true) {
		return opt.name;
	}
	// Escape backslashes and double quotes inside value
	const escaped = opt.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
	return `${opt.name}="${escaped}"`;
}

/**
 * Serialize a KeyEntry back to an authorized_keys line.
 */
function serializeEntry(entry) {
	let line = '';
	if (entry.options.length > 0) {
		line += entry.options.map(serializeOption).join(',');
		line += ' ';
	}
	line += `${entry.keyType} ${entry.keyData}`;
	if (entry.comment) {
		line += ` ${entry.comment}`;
	}
	return line;
}

/**
 * Serialize an array of KeyEntry objects to authorized_keys format.
 */
function serializeAuthorizedKeys(entries) {
	return entries.map(serializeEntry).join('\n') + '\n';
}

/**
 * Transform server-side entries for use on the proxy.
 * - Rewrites command= to invoke gitssh-proxy-client
 * - Injects environment= options for key type and data
 */
function transformForProxy(entries, clientPath) {
	return entries.map(entry => {
		const newOptions = [];

		for (const opt of entry.options) {
			if (opt.name === 'command' && opt.value !== true) {
				// Prefix the command with the client path
				newOptions.push({ name: 'command', value: `${clientPath} ${opt.value}` });
			} else if (opt.name === 'environment' && typeof opt.value === 'string' &&
								 (opt.value.startsWith('GITSSH_PROXY_KEY_TYPE=') ||
									opt.value.startsWith('GITSSH_PROXY_KEY_DATA='))) {
				// Remove existing proxy env vars (in case of re-transformation)
				continue;
			} else {
				newOptions.push(opt);
			}
		}

		// Inject key environment variables
		newOptions.push({ name: 'environment', value: `GITSSH_PROXY_KEY_TYPE=${entry.keyType}` });
		newOptions.push({ name: 'environment', value: `GITSSH_PROXY_KEY_DATA=${entry.keyData}` });

		return {
			options: newOptions,
			keyType: entry.keyType,
			keyData: entry.keyData,
			comment: entry.comment
		};
	});
}

/**
 * Find a key entry by type and data.
 */
function findKey(entries, keyType, keyData) {
	return entries.find(e => e.keyType === keyType && e.keyData === keyData) || null;
}

/**
 * Compute SHA-256 hex digest of text.
 */
function hashKeys(text) {
	return crypto.createHash('sha256').update(text).digest('hex');
}

module.exports = {
	parseAuthorizedKeys,
	serializeAuthorizedKeys,
	transformForProxy,
	findKey,
	hashKeys,
	// Exported for testing
	parseLine,
	parseOptions
};
