'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');

const KEY_TYPE_PREFIXES = ['ssh-', 'ecdsa-', 'sk-'];

/**
 * Key types the proxy accepts into its own authorized_keys.
 */
const ALLOWED_KEY_TYPES = new Set([
	'ssh-ed25519',
	'ssh-rsa',
	'ecdsa-sha2-nistp256',
	'ecdsa-sha2-nistp384',
	'ecdsa-sha2-nistp521',
	'sk-ssh-ed25519@openssh.com',
	'sk-ecdsa-sha2-nistp256@openssh.com'
]);

const KEY_DATA_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const CLIENT_PATH_RE = /^[A-Za-z0-9._/-]+$/;
const ETAG_RE = /^[A-Za-z0-9+/=]{1,128}$/;

/**
 * Parse OpenSSH authorized_keys options from the start of a line.
 * Returns { options: [{name, value}], rest: string }.
 *
 * Options are comma-separated. Each is either a bare keyword or name="value".
 * As in OpenSSH, \" is the only escape inside quoted values.
 */
function parseOptions(line) {
	const options = [];
	let i = 0;

	while (i < line.length) {
		if (line[i] === ' ' || line[i] === '\t') {
			i++;
			break;
		}

		// Read option name (up to '=' or ',' or whitespace)
		let nameStart = i;
		while (i < line.length && line[i] !== '=' && line[i] !== ',' && line[i] !== ' ' && line[i] !== '\t') {
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
					if (line[i] === '\\' && line[i + 1] === '"') {
						value += '"';
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
				while (i < line.length && line[i] !== ',' && line[i] !== ' ' && line[i] !== '\t') {
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
	const parts = rest.trim().split(/[ \t]+/);
	if (parts.length < 2) return null;

	const keyType = parts[0];
	const keyData = parts[1];
	const comment = parts.length > 2 ? parts.slice(2).join(' ') : '';

	return { options, keyType, keyData, comment };
}

/**
 * Parse a complete authorized_keys file into an array of KeyEntry objects.
 * Each entry also records its 1-based `line` number.
 */
function parseAuthorizedKeys(text) {
	const entries = [];
	text.split('\n').forEach((line, i) => {
		const entry = parseLine(line);
		if (entry) entries.push({ ...entry, line: i + 1 });
	});
	return entries;
}

/**
 * All values of an option on an entry. Option names are case-insensitive,
 * as in OpenSSH.
 */
function getOption(entry, name) {
	return entry.options.filter(o => o.name.toLowerCase() === name).map(o => o.value);
}

/**
 * Whether clientPath is safe to place in a command= option (which sshd runs
 * through a shell): path characters only.
 */
function isValidClientPath(clientPath) {
	return typeof clientPath === 'string' && CLIENT_PATH_RE.test(clientPath);
}

/**
 * Whether a key type and data are safe to place in the proxy's
 * authorized_keys: known type, strict base64 data.
 */
function isValidKey(keyType, keyData) {
	return typeof keyType === 'string' && ALLOWED_KEY_TYPES.has(keyType) &&
		typeof keyData === 'string' && KEY_DATA_RE.test(keyData);
}

/**
 * Build the proxy's authorized_keys from the server's key list.
 * Every line comes from a fixed template; keys that fail isValidKey are
 * dropped. Returns { content, dropped }.
 *
 * @param {Array<{t: string, k: string}>} keys
 * @param {string} clientPath
 */
function buildProxyAuthorizedKeys(keys, clientPath) {
	if (!Array.isArray(keys)) throw new TypeError('keys must be an array');
	if (!isValidClientPath(clientPath)) {
		throw new TypeError(`Invalid clientPath: ${clientPath}`);
	}

	const seen = new Set();
	const lines = [];
	let dropped = 0;
	for (const key of keys) {
		const t = key && key.t;
		const k = key && key.k;
		if (!isValidKey(t, k)) {
			dropped++;
			continue;
		}
		const id = `${t} ${k}`;
		if (seen.has(id)) continue;
		seen.add(id);
		lines.push(
			'restrict,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,' +
			`command="${clientPath}",` +
			`environment="GITSSH_PROXY_KEY_TYPE=${t}",` +
			`environment="GITSSH_PROXY_KEY_DATA=${k}" ` +
			id
		);
	}
	return { content: lines.map(l => l + '\n').join(''), dropped };
}

/**
 * Write a file atomically: exclusive-create a random temp file, then rename.
 */
function atomicWrite(file, content) {
	const tmp = `${file}.tmp.${crypto.randomBytes(8).toString('hex')}`;
	const fd = fs.openSync(tmp, 'wx', 0o600);
	try {
		fs.writeSync(fd, content);
	} finally {
		fs.closeSync(fd);
	}
	try {
		fs.renameSync(tmp, file);
	} catch (err) {
		try { fs.unlinkSync(tmp); } catch (e) { /* ignore */ }
		throw err;
	}
}

/**
 * Write the proxy's authorized_keys cache, then its etag (`<cacheFile>.etag`).
 * An invalid etag removes the etag file so the next request fetches in full.
 */
function writeCache(cacheFile, content, etag) {
	const etagFile = cacheFile + '.etag';
	atomicWrite(cacheFile, content);
	if (typeof etag === 'string' && ETAG_RE.test(etag)) {
		atomicWrite(etagFile, etag);
	} else {
		try { fs.unlinkSync(etagFile); } catch (e) { /* ignore */ }
	}
}

/**
 * Read the cache etag, or '' if missing/invalid.
 */
function readEtag(cacheFile) {
	try {
		const etag = fs.readFileSync(cacheFile + '.etag', 'utf8').trim();
		return ETAG_RE.test(etag) ? etag : '';
	} catch (err) {
		return '';
	}
}

/**
 * Find a key entry by type and data.
 */
function findKey(entries, keyType, keyData) {
	return entries.find(e => e.keyType === keyType && e.keyData === keyData) || null;
}

/**
 * Compute SHA-256 base64 digest of text.
 */
function hashKeys(text) {
	return crypto.createHash('sha256').update(text).digest('base64');
}

/**
 * OpenSSH-style SHA256 fingerprint of base64 key data.
 */
function fingerprint(keyData) {
	const digest = crypto.createHash('sha256').update(Buffer.from(String(keyData), 'base64')).digest('base64');
	return 'SHA256:' + digest.replace(/=+$/, '');
}

/**
 * Parse an expiry-time value (YYYYMMDD[HHMM[SS]][Z]) to epoch ms, or null.
 * Local time unless suffixed with Z, as in OpenSSH.
 */
function parseExpiryTime(value) {
	const m = /^(\d{4})(\d{2})(\d{2})(?:(\d{2})(\d{2})(\d{2})?)?(Z?)$/.exec(value);
	if (!m) return null;
	const [, y, mo, d, h = '0', mi = '0', s = '0', z] = m;
	const args = [+y, +mo - 1, +d, +h, +mi, +s];
	const t = z ? Date.UTC(...args) : new Date(...args).getTime();
	return Number.isNaN(t) ? null : t;
}

/**
 * Parse an IPv4 or IPv6 address into a byte array, or null.
 */
function ipToBytes(ip) {
	const v = net.isIP(ip);
	if (v === 4) return ip.split('.').map(Number);
	if (v !== 6) return null;

	let tail = [];
	const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
	if (v4) {
		tail = v4[1].split('.').map(Number);
		ip = ip.slice(0, -v4[1].length) + '0:0';
	}
	const [head, rest] = ip.split('::');
	const toWords = s => (s ? s.split(':').map(w => parseInt(w, 16)) : []);
	let words = toWords(head);
	if (rest !== undefined) {
		const restWords = toWords(rest);
		words = words.concat(new Array(8 - words.length - restWords.length).fill(0), restWords);
	}
	const bytes = [];
	for (const w of words) bytes.push(w >> 8, w & 0xff);
	if (tail.length) bytes.splice(12, 4, ...tail);
	return bytes;
}

/**
 * Normalize an IPv4-mapped IPv6 address to plain IPv4, as sshd does.
 */
function normalizeAddr(addr) {
	const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
	return m ? m[1] : addr;
}

/**
 * Match addr against one CIDR or plain-address pattern.
 * Returns true/false, or null if the pattern is not an address.
 * Throws if the mask length is inconsistent (host bits set), as sshd errors.
 */
function matchCidr(addr, pattern) {
	const [netStr, lenStr, extra] = pattern.split('/');
	if (extra !== undefined) return null;
	const netBytes = ipToBytes(netStr);
	if (!netBytes) return null;
	const max = netBytes.length * 8;
	let len = max;
	if (lenStr !== undefined) {
		if (!/^\d+$/.test(lenStr) || +lenStr > max) return null;
		len = +lenStr;
	}
	for (let bit = len; bit < max; bit++) {
		if (netBytes[bit >> 3] & (0x80 >> (bit & 7))) {
			throw new Error(`inconsistent mask length in "${pattern}"`);
		}
	}
	const addrBytes = ipToBytes(addr);
	if (!addrBytes || addrBytes.length !== netBytes.length) return false;
	for (let bit = 0; bit < len; bit++) {
		const mask = 0x80 >> (bit & 7);
		if ((addrBytes[bit >> 3] & mask) !== (netBytes[bit >> 3] & mask)) return false;
	}
	return true;
}

/**
 * Glob match supporting * and ?, case-insensitive.
 */
function matchGlob(str, pattern) {
	const re = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
	return new RegExp(`^${re}$`, 'i').test(str);
}

/**
 * Evaluate a from= pattern-list against addr, following sshd's
 * match_host_and_ip() with UseDNS off (the host name is the address).
 * Returns true if allowed.
 */
function matchFrom(addr, patternList) {
	let allowed = false;
	for (let pattern of patternList.split(',')) {
		const negated = pattern.startsWith('!');
		if (negated) pattern = pattern.slice(1);
		let matched = matchCidr(addr, pattern);
		if (matched === null) matched = matchGlob(addr, pattern);
		if (matched) {
			if (negated) return false;
			allowed = true;
		}
	}
	return allowed;
}

/**
 * Check the options of a server-side entry that restrict when it may be
 * used: from= (against the client-reported address) and expiry-time=.
 * Returns null if allowed, otherwise a reason string.
 *
 * @param {object} entry - KeyEntry
 * @param {{addr: string, now: number}} ctx - now in epoch ms
 */
function checkKeyOptions(entry, { addr, now }) {
	for (const value of getOption(entry, 'expiry-time')) {
		const expiry = typeof value === 'string' ? parseExpiryTime(value) : null;
		if (expiry === null) return 'invalid expiry-time';
		if (expiry < now) return 'key expired';
	}

	const froms = getOption(entry, 'from');
	if (froms.length > 0) {
		if (typeof addr !== 'string' || !net.isIP(normalizeAddr(addr))) return 'missing client address for from=';
		const ip = normalizeAddr(addr);
		for (const value of froms) {
			if (typeof value !== 'string') return 'invalid from=';
			try {
				if (!matchFrom(ip, value)) return `address ${ip} not allowed by from=`;
			} catch (err) {
				return `invalid from=: ${err.message}`;
			}
		}
	}

	return null;
}

module.exports = {
	ALLOWED_KEY_TYPES,
	parseAuthorizedKeys,
	getOption,
	isValidClientPath,
	isValidKey,
	buildProxyAuthorizedKeys,
	writeCache,
	readEtag,
	findKey,
	hashKeys,
	fingerprint,
	checkKeyOptions,
	// Exported for testing
	parseLine,
	parseOptions
};
