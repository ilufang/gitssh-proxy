'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
	parseAuthorizedKeys,
	buildProxyAuthorizedKeys,
	writeCache,
	readEtag,
	checkKeyOptions,
	findKey,
	hashKeys,
	fingerprint,
	parseLine,
	parseOptions
} = require('../lib/authkeys');

describe('parseOptions', () => {
	it('parses command with quoted value', () => {
		const line = 'command="/opt/gogs/gogs serv key-1",no-pty ssh-rsa AAAA';
		const { options, rest } = parseOptions(line);
		assert.equal(options.length, 2);
		assert.equal(options[0].name, 'command');
		assert.equal(options[0].value, '/opt/gogs/gogs serv key-1');
		assert.equal(options[1].name, 'no-pty');
		assert.equal(options[1].value, true);
		assert.equal(rest, 'ssh-rsa AAAA');
	});

	it('handles escaped quotes inside values', () => {
		const line = 'command="echo \\"hello\\"" ssh-rsa AAAA';
		const { options } = parseOptions(line);
		assert.equal(options[0].value, 'echo "hello"');
	});

	it('keeps backslashes literally, as OpenSSH does', () => {
		const line = 'command="path\\\\to\\thing" ssh-rsa AAAA';
		const { options } = parseOptions(line);
		assert.equal(options[0].value, 'path\\\\to\\thing');
	});

	it('treats \" before the closing quote as an escape, as OpenSSH does', () => {
		// OpenSSH rejects this line (missing end quote); so do we.
		assert.equal(parseLine('command="echo x\\",no-pty ssh-rsa AAAA'), null);
	});

	it('parses multiple options including environment', () => {
		const line = 'command="test",no-pty,environment="FOO=bar" ssh-rsa AAAA';
		const { options } = parseOptions(line);
		assert.equal(options.length, 3);
		assert.equal(options[2].name, 'environment');
		assert.equal(options[2].value, 'FOO=bar');
	});
});

describe('parseLine', () => {
	it('returns null for empty lines', () => {
		assert.equal(parseLine(''), null);
		assert.equal(parseLine('   '), null);
	});

	it('returns null for comment lines', () => {
		assert.equal(parseLine('# this is a comment'), null);
	});

	it('parses a full authorized_keys line', () => {
		const line = 'command="/opt/gogs/gogs serv key-1 --config=\'/opt/gogs/custom/conf/app.ini\'",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-rsa AAAA user@host';
		const entry = parseLine(line);
		assert.equal(entry.options.length, 5);
		assert.equal(entry.options[0].name, 'command');
		assert.equal(entry.options[0].value, "/opt/gogs/gogs serv key-1 --config='/opt/gogs/custom/conf/app.ini'");
		assert.equal(entry.keyType, 'ssh-rsa');
		assert.equal(entry.keyData, 'AAAA');
		assert.equal(entry.comment, 'user@host');
	});

	it('parses a line with no options', () => {
		const line = 'ssh-ed25519 AAAA user@host';
		const entry = parseLine(line);
		assert.equal(entry.options.length, 0);
		assert.equal(entry.keyType, 'ssh-ed25519');
		assert.equal(entry.keyData, 'AAAA');
		assert.equal(entry.comment, 'user@host');
	});

	it('parses a line with no comment', () => {
		const line = 'ssh-rsa AAAA';
		const entry = parseLine(line);
		assert.equal(entry.keyType, 'ssh-rsa');
		assert.equal(entry.keyData, 'AAAA');
		assert.equal(entry.comment, '');
	});

	it('parses ecdsa keys', () => {
		const line = 'ecdsa-sha2-nistp256 AAAA user@host';
		const entry = parseLine(line);
		assert.equal(entry.keyType, 'ecdsa-sha2-nistp256');
	});

	it('splits fields on tabs and repeated spaces', () => {
		const entry = parseLine('command="a"\tssh-rsa  AAAA \t user@host');
		assert.equal(entry.options[0].value, 'a');
		assert.equal(entry.keyType, 'ssh-rsa');
		assert.equal(entry.keyData, 'AAAA');
		assert.equal(entry.comment, 'user@host');
	});

	it('parses sk- prefixed keys', () => {
		const line = 'sk-ssh-ed25519@openssh.com AAAA user@host';
		const entry = parseLine(line);
		assert.equal(entry.keyType, 'sk-ssh-ed25519@openssh.com');
	});
});

describe('parseAuthorizedKeys', () => {
	it('parses the sample file', () => {
		const sample = fs.readFileSync(
			path.join(__dirname, '..', 'sample_remote_authorized_keys.txt'), 'utf8'
		);
		const entries = parseAuthorizedKeys(sample);
		// The sample file has 23 non-empty lines
		assert.ok(entries.length > 20, `Expected >20 entries, got ${entries.length}`);

		// Check first entry
		assert.equal(entries[0].options[0].name, 'command');
		assert.ok(entries[0].options[0].value.includes('gogs serv key-1'));
		assert.equal(entries[0].keyType, 'ssh-rsa');

		// Check that different key types are parsed
		const types = new Set(entries.map(e => e.keyType));
		assert.ok(types.has('ssh-rsa'));
		assert.ok(types.has('ecdsa-sha2-nistp256'));
		assert.ok(types.has('ssh-ed25519'));
	});
});

const CLIENT = '/usr/local/bin/gitssh-proxy-client';
const LINE_RE = new RegExp(
	'^restrict,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,' +
	'command="/usr/local/bin/gitssh-proxy-client",' +
	'environment="GITSSH_PROXY_KEY_TYPE=([a-z0-9@.-]+)",' +
	'environment="GITSSH_PROXY_KEY_DATA=([A-Za-z0-9+/=]+)" ([a-z0-9@.-]+) ([A-Za-z0-9+/=]+)$'
);

describe('buildProxyAuthorizedKeys', () => {
	it('builds one fixed-template line per key', () => {
		const { content, dropped } = buildProxyAuthorizedKeys([{ t: 'ssh-rsa', k: 'AAAA' }], CLIENT);
		assert.equal(dropped, 0);
		assert.equal(content,
			'restrict,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,' +
			`command="${CLIENT}",` +
			'environment="GITSSH_PROXY_KEY_TYPE=ssh-rsa",environment="GITSSH_PROXY_KEY_DATA=AAAA" ssh-rsa AAAA\n');
	});

	it('handles the sample file keys', () => {
		const sample = fs.readFileSync(
			path.join(__dirname, '..', 'sample_remote_authorized_keys.txt'), 'utf8'
		);
		const keys = parseAuthorizedKeys(sample).map(e => ({ t: e.keyType, k: e.keyData }));
		const { content, dropped } = buildProxyAuthorizedKeys(keys, CLIENT);
		assert.equal(dropped, 0);
		const lines = content.trimEnd().split('\n');
		assert.equal(lines.length, keys.length);
		for (const line of lines) assert.match(line, LINE_RE);
	});

	it('drops hostile or malformed keys', () => {
		const hostile = [
			{ t: 'ssh-rsa",command="sh', k: 'AAAA' },
			{ t: 'ssh-rsa', k: 'AAAA",command="sh' },
			{ t: 'ssh-rsa', k: 'AAAA BBBB' },
			{ t: 'ssh-rsa', k: 'AAAA\ncommand="sh" ssh-rsa BBBB' },
			{ t: 'ssh-rsa', k: 'AA\\AA' },
			{ t: 'ssh-rsa', k: 'AA,AA' },
			{ t: 'ssh-rsa', k: '$(id)' },
			{ t: 'ssh-dss', k: 'AAAA' },
			{ t: 'unknown', k: 'AAAA' },
			{ t: 'ssh-rsa', k: '' },
			{ t: 'ssh-rsa', k: 42 },
			{ t: ['ssh-rsa'], k: 'AAAA' },
			{ k: 'AAAA' },
			null,
			'ssh-rsa AAAA'
		];
		const { content, dropped } = buildProxyAuthorizedKeys(hostile, CLIENT);
		assert.equal(content, '');
		assert.equal(dropped, hostile.length);
	});

	it('collapses duplicate keys', () => {
		const { content } = buildProxyAuthorizedKeys(
			[{ t: 'ssh-ed25519', k: 'BBBB' }, { t: 'ssh-ed25519', k: 'BBBB' }, { t: 'ssh-rsa', k: 'BBBB' }], CLIENT);
		const lines = content.trimEnd().split('\n');
		assert.equal(lines.length, 2);
		for (const line of lines) {
			const m = LINE_RE.exec(line);
			assert.ok(m, line);
			assert.equal(m[1], m[3]);
			assert.equal(m[2], m[4]);
		}
	});

	it('rejects a non-array key list and an unsafe clientPath', () => {
		assert.throws(() => buildProxyAuthorizedKeys('ssh-rsa AAAA', CLIENT), TypeError);
		assert.throws(() => buildProxyAuthorizedKeys({}, CLIENT), TypeError);
		assert.throws(() => buildProxyAuthorizedKeys([], '/bin/client; sh'), TypeError);
		assert.throws(() => buildProxyAuthorizedKeys([], '/bin/my client'), TypeError);
		assert.throws(() => buildProxyAuthorizedKeys([], '/bin/"client'), TypeError);
	});
});

describe('writeCache', () => {
	it('writes cache and etag, and drops an invalid etag', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitssh-proxy-cache-'));
		try {
			const cacheFile = path.join(dir, 'authorized_keys');
			writeCache(cacheFile, 'line\n', 'abc+/=');
			assert.equal(fs.readFileSync(cacheFile, 'utf8'), 'line\n');
			assert.equal(fs.statSync(cacheFile).mode & 0o777, 0o600);
			assert.equal(readEtag(cacheFile), 'abc+/=');

			writeCache(cacheFile, 'line2\n', 'bad etag\n');
			assert.equal(fs.readFileSync(cacheFile, 'utf8'), 'line2\n');
			assert.equal(readEtag(cacheFile), '');
			assert.deepEqual(fs.readdirSync(dir), ['authorized_keys']);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe('checkKeyOptions', () => {
	const NOW = Date.UTC(2026, 5, 15, 12, 0, 0);
	function check(opts, addr) {
		const [entry] = parseAuthorizedKeys(`${opts},command="x" ssh-rsa AAAA`);
		return checkKeyOptions(entry, { addr, now: NOW });
	}

	it('allows entries without restricting options', () => {
		assert.equal(check('no-pty', undefined), null);
	});

	it('enforces expiry-time', () => {
		assert.equal(check('expiry-time="20260616"', '1.2.3.4'), null);
		assert.equal(check('expiry-time="202606151300Z"', '1.2.3.4'), null);
		assert.match(check('expiry-time="202606151100Z"', '1.2.3.4'), /expired/);
		assert.match(check('expiry-time="20000101"', '1.2.3.4'), /expired/);
		assert.match(check('expiry-time="tomorrow"', '1.2.3.4'), /invalid/);
	});

	it('enforces from= with addresses, CIDR and globs', () => {
		assert.equal(check('from="10.1.2.3"', '10.1.2.3'), null);
		assert.equal(check('from="10.0.0.0/8"', '10.1.2.3'), null);
		assert.equal(check('from="192.168.1.*"', '192.168.1.7'), null);
		assert.equal(check('from="2001:db8::/32"', '2001:db8::1'), null);
		assert.equal(check('from="10.0.0.0/8"', '::ffff:10.1.2.3'), null);
		assert.match(check('from="10.0.0.0/8"', '11.1.2.3'), /not allowed/);
		assert.match(check('from="192.168.1.*"', '192.168.2.7'), /not allowed/);
		assert.match(check('from="2001:db8::/32"', '2001:db9::1'), /not allowed/);
		assert.match(check('from="example.com"', '1.2.3.4'), /not allowed/);
	});

	it('denies on a negated from= match', () => {
		assert.equal(check('from="10.0.0.0/8,!10.9.0.0/16"', '10.1.2.3'), null);
		assert.match(check('from="10.0.0.0/8,!10.9.0.0/16"', '10.9.2.3'), /not allowed/);
		assert.match(check('from="!10.9.0.0/16"', '1.2.3.4'), /not allowed/);
	});

	it('denies from= with a missing address or inconsistent mask', () => {
		assert.match(check('from="10.0.0.0/8"', undefined), /missing/);
		assert.match(check('from="10.0.0.0/8"', 'not-an-ip'), /missing/);
		assert.match(check('from="10.0.0.1/8"', '10.0.0.1'), /inconsistent/);
	});

	it('treats option names case-insensitively', () => {
		assert.match(check('FROM="10.0.0.0/8"', '11.1.2.3'), /not allowed/);
	});
});

describe('findKey', () => {
	const entries = parseAuthorizedKeys(
		'command="a" ssh-rsa AAAA user1\n' +
		'command="b" ssh-ed25519 BBBB user2\n'
	);

	it('finds an existing key', () => {
		const found = findKey(entries, 'ssh-ed25519', 'BBBB');
		assert.ok(found);
		assert.equal(found.comment, 'user2');
	});

	it('returns null for missing key', () => {
		assert.equal(findKey(entries, 'ssh-rsa', 'ZZZZ'), null);
	});
});

describe('fingerprint', () => {
	it('matches ssh-keygen -l output', () => {
		assert.equal(
			fingerprint('AAAAC3NzaC1lZDI1NTE5AAAAINl5xoa7N1zlRa2koZyz9m8YO1kVhmkuW/HBm57IDkLC'),
			'SHA256:C5QA2JkvMnmqsh5/6/K1htUARFfgSEYQLWjshwPnA/A');
	});
});

describe('hashKeys', () => {
	it('returns consistent digest', () => {
		const h1 = hashKeys('hello');
		const h2 = hashKeys('hello');
		assert.equal(h1, h2);
	});

	it('differs for different input', () => {
		assert.notEqual(hashKeys('a'), hashKeys('b'));
	});
});
