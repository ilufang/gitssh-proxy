'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
	parseAuthorizedKeys,
	serializeAuthorizedKeys,
	transformForProxy,
	findKey,
	hashKeys,
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

	it('handles escaped backslashes inside values', () => {
		const line = 'command="path\\\\to\\\\thing" ssh-rsa AAAA';
		const { options } = parseOptions(line);
		assert.equal(options[0].value, 'path\\to\\thing');
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

describe('serializeAuthorizedKeys', () => {
	it('round-trips a simple entry', () => {
		const line = 'command="/opt/gogs/gogs serv key-1",no-pty ssh-rsa AAAA user@host';
		const entries = parseAuthorizedKeys(line);
		const serialized = serializeAuthorizedKeys(entries).trim();
		assert.equal(serialized, line);
	});

	it('round-trips the sample file preserving key data', () => {
		const sample = fs.readFileSync(
			path.join(__dirname, '..', 'sample_remote_authorized_keys.txt'), 'utf8'
		);
		const entries = parseAuthorizedKeys(sample);
		const serialized = serializeAuthorizedKeys(entries);
		const reparsed = parseAuthorizedKeys(serialized);

		assert.equal(reparsed.length, entries.length);
		for (let i = 0; i < entries.length; i++) {
			assert.equal(reparsed[i].keyType, entries[i].keyType);
			assert.equal(reparsed[i].keyData, entries[i].keyData);
			assert.equal(reparsed[i].options[0].value, entries[i].options[0].value);
		}
	});
});

describe('transformForProxy', () => {
	it('rewrites command and injects environment vars', () => {
		const entries = parseAuthorizedKeys(
			'command="/opt/gogs/gogs serv key-1",no-pty ssh-rsa AAAA user@host'
		);
		const transformed = transformForProxy(entries, 'gitssh-proxy-client');

		assert.equal(transformed.length, 1);
		const entry = transformed[0];

		// command= should be prefixed
		const cmdOpt = entry.options.find(o => o.name === 'command');
		assert.equal(cmdOpt.value, 'gitssh-proxy-client /opt/gogs/gogs serv key-1');

		// no-pty preserved
		assert.ok(entry.options.some(o => o.name === 'no-pty' && o.value === true));

		// environment vars injected
		const envOpts = entry.options.filter(o => o.name === 'environment');
		assert.equal(envOpts.length, 2);
		assert.equal(envOpts[0].value, 'GITSSH_PROXY_KEY_TYPE=ssh-rsa');
		assert.equal(envOpts[1].value, 'GITSSH_PROXY_KEY_DATA=AAAA');

		// key type and data preserved
		assert.equal(entry.keyType, 'ssh-rsa');
		assert.equal(entry.keyData, 'AAAA');
	});

	it('removes existing proxy env vars on re-transformation', () => {
		const input = 'command="gitssh-proxy-client test",environment="GITSSH_PROXY_KEY_TYPE=old",environment="GITSSH_PROXY_KEY_DATA=old" ssh-rsa NEW';
		const entries = parseAuthorizedKeys(input);
		const transformed = transformForProxy(entries, 'client');

		const envOpts = transformed[0].options.filter(o => o.name === 'environment');
		assert.equal(envOpts.length, 2);
		assert.equal(envOpts[0].value, 'GITSSH_PROXY_KEY_TYPE=ssh-rsa');
		assert.equal(envOpts[1].value, 'GITSSH_PROXY_KEY_DATA=NEW');
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

describe('hashKeys', () => {
	it('returns consistent SHA-256 hex digest', () => {
		const h1 = hashKeys('hello');
		const h2 = hashKeys('hello');
		assert.equal(h1, h2);
		assert.equal(h1.length, 64); // SHA-256 hex is 64 chars
	});

	it('differs for different input', () => {
		assert.notEqual(hashKeys('a'), hashKeys('b'));
	});
});
