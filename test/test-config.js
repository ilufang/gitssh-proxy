'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadConfig } = require('../lib/config');

describe('loadConfig', () => {
	let dir;
	before(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitssh-proxy-config-')); });
	after(() => fs.rmSync(dir, { recursive: true, force: true }));

	function load(section, obj) {
		const file = path.join(dir, `${section}.json`);
		fs.writeFileSync(file, JSON.stringify({ psk: 'x', ...obj }));
		return loadConfig(file, section);
	}

	it('accepts a plain clientPath', () => {
		assert.equal(load('client', { clientPath: '/usr/local/bin/gitssh-proxy-client' }).clientPath,
			'/usr/local/bin/gitssh-proxy-client');
		assert.equal(load('client', {}).clientPath, 'gitssh-proxy-client');
	});

	it('rejects a clientPath with shell or option syntax', () => {
		for (const clientPath of ['/bin/client; sh', '/bin/my client', '/bin/"client', '$(id)', '', 42]) {
			assert.throws(() => load('client', { clientPath }), /clientPath/, JSON.stringify(clientPath));
		}
	});

	it('accepts absent, empty or absolute allowedCommands', () => {
		assert.equal(load('server', {}).allowedCommands, undefined);
		assert.deepEqual(load('server', { allowedCommands: [] }).allowedCommands, []);
		assert.deepEqual(load('server', { allowedCommands: ['/opt/gogs/gogs'] }).allowedCommands, ['/opt/gogs/gogs']);
	});

	it('rejects relative or malformed allowedCommands', () => {
		for (const allowedCommands of [['gogs'], ['./gogs'], '/opt/gogs/gogs', [42]]) {
			assert.throws(() => load('server', { allowedCommands }), /allowedCommands/, JSON.stringify(allowedCommands));
		}
	});
});
