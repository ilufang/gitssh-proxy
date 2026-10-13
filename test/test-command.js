'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { tokenizeCommand, resolveCommand, validateOrigCmd, buildChildEnv } = require('../lib/command');
const { parseAuthorizedKeys } = require('../lib/authkeys');

describe('tokenizeCommand', () => {
	it('splits git server commands', () => {
		assert.deepEqual(
			tokenizeCommand("/opt/gogs/gogs serv key-1 --config='/opt/gogs/custom/conf/app.ini'"),
			['/opt/gogs/gogs', 'serv', 'key-1', '--config=/opt/gogs/custom/conf/app.ini']);
		assert.deepEqual(
			tokenizeCommand('/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-3'),
			['/usr/local/bin/gitea', '--config=/etc/gitea/app.ini', 'serv', 'key-3']);
		assert.deepEqual(
			tokenizeCommand('/opt/gitlab/embedded/service/gitlab-shell/bin/gitlab-shell key-1'),
			['/opt/gitlab/embedded/service/gitlab-shell/bin/gitlab-shell', 'key-1']);
	});

	it('handles every command in the sample file', () => {
		const sample = fs.readFileSync(path.join(__dirname, '..', 'sample_remote_authorized_keys.txt'), 'utf8');
		for (const entry of parseAuthorizedKeys(sample)) {
			const argv = tokenizeCommand(entry.options[0].value);
			assert.ok(argv, entry.options[0].value);
			assert.equal(argv[0], '/opt/gogs/gogs');
		}
	});

	it('keeps single-quoted text literal and joins adjacent parts', () => {
		assert.deepEqual(tokenizeCommand("a 'b c' d'e f'g"), ['a', 'b c', 'de fg']);
		assert.deepEqual(tokenizeCommand("echo 'a; $(id) `x` | &'"), ['echo', 'a; $(id) `x` | &']);
		assert.deepEqual(tokenizeCommand("x ''"), ['x', '']);
		assert.deepEqual(tokenizeCommand(' \ta\t b '), ['a', 'b']);
	});

	it('rejects shell syntax outside single quotes', () => {
		for (const cmd of [
			'a; b', 'a && b', 'a || b', 'a | b', 'a & b', 'a > f', 'a < f', 'a $(id)', 'a `id`',
			'a $HOME', 'a "b"', 'a \\b', 'a *', 'a ?', 'a [x]', 'a {x,y}', '~/a', 'a # c', 'a !b',
			"a 'unterminated", "a 'x\ny'", 'a\nb', '(a)', ''
		]) {
			assert.equal(tokenizeCommand(cmd), null, JSON.stringify(cmd));
		}
		assert.equal(tokenizeCommand(undefined), null);
	});
});

describe('resolveCommand', () => {
	it('uses /bin/sh -c without an allowlist', () => {
		for (const allowed of [undefined, null, []]) {
			assert.deepEqual(resolveCommand('echo a; b', allowed), { file: '/bin/sh', args: ['-c', 'echo a; b'] });
		}
	});

	it('runs allowlisted executables without a shell', () => {
		assert.deepEqual(
			resolveCommand("/opt/gogs/gogs serv key-1 --config='/x/app.ini'", ['/opt/gogs/gogs']),
			{ file: '/opt/gogs/gogs', args: ['serv', 'key-1', '--config=/x/app.ini'] });
	});

	it('rejects unlisted executables and shell syntax with an allowlist', () => {
		assert.ok(resolveCommand('/usr/bin/env', ['/opt/gogs/gogs']).error);
		assert.ok(resolveCommand('gogs serv key-1', ['/opt/gogs/gogs']).error);
		assert.ok(resolveCommand('/opt/gogs/gogs serv key-1; id', ['/opt/gogs/gogs']).error);
		assert.ok(resolveCommand('FOO=bar /opt/gogs/gogs', ['/opt/gogs/gogs']).error);
	});

	it('rejects a missing command', () => {
		assert.ok(resolveCommand(true, []).error);
		assert.ok(resolveCommand(undefined, ['/bin/echo']).error);
	});
});

describe('validateOrigCmd', () => {
	it('accepts empty and git-* commands', () => {
		for (const cmd of ['', "git-upload-pack 'user/repo.git'", "git-receive-pack 'a/b.git'",
			"git-upload-archive 'a/b.git'", 'git-lfs-authenticate a/b.git download', 'git-upload-pack repo.git']) {
			assert.equal(validateOrigCmd(cmd), true, cmd);
		}
	});

	it('rejects other commands, line breaks and non-strings', () => {
		for (const cmd of ['sh', 'ls -la', ' git-upload-pack x', 'git upload-pack x', 'git-', 'GIT-upload-pack x',
			"git-upload-pack 'x'\nid", "git-upload-pack 'x'\r", "git-upload-pack 'x\0'", undefined, null, 1, {}]) {
			assert.equal(validateOrigCmd(cmd), false, JSON.stringify(cmd));
		}
	});
});

describe('buildChildEnv', () => {
	it('passes only basic variables and SSH_ORIGINAL_COMMAND', () => {
		const env = buildChildEnv('git-upload-pack x', { PATH: '/bin', HOME: '/home/git', SECRET: 's', NODE_OPTIONS: 'x' });
		assert.deepEqual(env, { PATH: '/bin', HOME: '/home/git', SSH_ORIGINAL_COMMAND: 'git-upload-pack x' });
		assert.deepEqual(buildChildEnv('', { PATH: '/bin' }), { PATH: '/bin' });
	});
});
