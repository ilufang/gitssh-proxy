'use strict';

// Server-side command handling: how a command= value is run, which
// SSH_ORIGINAL_COMMAND values are accepted, and the child's environment.

const path = require('path');

const SAFE_CHAR_RE = /[A-Za-z0-9_@%+=:,./-]/;
const CONTROL_RE = /[\x00-\x1f\x7f]/;
const ORIGCMD_VERB_RE = /^git-[a-z0-9-]+$/;

const PASS_ENV = ['PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'TZ'];

/**
 * Split a command= value into argv using a strict subset of POSIX shell
 * syntax: bare words of safe characters, '…' single-quoted runs, and words
 * concatenated from both, separated by spaces or tabs.
 * Returns null on anything else (other quoting, escapes, expansions,
 * operators, redirections, globs, control characters).
 *
 * @param {string} str
 * @returns {string[] | null}
 */
function tokenizeCommand(str) {
	if (typeof str !== 'string') return null;
	const argv = [];
	let word = null;
	let i = 0;
	while (i < str.length) {
		const c = str[i];
		if (c === ' ' || c === '\t') {
			if (word !== null) argv.push(word);
			word = null;
			i++;
		} else if (c === "'") {
			const end = str.indexOf("'", i + 1);
			if (end < 0) return null;
			const quoted = str.slice(i + 1, end);
			if (CONTROL_RE.test(quoted)) return null;
			word = (word ?? '') + quoted;
			i = end + 1;
		} else if (SAFE_CHAR_RE.test(c)) {
			word = (word ?? '') + c;
			i++;
		} else {
			return null;
		}
	}
	if (word !== null) argv.push(word);
	return argv.length > 0 ? argv : null;
}

/**
 * Decide how to run a command= value.
 * Without an allowlist, it runs through /bin/sh -c, as sshd would.
 * With one, it must tokenize and its executable must be listed; it then
 * runs without a shell.
 *
 * @param {string} command - the command= value
 * @param {string[] | null | undefined} allowedCommands
 * @returns {{file: string, args: string[]} | {error: string}}
 */
function resolveCommand(command, allowedCommands) {
	if (typeof command !== 'string') return { error: 'no command=' };
	if (!Array.isArray(allowedCommands) || allowedCommands.length === 0) {
		const shell = process.platform === 'win32' ? process.env.SHELL || 'sh' : '/bin/sh';
		return { file: shell, args: ['-c', command] };
	}
	const argv = tokenizeCommand(command);
	if (!argv) return { error: 'command= is not a plain argument list' };
	if (!allowedCommands.includes(argv[0])) return { error: `${argv[0]} is not in allowedCommands` };
	return { file: argv[0], args: argv.slice(1) };
}

/**
 * Whether an SSH_ORIGINAL_COMMAND is acceptable: empty, or a single line
 * whose first word is a git-* command.
 */
function validateOrigCmd(origcmd) {
	if (typeof origcmd !== 'string') return false;
	if (origcmd === '') return true;
	if (/[\0\r\n]/.test(origcmd)) return false;
	return ORIGCMD_VERB_RE.test(origcmd.split(/[ \t]/)[0]);
}

/**
 * Minimal environment for the spawned command, like the one sshd provides.
 */
function buildChildEnv(origcmd, baseEnv = process.env) {
	const env = {};
	for (const name of PASS_ENV) {
		if (baseEnv[name] !== undefined) env[name] = baseEnv[name];
	}
	if (origcmd) env.SSH_ORIGINAL_COMMAND = origcmd;
	return env;
}

/**
 * Validate an allowedCommands config value. Returns an error string or null.
 */
function checkAllowedCommands(value) {
	if (value === undefined || value === null) return null;
	if (!Array.isArray(value)) return '"allowedCommands" must be an array';
	for (const p of value) {
		if (typeof p !== 'string' || !path.posix.isAbsolute(p)) {
			return `"allowedCommands" entries must be absolute paths: ${JSON.stringify(p)}`;
		}
	}
	return null;
}

module.exports = { tokenizeCommand, resolveCommand, validateOrigCmd, buildChildEnv, checkAllowedCommands };
