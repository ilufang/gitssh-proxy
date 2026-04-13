'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('stream');
const { sendMessage, recvMessage } = require('../lib/protocol');

describe('sendMessage', () => {
	it('writes JSON followed by newline', async () => {
		const stream = new PassThrough();
		const chunks = [];
		stream.on('data', (chunk) => chunks.push(chunk));

		await sendMessage(stream, { hello: 'world' });
		stream.end();

		const output = Buffer.concat(chunks).toString();
		assert.equal(output, '{"hello":"world"}\n');
	});
});

describe('recvMessage', () => {
	it('reads a single JSON line', async () => {
		const stream = new PassThrough();
		stream.push('{"foo":"bar"}\n');

		const msg = await recvMessage(stream);
		assert.deepEqual(msg, { foo: 'bar' });
	});

	it('handles split delivery across multiple chunks', async () => {
		const stream = new PassThrough();

		// Deliver the message in two parts
		stream.push('{"spl');
		setTimeout(() => stream.push('it":"yes"}\n'), 5);

		const msg = await recvMessage(stream);
		assert.deepEqual(msg, { split: 'yes' });
	});

	it('unshifts remainder bytes after newline', async () => {
		const stream = new PassThrough();

		// JSON line followed immediately by binary data in one chunk
		const jsonLine = '{"exec":{"ok":true}}\n';
		const binaryData = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff]);
		const combined = Buffer.concat([Buffer.from(jsonLine), binaryData]);
		stream.push(combined);

		const msg = await recvMessage(stream);
		assert.deepEqual(msg, { exec: { ok: true } });

		// The binary data should be readable from the stream
		const remainder = await new Promise((resolve) => {
			stream.once('readable', () => {
				resolve(stream.read());
			});
			// Trigger readable if data already available
			const avail = stream.read();
			if (avail) resolve(avail);
		});

		assert.ok(Buffer.isBuffer(remainder));
		assert.deepEqual(remainder, binaryData);
	});

	it('handles message with no trailing data', async () => {
		const stream = new PassThrough();
		stream.push('{"clean":"line"}\n');

		const msg = await recvMessage(stream);
		assert.deepEqual(msg, { clean: 'line' });
	});

	it('rejects on invalid JSON', async () => {
		const stream = new PassThrough();
		stream.push('not json\n');

		await assert.rejects(() => recvMessage(stream), /Invalid JSON/);
	});

	it('rejects on premature end with no data', async () => {
		const stream = new PassThrough();
		stream.end();

		await assert.rejects(() => recvMessage(stream), /Connection closed/);
	});

	it('handles bundled exec+getkey message', async () => {
		const stream = new PassThrough();
		const msg = {
			exec: { t: 'ssh-rsa', k: 'AAAA', cmd: 'test', origcmd: 'git-upload-pack' },
			getkey: { match: 'abc123' }
		};
		stream.push(JSON.stringify(msg) + '\n');

		const received = await recvMessage(stream);
		assert.deepEqual(received, msg);
	});
});
