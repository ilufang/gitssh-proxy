'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('stream');
const { wrapTransport } = require('../lib/transport');
const { sendMessage, recvMessage } = require('../lib/protocol');
const { STDOUT, STDERR, CONTROL } = require('../lib/mux');

const PSK = 'test-psk';

/** Writer over a fake socket that records the encrypted bytes. */
function encoder(psk = PSK) {
	const chunks = [];
	const fake = {
		write(buf, cb) { chunks.push(buf); cb(); },
		pipe() {},
		destroy() {}
	};
	const { writer } = wrapTransport(fake, psk);
	return { writer, bytes: () => Buffer.concat(chunks) };
}

/** Reader fed from a PassThrough standing in for the socket. */
function decoder(psk = PSK) {
	const input = new PassThrough();
	const { reader } = wrapTransport(input, psk);
	return { input, reader };
}

function readFrames(reader, n) {
	return new Promise((resolve, reject) => {
		const frames = [];
		reader.on('data', (frame) => {
			frames.push(frame);
			if (frames.length === n) resolve(frames);
		});
		reader.on('error', reject);
	});
}

describe('transport', () => {
	it('round-trips a control message', async () => {
		const enc = encoder();
		const msg = { ts: 1, exec: { t: 'ssh-rsa', k: 'AAAA' }, getkey: { match: 'abc' } };
		await sendMessage(enc.writer, msg);

		const dec = decoder();
		dec.input.write(enc.bytes());
		assert.deepEqual(await recvMessage(dec.reader), msg);
	});

	it('starts with a fresh random salt per stream', async () => {
		const a = encoder();
		const b = encoder();
		await sendMessage(a.writer, { x: 1 });
		await sendMessage(b.writer, { x: 1 });
		assert.notDeepEqual(a.bytes().subarray(0, 16), b.bytes().subarray(0, 16));

		const dec = decoder();
		dec.input.write(a.bytes());
		await recvMessage(dec.reader);
		assert.deepEqual(dec.reader.salt, a.bytes().subarray(0, 16));
	});

	it('decodes byte-by-byte delivery', async () => {
		const enc = encoder();
		await sendMessage(enc.writer, { split: 'yes' });

		const dec = decoder();
		const pending = recvMessage(dec.reader);
		for (const b of enc.bytes()) dec.input.write(Buffer.from([b]));
		assert.deepEqual(await pending, { split: 'yes' });
	});

	it('keeps frames that follow a control message buffered', async () => {
		const enc = encoder();
		await sendMessage(enc.writer, { exec: { ok: true } });
		await enc.writer.send(STDOUT, Buffer.from('out'));
		await enc.writer.send(STDERR, Buffer.from('err'));
		await enc.writer.sendEof(STDOUT);

		const dec = decoder();
		dec.input.write(enc.bytes()); // all in one chunk
		assert.deepEqual(await recvMessage(dec.reader), { exec: { ok: true } });

		const frames = await readFrames(dec.reader, 3);
		assert.equal(frames[0].channel, STDOUT);
		assert.equal(frames[0].payload.toString(), 'out');
		assert.equal(frames[1].channel, STDERR);
		assert.equal(frames[1].payload.toString(), 'err');
		assert.deepEqual(frames[2], { channel: STDOUT, payload: null });
	});

	it('handles payloads larger than 64KB', async () => {
		const big = Buffer.alloc(200 * 1024, 0xab);
		const enc = encoder();
		await enc.writer.send(STDOUT, big);

		const dec = decoder();
		dec.input.write(enc.bytes());
		const [frame] = await readFrames(dec.reader, 1);
		assert.deepEqual(frame.payload, big);
	});

	it('encodes channel 15 EOF (top header bits) correctly', async () => {
		const enc = encoder();
		await enc.writer.sendEof(CONTROL);

		const dec = decoder();
		dec.input.write(enc.bytes());
		const [frame] = await readFrames(dec.reader, 1);
		assert.deepEqual(frame, { channel: CONTROL, payload: null });
	});

	it('rejects empty data frames', async () => {
		const enc = encoder();
		await assert.rejects(() => enc.writer.send(STDOUT, Buffer.alloc(0)), RangeError);
	});

	it('fails on wrong psk', async () => {
		const enc = encoder('wrong');
		await sendMessage(enc.writer, { x: 1 });

		const dec = decoder();
		dec.input.write(enc.bytes());
		await assert.rejects(() => recvMessage(dec.reader), /Decryption failed/);
	});

	it('fails on tampered ciphertext', async () => {
		const enc = encoder();
		await sendMessage(enc.writer, { x: 1 });
		const bytes = enc.bytes();
		bytes[bytes.length - 20] ^= 0x01; // inside the payload chunk

		const dec = decoder();
		dec.input.write(bytes);
		await assert.rejects(() => recvMessage(dec.reader), /Decryption failed/);
	});

	it('recvMessage rejects a non-control frame', async () => {
		const enc = encoder();
		await enc.writer.send(STDOUT, Buffer.from('x'));

		const dec = decoder();
		dec.input.write(enc.bytes());
		await assert.rejects(() => recvMessage(dec.reader), /Expected control message/);
	});

	it('recvMessage rejects on premature end', async () => {
		const dec = decoder();
		dec.input.end();
		await assert.rejects(() => recvMessage(dec.reader), /Connection closed/);
	});
});
