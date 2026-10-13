'use strict';

// AEAD (aes-128-gcm) framing over a TCP socket. See DESIGN.md.
//
// Each direction begins with a random 16-byte salt. The per-direction subkey
// is HKDF-SHA256(psk, salt, "gitssh-proxy-subkey"). The nonce is a 12-byte
// little-endian counter incremented after every seal/open.
//
// Frame: [seal(header)][seal(payload)]   (each sealed chunk carries a 16B tag)
//   header = u32 LE (channel << 28) | length
//   length 0 = EOF for that channel; no payload chunk follows.

const crypto = require('crypto');
const { Transform } = require('stream');

const SALT_LEN = 16;
const KEY_LEN = 16;
const TAG_LEN = 16;
const HDR_LEN = 4;
const MAX_LEN = 0x0FFFFFFF;

function createCipher(psk, salt) {
	const key = Buffer.from(crypto.hkdfSync('sha256', psk, salt, 'gitssh-proxy-subkey', KEY_LEN));
	const nonce = Buffer.alloc(12);

	function increment() {
		for (let i = 0; i < nonce.length; i++) {
			nonce[i] = (nonce[i] + 1) & 0xff;
			if (nonce[i] !== 0) break;
		}
	}

	return {
		seal(plain) {
			const c = crypto.createCipheriv('aes-128-gcm', key, nonce);
			const out = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
			increment();
			return out;
		},
		open(sealed) {
			const d = crypto.createDecipheriv('aes-128-gcm', key, nonce);
			d.setAuthTag(sealed.subarray(sealed.length - TAG_LEN));
			const out = Buffer.concat([d.update(sealed.subarray(0, sealed.length - TAG_LEN)), d.final()]);
			increment();
			return out;
		}
	};
}

/**
 * Decrypting reader: bytes in, `{ channel, payload }` objects out.
 * `payload` is null for an EOF frame. Exposes `reader.salt` once read.
 */
function createReader(psk) {
	let buf = Buffer.alloc(0);
	let cipher = null;
	let pending = null; // { channel, length } of a header awaiting its payload

	const reader = new Transform({
		readableObjectMode: true,
		transform(chunk, encoding, callback) {
			buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
			try {
				while (true) {
					if (!cipher) {
						if (buf.length < SALT_LEN) break;
						reader.salt = Buffer.from(buf.subarray(0, SALT_LEN));
						cipher = createCipher(psk, reader.salt);
						buf = buf.subarray(SALT_LEN);
					} else if (!pending) {
						if (buf.length < HDR_LEN + TAG_LEN) break;
						const h = cipher.open(buf.subarray(0, HDR_LEN + TAG_LEN)).readUInt32LE(0);
						buf = buf.subarray(HDR_LEN + TAG_LEN);
						const channel = h >>> 28;
						const length = h & MAX_LEN;
						if (length === 0) this.push({ channel, payload: null });
						else pending = { channel, length };
					} else {
						if (buf.length < pending.length + TAG_LEN) break;
						const payload = cipher.open(buf.subarray(0, pending.length + TAG_LEN));
						buf = buf.subarray(pending.length + TAG_LEN);
						this.push({ channel: pending.channel, payload });
						pending = null;
					}
				}
			} catch (err) {
				return callback(new Error('Decryption failed'));
			}
			callback();
		}
	});
	return reader;
}

/**
 * Encrypting writer. The salt is sent lazily with the first frame, so a
 * server stays silent until it has something to say.
 */
function createWriter(socket, psk) {
	let cipher = null;

	function writeFrame(channel, payload) {
		const parts = [];
		if (!cipher) {
			const salt = crypto.randomBytes(SALT_LEN);
			cipher = createCipher(psk, salt);
			parts.push(salt);
		}
		const header = Buffer.allocUnsafe(HDR_LEN);
		header.writeUInt32LE(((channel << 28) | (payload ? payload.length : 0)) >>> 0);
		parts.push(cipher.seal(header));
		if (payload) parts.push(cipher.seal(payload));
		return new Promise((resolve, reject) => {
			socket.write(Buffer.concat(parts), (err) => {
				if (err) reject(err); else resolve();
			});
		});
	}

	return {
		/** Send a data frame. Payload must be 1..MAX_LEN bytes. */
		send(channel, payload) {
			if (payload.length === 0 || payload.length > MAX_LEN) {
				return Promise.reject(new RangeError(`Invalid frame length ${payload.length}`));
			}
			return writeFrame(channel, payload);
		},
		/** Send an EOF frame for the channel. */
		sendEof(channel) {
			return writeFrame(channel, null);
		}
	};
}

/**
 * Wrap a TCP socket with the encrypted frame transport.
 * A decryption failure destroys the socket.
 *
 * @param {net.Socket} socket
 * @param {string} psk
 * @returns {{ reader: stream.Readable, writer: { send, sendEof }, socket: net.Socket }}
 */
function wrapTransport(socket, psk) {
	const reader = createReader(psk);
	reader.on('error', () => socket.destroy());
	socket.pipe(reader);
	return { reader, writer: createWriter(socket, psk), socket };
}

module.exports = { wrapTransport };
