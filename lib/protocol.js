'use strict';

const { CONTROL } = require('./mux');

/**
 * Send a JSON control message as a single frame on the control channel.
 * @param {{ send }} writer
 * @param {object} obj
 * @returns {Promise<void>}
 */
function sendMessage(writer, obj) {
	return writer.send(CONTROL, Buffer.from(JSON.stringify(obj), 'utf8'));
}

/**
 * Read exactly one frame from the transport reader and parse it as a
 * control message. Subsequent frames stay buffered in the reader.
 * @param {stream.Readable} reader - object-mode reader from wrapTransport()
 * @returns {Promise<object>}
 */
function recvMessage(reader) {
	return new Promise((resolve, reject) => {
		function cleanup() {
			reader.removeListener('readable', onReadable);
			reader.removeListener('error', onError);
			reader.removeListener('end', onEnd);
		}

		function onReadable() {
			const frame = reader.read();
			if (frame === null) return;
			cleanup();
			if (frame.channel !== CONTROL || !frame.payload) {
				reject(new Error(`Expected control message, got channel ${frame.channel}`));
				return;
			}
			try {
				resolve(JSON.parse(frame.payload.toString('utf8')));
			} catch (e) {
				reject(new Error('Invalid JSON: ' + e.message));
			}
		}

		function onError(err) {
			cleanup();
			reject(err);
		}

		function onEnd() {
			cleanup();
			reject(new Error('Connection closed before message'));
		}

		reader.on('readable', onReadable);
		reader.on('error', onError);
		reader.on('end', onEnd);
		onReadable();
	});
}

// Replay protection: requests must carry a fresh timestamp, and each
// request salt is accepted only once within the timestamp window.
const MAX_SKEW = 30*1000; // msec
const seenSalts = new Map(); // salt hex -> expiry (insertion order = expiry order)

/**
 * The `ts` value for a new request: current Unix time in milliseconds.
 * @returns {number}
 */
function generateTsNonce() {
	return Date.now();
}

/**
 * Check a request's `ts` against the clock and its transport salt against
 * the salts already seen. Records the salt on success.
 * @param {*} ts - the request's `ts` field
 * @param {Buffer} salt - the request's transport salt (reader.salt)
 * @returns {string|null} rejection reason, or null if accepted
 */
function validateTsNonce(ts, salt) {
	const now = generateTsNonce();
	if (typeof ts !== 'number' || Math.abs(now - ts) > MAX_SKEW) return 'stale timestamp';
	for (const [key, expiry] of seenSalts) {
		if (expiry >= now) break;
		seenSalts.delete(key);
	}
	const key = salt.toString('hex');
	if (seenSalts.has(key)) return 'replayed salt';
	seenSalts.set(key, now + 2 * MAX_SKEW);
	return null;
}

module.exports = { sendMessage, recvMessage, generateTsNonce, validateTsNonce };
