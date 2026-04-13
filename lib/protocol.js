'use strict';

/**
 * Send a JSON message as a newline-terminated string.
 * @param {stream.Writable} writer
 * @param {object} obj
 * @returns {Promise<void>}
 */
function sendMessage(writer, obj) {
	return new Promise((resolve, reject) => {
		const line = JSON.stringify(obj) + '\n';
		writer.write(line, 'utf8', (err) => {
			if (err) reject(err);
			else resolve();
		});
	});
}

/**
 * Read exactly one JSON line from a readable stream.
 *
 * Uses manual data event handling to avoid consuming bytes beyond
 * the newline delimiter. Any leftover bytes after the newline are
 * unshifted back into the reader. This is critical because after
 * the JSON handshake, the stream carries raw binary data (git pack).
 *
 * @param {stream.Readable} reader
 * @returns {Promise<object>}
 */
function recvMessage(reader) {
	return new Promise((resolve, reject) => {
		let chunks = [];
		let totalLen = 0;

		function cleanup() {
			reader.removeListener('data', onData);
			reader.removeListener('error', onError);
			reader.removeListener('end', onEnd);
		}

		function onData(chunk) {
			// Ensure we work with Buffer for binary safety
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			chunks.push(buf);
			totalLen += buf.length;

			// Scan for newline across all accumulated chunks
			const combined = Buffer.concat(chunks, totalLen);
			const nlIndex = combined.indexOf(0x0a); // '\n'

			if (nlIndex !== -1) {
				cleanup();
				reader.pause();

				const lineBytes = combined.slice(0, nlIndex);
				const remainder = combined.slice(nlIndex + 1);

				if (remainder.length > 0) {
					reader.unshift(remainder);
				}

				try {
					const obj = JSON.parse(lineBytes.toString('utf8'));
					resolve(obj);
				} catch (e) {
					reject(new Error('Invalid JSON: ' + e.message));
				}
			}
		}

		function onError(err) {
			cleanup();
			reject(err);
		}

		function onEnd() {
			cleanup();
			if (totalLen > 0) {
				// Try to parse whatever we have
				const combined = Buffer.concat(chunks, totalLen);
				try {
					resolve(JSON.parse(combined.toString('utf8')));
				} catch (e) {
					reject(new Error('Connection closed before complete message'));
				}
			} else {
				reject(new Error('Connection closed before any data'));
			}
		}

		reader.on('data', onData);
		reader.on('error', onError);
		reader.on('end', onEnd);
		reader.resume();
	});
}

module.exports = { sendMessage, recvMessage };
