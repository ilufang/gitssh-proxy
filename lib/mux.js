'use strict';

// Multiplexed stream framing for the raw stdio phase after exec.
//
// Frame format: [1-byte channel][4-byte big-endian uint32 length][payload]
//   Channel 0x01 = stdout
//   Channel 0x02 = stderr

const STDOUT = 0x01;
const STDERR = 0x02;

/**
 * Write a single mux frame to a writable.
 * @param {stream.Writable} writer
 * @param {number} channel - STDOUT or STDERR
 * @param {Buffer} payload
 * @returns {Promise<void>}
 */
function writeFrame(writer, channel, payload) {
	const header = Buffer.allocUnsafe(5);
	header[0] = channel;
	header.writeUInt32BE(payload.length, 1);
	return new Promise((resolve, reject) => {
		writer.write(Buffer.concat([header, payload]), (err) => {
			if (err) reject(err); else resolve();
		});
	});
}

/**
 * Pipe a readable into the mux writer as the given channel.
 * Returns a Promise that resolves when the source ends.
 * @param {stream.Readable} src
 * @param {stream.Writable} writer
 * @param {number} channel
 * @returns {Promise<void>}
 */
function pipeChannel(src, writer, channel) {
	return new Promise((resolve, reject) => {
		src.on('data', (chunk) => {
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			writeFrame(writer, channel, buf).catch(reject);
		});
		src.on('end', resolve);
		src.on('error', reject);
		src.resume();
	});
}

/**
 * Demultiplex a mux stream into separate stdout/stderr writables.
 *
 * Reads frames from `reader` and routes each to the appropriate sink.
 * Resolves when the reader ends.
 *
 * @param {stream.Readable} reader
 * @param {stream.Writable} stdout - destination for channel 0x01
 * @param {stream.Writable} stderr - destination for channel 0x02
 * @returns {Promise<void>}
 */
function demux(reader, stdout, stderr) {
	return new Promise((resolve, reject) => {
		let buf = Buffer.alloc(0);

		function tryConsume() {
			while (true) {
				// Need at least 5-byte header
				if (buf.length < 5) break;
				const channel = buf[0];
				const length = buf.readUInt32BE(1);
				if (buf.length < 5 + length) break;

				const payload = buf.slice(5, 5 + length);
				buf = buf.slice(5 + length);

				if (channel === STDOUT) {
					stdout.write(payload);
				} else if (channel === STDERR) {
					stderr.write(payload);
				}
				// Unknown channels are silently dropped
			}
		}

		reader.on('data', (chunk) => {
			buf = Buffer.concat([buf, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
			tryConsume();
		});
		reader.on('end', resolve);
		reader.on('error', reject);
		reader.resume();
	});
}

module.exports = { STDOUT, STDERR, pipeChannel, demux };
