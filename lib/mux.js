'use strict';

// Channel numbers for transport frames (4 bits, 0..15).

const STDIN = 0;
const STDOUT = 1;
const STDERR = 2;
const CONTROL = 15;

/**
 * Pipe a readable into the transport writer as the given channel, followed
 * by an EOF frame. Resolves once the EOF frame has been written.
 * @param {stream.Readable} src
 * @param {{ send, sendEof }} writer
 * @param {number} channel
 * @returns {Promise<void>}
 */
function pipeChannel(src, writer, channel) {
	return new Promise((resolve, reject) => {
		src.on('data', (chunk) => {
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			if (buf.length > 0) writer.send(channel, buf).catch(reject);
		});
		src.on('end', () => writer.sendEof(channel).then(resolve, reject));
		src.on('error', reject);
		src.resume();
	});
}

module.exports = { STDIN, STDOUT, STDERR, CONTROL, pipeChannel };
