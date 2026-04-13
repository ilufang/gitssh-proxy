'use strict';

/**
 * Wrap a TCP socket with a transport pipeline.
 *
 * Currently identity (passthrough). When PSK encryption is needed,
 * cipher/decipher transforms will be inserted here — all application
 * code uses only reader/writer, never the raw socket for data I/O.
 *
 * @param {net.Socket} socket
 * @param {object} [options]
 * @returns {{ reader: stream.Readable, writer: stream.Writable, socket: net.Socket }}
 */
function wrapTransport(socket, options) {
	return { reader: socket, writer: socket, socket };
}

module.exports = { wrapTransport };
