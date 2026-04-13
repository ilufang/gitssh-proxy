'use strict';

const net = require('net');
const { wrapTransport } = require('./transport');

/**
 * Connect to a gitssh-proxy server and return a wrapped transport.
 * @param {string} host
 * @param {number} port
 * @param {object} [transportOptions]
 * @returns {Promise<{reader: stream.Readable, writer: stream.Writable, socket: net.Socket}>}
 */
function connect(host, port, transportOptions) {
	return new Promise((resolve, reject) => {
		const socket = net.createConnection({ host, port }, () => {
			resolve(wrapTransport(socket, transportOptions));
		});
		socket.once('error', reject);
	});
}

module.exports = { connect };
