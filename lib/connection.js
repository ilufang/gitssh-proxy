'use strict';

const net = require('net');
const { wrapTransport } = require('./transport');

/**
 * Connect to a gitssh-proxy server and return a wrapped transport.
 * @param {string} host
 * @param {number} port
 * @param {string} psk
 * @returns {Promise<{reader: stream.Readable, writer: {send, sendEof}, socket: net.Socket}>}
 */
function connect(host, port, psk) {
	return new Promise((resolve, reject) => {
		const socket = net.createConnection({ host, port }, () => {
			resolve(wrapTransport(socket, psk));
		});
		socket.once('error', reject);
	});
}

module.exports = { connect };
