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

module.exports = { sendMessage, recvMessage };
