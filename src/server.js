'use strict';

const config = require('./config');
const { createApp } = require('./app');
const { closeDb } = require('./db');
const housekeeping = require('./housekeeping');

const app = createApp();
housekeeping.start();

const server = app.listen(config.port, config.host, () => {
  // eslint-disable-next-line no-console
  console.log(`U-Mole listening on http://${config.host}:${config.port} (${config.env})`);
  if (!config.session.cookieSecure) {
    // eslint-disable-next-line no-console
    console.log('[security] Running without HTTPS — do not expose this to the internet as is.');
  }
});

// Slow-loris protection: a client cannot hold a connection open indefinitely
// while dribbling out headers.
server.headersTimeout = 20_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 10_000;

function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.log(`\n${signal} received, shutting down.`);
  server.close(() => {
    closeDb();
    process.exit(0);
  });
  // Do not hang forever on a stuck connection.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
