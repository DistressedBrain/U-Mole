#!/usr/bin/env node
'use strict';

/**
 * Take a consistent snapshot of the database.
 *
 * Copying the SQLite file with `cp` while the server is running can capture a
 * torn write, because the WAL may hold committed pages the main file does not.
 * SQLite's own online backup API takes a coherent copy of a live database, so
 * this can run on a schedule without stopping anything.
 *
 * The snapshot contains password hashes and encrypted TOTP secrets. Treat it
 * exactly like the live database: restricted permissions, and stored somewhere
 * other than where SECRET_KEY lives.
 *
 * Usage:
 *   node scripts/backup.js [destination-directory] [--keep N]
 */

const fs = require('node:fs');
const path = require('node:path');

const config = require('../src/config');
const { getDb, closeDb } = require('../src/db');

function parseArgs(argv) {
  const positional = [];
  let keep = 14;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--keep') {
      keep = Number.parseInt(argv[i + 1], 10);
      if (!Number.isFinite(keep) || keep < 1) {
        throw new Error('--keep needs a positive integer');
      }
      i += 1;
    } else {
      positional.push(argv[i]);
    }
  }
  return { directory: positional[0] || '/data/backups', keep };
}

async function main() {
  const { directory, keep } = parseArgs(process.argv.slice(2));

  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const destination = path.join(directory, `umole-${stamp}.sqlite3`);

  const db = getDb();
  await db.backup(destination);
  fs.chmodSync(destination, 0o600);

  const { size } = fs.statSync(destination);
  console.log(`Wrote ${destination} (${(size / 1024).toFixed(0)} KiB) from ${config.databasePath}`);

  // Keep the newest N and drop the rest.
  const existing = fs
    .readdirSync(directory)
    .filter((name) => /^umole-.*\.sqlite3$/.test(name))
    .sort()
    .reverse();

  for (const stale of existing.slice(keep)) {
    fs.unlinkSync(path.join(directory, stale));
    console.log(`Removed old snapshot ${stale}`);
  }

  console.log(`${Math.min(existing.length, keep)} snapshot(s) retained.`);
}

main()
  .then(() => closeDb())
  .catch((error) => {
    console.error(`Backup failed: ${error.message}`);
    closeDb();
    process.exit(1);
  });
