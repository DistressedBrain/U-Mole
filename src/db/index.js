'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');

const config = require('../config');
const { migrate } = require('./migrations');

let db = null;

function open() {
  if (db) return db;

  if (config.databasePath !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(config.databasePath)), { recursive: true });
  }

  db = new Database(config.databasePath);

  // Durability and concurrency.
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = FULL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  // Defence in depth: the application never needs to attach other databases
  // or load extensions, so refuse both.
  db.pragma('trusted_schema = OFF');

  if (config.databasePath !== ':memory:') {
    // The database holds password hashes and encrypted TOTP secrets; keep it
    // unreadable by other local users.
    try {
      fs.chmodSync(path.resolve(config.databasePath), 0o600);
    } catch {
      /* best effort: some filesystems do not support chmod */
    }
  }

  migrate(db);
  return db;
}

function getDb() {
  return db || open();
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDb, closeDb };
