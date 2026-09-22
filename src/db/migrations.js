'use strict';

/**
 * Migrations are applied in order and tracked with `PRAGMA user_version`, so a
 * restart never re-applies work it has already done and an older binary will
 * refuse to run against a newer database.
 */
const MIGRATIONS = [
  function initialSchema(db) {
    db.exec(`
      CREATE TABLE users (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id           TEXT    NOT NULL UNIQUE,
        email               TEXT    NOT NULL UNIQUE,
        name                TEXT    NOT NULL DEFAULT '',
        password_hash       TEXT,
        role                TEXT    NOT NULL DEFAULT 'user'
                                    CHECK (role IN ('admin', 'user')),
        status              TEXT    NOT NULL DEFAULT 'active'
                                    CHECK (status IN ('active', 'disabled')),
        totp_secret         TEXT,
        totp_enabled        INTEGER NOT NULL DEFAULT 0,
        totp_last_step      INTEGER NOT NULL DEFAULT 0,
        must_change_password INTEGER NOT NULL DEFAULT 0,
        failed_login_count  INTEGER NOT NULL DEFAULT 0,
        locked_until        INTEGER NOT NULL DEFAULT 0,
        password_changed_at INTEGER,
        last_login_at       INTEGER,
        created_at          INTEGER NOT NULL,
        updated_at          INTEGER NOT NULL,
        created_by          INTEGER REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE recovery_codes (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT    NOT NULL,
        used_at   INTEGER
      );
      CREATE INDEX idx_recovery_codes_user ON recovery_codes(user_id);

      CREATE TABLE sessions (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash          TEXT    NOT NULL UNIQUE,
        user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token          TEXT    NOT NULL,
        mfa_pending         INTEGER NOT NULL DEFAULT 0,
        sudo_until          INTEGER NOT NULL DEFAULT 0,
        created_at          INTEGER NOT NULL,
        last_seen_at        INTEGER NOT NULL,
        absolute_expires_at INTEGER NOT NULL,
        revoked_at          INTEGER,
        ip                  TEXT    NOT NULL DEFAULT '',
        user_agent          TEXT    NOT NULL DEFAULT ''
      );
      CREATE INDEX idx_sessions_user ON sessions(user_id);
      CREATE INDEX idx_sessions_expiry ON sessions(absolute_expires_at);

      CREATE TABLE auth_tokens (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT    NOT NULL UNIQUE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        purpose    TEXT    NOT NULL CHECK (purpose IN ('invite', 'reset')),
        expires_at INTEGER NOT NULL,
        used_at    INTEGER,
        created_at INTEGER NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
      );
      CREATE INDEX idx_auth_tokens_user ON auth_tokens(user_id);

      CREATE TABLE audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        at              INTEGER NOT NULL,
        event           TEXT    NOT NULL,
        success         INTEGER NOT NULL DEFAULT 1,
        actor_user_id   INTEGER,
        actor_email     TEXT    NOT NULL DEFAULT '',
        target_user_id  INTEGER,
        target_email    TEXT    NOT NULL DEFAULT '',
        ip              TEXT    NOT NULL DEFAULT '',
        user_agent      TEXT    NOT NULL DEFAULT '',
        detail          TEXT    NOT NULL DEFAULT '{}'
      );
      CREATE INDEX idx_audit_at ON audit_log(at DESC);
      CREATE INDEX idx_audit_event ON audit_log(event);
      CREATE INDEX idx_audit_actor ON audit_log(actor_user_id);

      CREATE TABLE rate_limits (
        key          TEXT    PRIMARY KEY,
        count        INTEGER NOT NULL,
        window_start INTEGER NOT NULL
      );
      CREATE INDEX idx_rate_limits_window ON rate_limits(window_start);
    `);
  },
];

function migrate(db) {
  const current = db.pragma('user_version', { simple: true });

  if (current > MIGRATIONS.length) {
    throw new Error(
      `Database schema version ${current} is newer than this build understands ` +
        `(${MIGRATIONS.length}). Upgrade the application before starting it.`
    );
  }

  for (let version = current; version < MIGRATIONS.length; version += 1) {
    const migration = MIGRATIONS[version];
    const run = db.transaction(() => {
      migration(db);
      db.pragma(`user_version = ${version + 1}`);
    });
    run();
  }
}

module.exports = { migrate, LATEST_VERSION: MIGRATIONS.length };
