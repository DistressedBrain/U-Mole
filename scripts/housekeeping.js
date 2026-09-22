#!/usr/bin/env node
'use strict';

/** One-shot cleanup, for running from cron instead of in-process. */
const { getDb, closeDb } = require('../src/db');
const housekeeping = require('../src/housekeeping');

getDb();
const removed = housekeeping.sweep();
console.log(
  `Removed ${removed.sessions} session(s), ${removed.tokens} token(s), ` +
    `${removed.rateLimits} rate-limit row(s).`
);
closeDb();
