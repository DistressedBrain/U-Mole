#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

// eslint-disable-next-line no-console
console.log(crypto.randomBytes(32).toString('hex'));
