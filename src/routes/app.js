'use strict';

const express = require('express');

const stats = require('../models/stats');
const { requireAuth } = require('../middleware/auth');
const { lookup } = require('../lib/messages');
const views = require('../views/app');

const router = express.Router();

/**
 * Everything below `requireAuth` is private. There is no public page on this
 * site other than the sign-in flow itself — add new content here and it
 * inherits that.
 */
router.get('/', requireAuth, (req, res) => {
  res.send(
    views.dashboardPage({
      user: { ...req.user, csrfToken: req.session.csrf_token },
      stats: req.user.role === 'admin' ? stats.overview() : {},
      flash: lookup(req.query.msg),
    })
  );
});

module.exports = router;
