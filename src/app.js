'use strict';

const path = require('node:path');
const express = require('express');
const cookieParser = require('cookie-parser');

const config = require('./config');
const { getDb } = require('./db');
const { securityHeaders, clientIp, methodFilter } = require('./middleware/security');
const { csrfProtection } = require('./middleware/csrf');
const { loadSession } = require('./middleware/auth');
const { limiter } = require('./middleware/rate-limit');
const { errorPage } = require('./views/error');
const audit = require('./models/audit');

function createApp() {
  // Touch the database once at start-up so migrations run (and fail loudly)
  // before the first request rather than during it.
  getDb();

  const app = express();

  app.disable('x-powered-by');
  app.set('etag', false);
  // Only believe X-Forwarded-* when an operator has said a proxy is in front.
  app.set('trust proxy', config.trustProxy ? 1 : false);

  app.use(methodFilter);
  app.use(clientIp);
  app.use(...securityHeaders());

  app.use(
    '/static',
    express.static(path.join(__dirname, '..', 'public'), {
      index: false,
      dotfiles: 'deny',
      redirect: false,
      maxAge: config.isProduction ? '1h' : 0,
      setHeaders(res) {
        res.setHeader(
          'Cache-Control',
          config.isProduction ? 'public, max-age=3600' : 'no-store'
        );
      },
    })
  );

  // A blunt ceiling in front of everything, so no single address can keep the
  // process busy however cheap the endpoint is.
  app.use(limiter('global', config.rateLimits.global));

  // Forms only, and small ones. No JSON body parser: nothing here consumes it,
  // and an unused parser is just more attack surface.
  app.use(express.urlencoded({ extended: false, limit: '32kb', parameterLimit: 64 }));
  app.use(cookieParser());
  app.use(loadSession);
  app.use(csrfProtection);

  app.use(require('./routes/auth'));
  // Mounted under a prefix so that each router's `use` guards apply only to
  // its own paths.
  app.use('/account', require('./routes/account'));
  app.use('/admin', require('./routes/admin'));
  app.use(require('./routes/app'));

  app.use((req, res) => {
    res.status(404).send(
      errorPage({
        status: 404,
        user: req.user ? { ...req.user, csrfToken: req.session.csrf_token } : null,
        hint: 'That page does not exist.',
      })
    );
  });

  // eslint-disable-next-line no-unused-vars -- Express identifies this by arity
  app.use((err, req, res, _next) => {
    const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 600
      ? err.status
      : err.type === 'entity.too.large'
        ? 413
        : 500;

    if (status >= 500) {
      // Full detail to the log, never to the response.
      // eslint-disable-next-line no-console
      console.error('[error]', req.method, req.originalUrl, err);
      try {
        audit.recordFromRequest(req, {
          event: 'server.error',
          success: false,
          detail: { path: req.originalUrl.split('?')[0], message: err.message },
        });
      } catch {
        /* the audit write must never mask the original failure */
      }
    }

    if (res.headersSent) return res.end();

    const hint =
      status === 403 && err.csrf
        ? 'Your form had expired. Go back, reload the page and try again.'
        : status === 403
          ? 'You do not have access to that.'
          : status === 429
            ? `Too many requests. Try again in ${err.retryAfterSeconds || 60} seconds.`
            : null;

    return res.status(status).send(
      errorPage({
        status,
        user: req.user ? { ...req.user, csrfToken: req.session.csrf_token } : null,
        hint,
      })
    );
  });

  return app;
}

module.exports = { createApp };
