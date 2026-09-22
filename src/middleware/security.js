'use strict';

const helmet = require('helmet');

const config = require('../config');

/**
 * Response headers. The policy is deny-by-default: the page may load scripts,
 * styles and images from its own origin and nothing else, may not be framed,
 * may not set a <base>, and may only submit forms back to itself.
 */
function securityHeaders() {
  const directives = {
    defaultSrc: ["'none'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", 'data:'],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    baseUri: ["'none'"],
    objectSrc: ["'none'"],
    manifestSrc: ["'self'"],
  };
  if (config.session.cookieSecure) {
    directives.upgradeInsecureRequests = [];
  }

  return [
    helmet({
      contentSecurityPolicy: { useDefaults: false, directives },
      crossOriginEmbedderPolicy: false, // nothing cross-origin is embedded
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'same-origin' },
      hsts: config.session.cookieSecure
        ? { maxAge: 63072000, includeSubDomains: true, preload: true }
        : false,
      frameguard: { action: 'deny' },
      noSniff: true,
      xPoweredBy: false,
      xDnsPrefetchControl: { allow: false },
    }),
    function extraHeaders(req, res, next) {
      // Nothing here needs a camera, a microphone or a location.
      res.setHeader(
        'Permissions-Policy',
        'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()'
      );
      // Authenticated pages must never sit in a shared or back-button cache.
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      next();
    },
  ];
}

/**
 * Resolve the client address exactly once, and only trust proxy headers when
 * the operator has said there is a proxy. Otherwise any client can set
 * X-Forwarded-For and walk straight past the per-IP rate limits.
 */
function clientIp(req, res, next) {
  req.clientIp = config.trustProxy
    ? req.ip || ''
    : (req.socket && req.socket.remoteAddress) || '';
  next();
}

/** Reject request bodies and methods the application never uses. */
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST']);

function methodFilter(req, res, next) {
  if (!ALLOWED_METHODS.has(req.method)) {
    res.setHeader('Allow', 'GET, HEAD, POST');
    return res.status(405).type('text/plain').send('Method Not Allowed');
  }
  return next();
}

module.exports = { securityHeaders, clientIp, methodFilter };
