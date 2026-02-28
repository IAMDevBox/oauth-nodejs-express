/**
 * OAuth 2.0 Authorization Code Flow — Node.js + Express
 *
 * Production-ready implementation with:
 * - State parameter CSRF protection
 * - Redis-backed session storage
 * - Automatic token refresh
 * - Rate limiting on auth endpoints
 * - HTTPS enforcement in production
 * - Structured logging with Winston
 *
 * Full tutorial: https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/
 * Companion repo: https://github.com/IAMDevBox/oauth-nodejs-express
 */

'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { createClient } = require('ioredis');
const RedisStore = require('connect-redis').default;
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const { buildAuthorizationURL, exchangeCodeForTokens, fetchUserInfo } = require('./oauth');
const { ensureValidToken } = require('./middleware');
const logger = require('./logger');

// ─── Redis ────────────────────────────────────────────────────────────────────
const redisClient = createClient({ lazyConnect: true });
redisClient.on('error', (err) => logger.error('Redis error', { error: err.message }));
redisClient.connect().catch((err) => logger.error('Redis connect failed', { error: err.message }));

// ─── App Setup ────────────────────────────────────────────────────────────────
const app = express();

// Trust proxy headers (needed for secure cookies behind load balancer / Nginx)
app.set('trust proxy', 1);

// ─── HTTPS Redirect (production only) ────────────────────────────────────────
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// ─── Session ──────────────────────────────────────────────────────────────────
app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
      httpOnly: true,                                // Prevent XSS access
      maxAge: 60 * 60 * 1000,                       // 1 hour
      sameSite: 'lax',                              // CSRF protection
    },
    name: 'sid', // Don't expose the default 'connect.sid' name
  })
);

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // Max 10 login attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Please try again in 15 minutes.',
});

// ─── Routes ───────────────────────────────────────────────────────────────────

// Home
app.get('/', (req, res) => {
  const isAuthenticated = !!req.session.tokens;
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>OAuth 2.0 Demo</title></head>
    <body>
      <h1>OAuth 2.0 Authorization Code Flow Demo</h1>
      <p>Tutorial: <a href="https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/">
        IAMDevBox.com — OAuth 2.0 with Node.js and Express
      </a></p>
      ${isAuthenticated
        ? '<p>✅ You are logged in. <a href="/profile">View Profile</a> | <a href="/logout">Logout</a></p>'
        : '<p><a href="/login"><button>Login with OAuth 2.0</button></a></p>'
      }
    </body>
    </html>
  `);
});

// Step 1: Initiate OAuth flow — generate state, redirect to IdP
app.get('/login', authLimiter, (req, res) => {
  // Generate cryptographically secure state (CSRF protection)
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;

  const authorizationURL = buildAuthorizationURL(state);
  logger.info('Redirecting to authorization server');
  res.redirect(authorizationURL);
});

// Step 2: Handle callback from IdP — validate state, exchange code for tokens
app.get('/callback', authLimiter, async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Handle authorization errors from the IdP
  if (error) {
    logger.error('Authorization error from IdP', { error, error_description });
    return res.redirect(`/?error=${encodeURIComponent(error)}`);
  }

  // Validate state parameter — prevents CSRF attacks
  if (!state || state !== req.session.oauthState) {
    logger.warn('Invalid state parameter — possible CSRF attack', {
      received: state,
      expected: req.session.oauthState ? '[set]' : '[not set]',
    });
    return res.status(403).send('Invalid state parameter. Possible CSRF attack.');
  }

  // Prevent double-use (e.g., browser refresh on callback URL)
  if (req.session.tokens) {
    return res.redirect('/profile');
  }

  try {
    // Exchange authorization code for access + refresh tokens
    const tokens = await exchangeCodeForTokens(code);

    req.session.tokens = tokens;
    req.session.tokenIssuedAt = Date.now();
    delete req.session.oauthState; // Clean up state after use

    logger.info('User authenticated successfully');
    res.redirect('/profile');
  } catch (err) {
    const errData = err.response?.data || err.message;
    logger.error('Token exchange failed', { error: errData });
    res.redirect('/?error=authentication_failed');
  }
});

// Protected route — guarded by ensureValidToken middleware
app.get('/profile', ensureValidToken, async (req, res) => {
  try {
    const userInfo = await fetchUserInfo(req.session.tokens.access_token);

    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Profile</title></head>
      <body>
        <h1>Your Profile</h1>
        <pre>${JSON.stringify(userInfo, null, 2)}</pre>
        <p><a href="/logout">Logout</a></p>
        <p><small>
          Token expires in: ${Math.round((req.session.tokens.expires_in || 0) - (Date.now() - req.session.tokenIssuedAt) / 1000)}s
          | <a href="https://www.iamdevbox.com/tools/saml-decoder/">Decode SAML / JWT</a>
        </small></p>
      </body>
      </html>
    `);
  } catch (err) {
    logger.error('Failed to fetch user info', { error: err.message });
    res.status(401).send('Failed to fetch user info. <a href="/logout">Logout and retry</a>');
  }
});

// Logout — destroy session
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) logger.error('Session destroy error', { error: err.message });
    res.redirect('/');
  });
});

// Health check — verify Redis connectivity
app.get('/health', async (req, res) => {
  try {
    await redisClient.ping();
    res.json({ status: 'ok', redis: 'connected', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'error', redis: 'disconnected', error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
  logger.info('Full tutorial: https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/');
});

module.exports = app; // For testing
