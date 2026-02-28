/**
 * Authentication Middleware
 *
 * ensureValidToken: Guards protected routes. Checks session, auto-refreshes
 * expired tokens (5-minute pre-expiry buffer), and redirects unauthenticated
 * requests to /login.
 *
 * Full tutorial: https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/
 */

'use strict';

const { refreshAccessToken } = require('./oauth');
const logger = require('./logger');

/**
 * Express middleware that ensures a valid access token exists in the session.
 *
 * Behavior:
 * 1. No session → redirect to /login
 * 2. Token not expiring soon → pass through
 * 3. Token expiring in < 5 minutes AND refresh_token present → auto-refresh
 * 4. Refresh fails → destroy session and redirect to /login with error
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
async function ensureValidToken(req, res, next) {
  if (!req.session || !req.session.tokens) {
    return res.redirect('/login');
  }

  const { expires_in, refresh_token } = req.session.tokens;
  const tokenIssuedAt = req.session.tokenIssuedAt || 0;
  const tokenAgeMs = Date.now() - tokenIssuedAt;
  const expiresInMs = (expires_in || 3600) * 1000;
  const bufferMs = 5 * 60 * 1000; // 5 minutes

  // Refresh if within 5 minutes of expiry
  const shouldRefresh = tokenAgeMs > (expiresInMs - bufferMs);

  if (shouldRefresh && refresh_token) {
    try {
      logger.info('Token expiring soon — refreshing');
      const newTokens = await refreshAccessToken(refresh_token);
      req.session.tokens = newTokens;
      req.session.tokenIssuedAt = Date.now();
      logger.info('Token refreshed successfully');
    } catch (err) {
      logger.error('Token refresh failed', { error: err.message });
      req.session.destroy(() => {});
      return res.redirect('/login?error=session_expired');
    }
  } else if (shouldRefresh && !refresh_token) {
    // No refresh token — force re-login
    logger.warn('Token expired and no refresh_token — forcing re-login');
    req.session.destroy(() => {});
    return res.redirect('/login?error=session_expired');
  }

  next();
}

module.exports = { ensureValidToken };
