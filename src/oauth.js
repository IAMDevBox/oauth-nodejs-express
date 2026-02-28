/**
 * OAuth 2.0 Configuration and Token Helpers
 *
 * Full tutorial: https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/
 */

'use strict';

require('dotenv').config();
const querystring = require('querystring');
const axios = require('axios');

const oauth = {
  authorizationURL: process.env.OAUTH_AUTHORIZATION_URL,
  tokenURL: process.env.OAUTH_TOKEN_URL,
  userInfoURL: process.env.OAUTH_USERINFO_URL,
  clientId: process.env.OAUTH_CLIENT_ID,
  clientSecret: process.env.OAUTH_CLIENT_SECRET,
  redirectUri: process.env.OAUTH_REDIRECT_URI,
  scope: process.env.OAUTH_SCOPE || 'openid profile email',
};

/**
 * Build the authorization URL to redirect the user to the Identity Provider.
 * Includes response_type, client_id, redirect_uri, scope, and state (CSRF token).
 *
 * @param {string} state - Cryptographically random state string for CSRF protection
 * @returns {string} Full authorization URL
 */
function buildAuthorizationURL(state) {
  const params = {
    response_type: 'code',
    client_id: oauth.clientId,
    redirect_uri: oauth.redirectUri,
    scope: oauth.scope,
    state,
  };
  return `${oauth.authorizationURL}?${querystring.stringify(params)}`;
}

/**
 * Exchange an authorization code for access + refresh tokens.
 * This is Step 6 of the Authorization Code Flow.
 *
 * @param {string} code - Authorization code received from the IdP callback
 * @returns {Promise<Object>} Token response: { access_token, refresh_token, expires_in, token_type }
 * @throws {Error} If token exchange fails (invalid code, expired, redirect_uri mismatch, etc.)
 */
async function exchangeCodeForTokens(code) {
  const response = await axios.post(
    oauth.tokenURL,
    querystring.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: oauth.redirectUri,
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
    }),
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 5000,
    }
  );
  return response.data;
}

/**
 * Refresh an expired access token using a refresh token.
 * Called automatically by the ensureValidToken middleware (5-minute pre-expiry buffer).
 *
 * @param {string} refreshToken - The refresh_token from the previous token response
 * @returns {Promise<Object>} New token response: { access_token, refresh_token, expires_in }
 * @throws {Error} If refresh fails (refresh token expired, revoked, etc.)
 */
async function refreshAccessToken(refreshToken) {
  const response = await axios.post(
    oauth.tokenURL,
    querystring.stringify({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
    }),
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 5000,
    }
  );
  return response.data;
}

/**
 * Fetch user info from the IdP's userinfo endpoint using the access token.
 *
 * @param {string} accessToken - The current access token
 * @returns {Promise<Object>} User profile (sub, email, name, etc.)
 */
async function fetchUserInfo(accessToken) {
  const response = await axios.get(oauth.userInfoURL, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 5000,
  });
  return response.data;
}

module.exports = {
  oauth,
  buildAuthorizationURL,
  exchangeCodeForTokens,
  refreshAccessToken,
  fetchUserInfo,
};
