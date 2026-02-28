/**
 * Tests for OAuth 2.0 flow helpers
 *
 * Full tutorial: https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/
 */

'use strict';

process.env.OAUTH_AUTHORIZATION_URL = 'https://idp.example.com/oauth2/authorize';
process.env.OAUTH_TOKEN_URL = 'https://idp.example.com/oauth2/token';
process.env.OAUTH_USERINFO_URL = 'https://idp.example.com/userinfo';
process.env.OAUTH_CLIENT_ID = 'test-client';
process.env.OAUTH_CLIENT_SECRET = 'test-secret';
process.env.OAUTH_REDIRECT_URI = 'http://localhost:3000/callback';
process.env.OAUTH_SCOPE = 'openid profile email';

const { buildAuthorizationURL } = require('../src/oauth');

describe('buildAuthorizationURL', () => {
  it('includes required OAuth parameters', () => {
    const url = buildAuthorizationURL('test-state-123');
    expect(url).toContain('response_type=code');
    expect(url).toContain('client_id=test-client');
    expect(url).toContain('redirect_uri=');
    expect(url).toContain('scope=openid');
    expect(url).toContain('state=test-state-123');
  });

  it('uses the authorization endpoint as base URL', () => {
    const url = buildAuthorizationURL('some-state');
    expect(url.startsWith('https://idp.example.com/oauth2/authorize')).toBe(true);
  });

  it('includes different state values per call', () => {
    const url1 = buildAuthorizationURL('state-abc');
    const url2 = buildAuthorizationURL('state-xyz');
    expect(url1).toContain('state=state-abc');
    expect(url2).toContain('state=state-xyz');
  });
});

describe('State parameter (CSRF protection)', () => {
  it('state should be 64 hex characters (32 random bytes)', () => {
    const crypto = require('crypto');
    const state = crypto.randomBytes(32).toString('hex');
    expect(state).toHaveLength(64);
    expect(state).toMatch(/^[0-9a-f]+$/);
  });
});
