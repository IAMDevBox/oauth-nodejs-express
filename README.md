# OAuth 2.0 Authorization Code Flow — Node.js + Express

Production-ready implementation of **OAuth 2.0 Authorization Code Flow** using Node.js and Express.

This companion repo for the tutorial at **[IAMDevBox.com](https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/?utm_source=github&utm_medium=companion-repo&utm_campaign=oauth-nodejs-express)** gives you a complete, runnable example with:

- State parameter CSRF protection
- Redis-backed session storage
- Automatic token refresh (5-minute pre-expiry buffer)
- Rate limiting on auth endpoints
- HTTPS enforcement in production
- Health check endpoint

## 📚 Full Tutorial

**[→ OAuth 2.0 Authorization Flow Using Node.js and Express](https://www.iamdevbox.com/posts/oauth-20-authorization-flow-using-nodejs-and-express/?utm_source=github&utm_medium=companion-repo&utm_campaign=oauth-nodejs-express)**

Covers:
- Why Authorization Code Flow for server-side Node.js
- Step-by-step implementation walkthrough
- Debugging `invalid_grant`, session hijacking, token expiration
- Production security checklist

## Related IAMDevBox Guides

- [OAuth 2.0 Complete Developer Guide](https://www.iamdevbox.com/posts/oauth-20-complete-developer-guide-authorization-authentication/?utm_source=github&utm_medium=companion-repo&utm_campaign=oauth-nodejs-express)
- [Authorization Code Flow with PKCE Tutorial](https://www.iamdevbox.com/posts/understanding-the-authorization-code-flow-with-pkce-in-oauth-20-step-by-step-tutorial-with-code-examples-and-common-pitfalls/?utm_source=github&utm_medium=companion-repo&utm_campaign=oauth-nodejs-express)
- [PKCE Generator Tool](https://www.iamdevbox.com/tools/pkce-generator/?utm_source=github&utm_medium=companion-repo&utm_campaign=oauth-nodejs-express) — Generate PKCE code verifier/challenge online
- [OAuth invalid_grant Error: Causes and Fixes](https://www.iamdevbox.com/posts/oauth-invalid-grant-error-causes-and-fixes-with-keycloak-auth0-and-standard-servers/?utm_source=github&utm_medium=companion-repo&utm_campaign=oauth-nodejs-express)

## Quick Start

### Prerequisites

- Node.js 18+
- Redis (local or Docker)
- OAuth 2.0 Identity Provider (Keycloak, Auth0, Okta, etc.)

### 1. Clone and Install

```bash
git clone https://github.com/IAMDevBox/oauth-nodejs-express.git
cd oauth-nodejs-express
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your IdP settings:

```bash
# Server
NODE_ENV=development
PORT=3000

# Redis
REDIS_URL=redis://localhost:6379

# Session
SESSION_SECRET=change-this-to-a-long-random-string

# OAuth 2.0 Identity Provider
OAUTH_AUTHORIZATION_URL=https://your-idp.example.com/oauth2/authorize
OAUTH_TOKEN_URL=https://your-idp.example.com/oauth2/token
OAUTH_USERINFO_URL=https://your-idp.example.com/userinfo
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:3000/callback
```

### 3. Start Redis

```bash
docker run -d -p 6379:6379 redis:7-alpine
```

### 4. Run the App

```bash
npm start
```

Open [http://localhost:3000](http://localhost:3000) and click **Login**.

## Keycloak Quick Setup

If you don't have an IdP, use Keycloak locally:

```bash
docker run -d \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0 start-dev
```

Then in Keycloak Admin Console:

1. Create realm: `demo`
2. Create client: `oauth-nodejs-demo`
   - Client type: Confidential
   - Valid redirect URIs: `http://localhost:3000/callback`
3. Set in `.env`:
   ```
   OAUTH_AUTHORIZATION_URL=http://localhost:8080/realms/demo/protocol/openid-connect/auth
   OAUTH_TOKEN_URL=http://localhost:8080/realms/demo/protocol/openid-connect/token
   OAUTH_USERINFO_URL=http://localhost:8080/realms/demo/protocol/openid-connect/userinfo
   OAUTH_CLIENT_ID=oauth-nodejs-demo
   OAUTH_CLIENT_SECRET=<your-client-secret>
   ```

## Project Structure

```
oauth-nodejs-express/
├── src/
│   ├── app.js           # Express app setup, session, routes
│   ├── oauth.js         # OAuth configuration and token helpers
│   └── middleware.js    # Token refresh + auth guard middleware
├── .env.example         # Environment variable template
├── docker-compose.yml   # Redis + app stack
├── package.json
└── README.md
```

## Routes

| Route | Description |
|-------|-------------|
| `GET /` | Home page |
| `GET /login` | Initiates OAuth flow (generates state, redirects to IdP) |
| `GET /callback` | OAuth callback — validates state, exchanges code for tokens |
| `GET /profile` | Protected page (requires valid session + auto-refreshes token) |
| `GET /logout` | Destroys session |
| `GET /health` | Health check (checks Redis connectivity) |

## Security Features

| Feature | Implementation |
|---------|---------------|
| CSRF protection | Random state parameter, validated on callback |
| Token storage | Redis-backed server-side sessions only |
| Cookie security | `httpOnly`, `secure` (prod), `sameSite: lax` |
| Token refresh | Auto-refresh 5 minutes before expiry |
| Rate limiting | 5 login attempts per 15 minutes |
| HTTPS redirect | Enforced in production mode |

## GitHub Topics

`oauth2` `nodejs` `express` `authorization-code-flow` `keycloak` `iam` `identity` `authentication` `session-management` `redis`

---

Built with ❤️ by [IAMDevBox.com](https://www.iamdevbox.com/?utm_source=github&utm_medium=companion-repo&utm_campaign=oauth-nodejs-express) — practical IAM engineering guides.
