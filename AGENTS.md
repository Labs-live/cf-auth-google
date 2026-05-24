# cf-auth-google

Fork of Google OAuth for Cloudflare Workers. Sign-in with Google, signed session cookies, email allowlist plus profile mapping. ~400 lines, zero runtime dependencies.

## Install

```sh
npm install github:auraz/cf-auth-google
```

## Types

```ts
export interface Env {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SESSION_KEY: string;
  
  PROFILE_MAP: string;      // '{"kryklia@gmail.com":"oleksandr","vira@gmail.com":"vira"}'
}
```

## Endpoints exposed

- `GET /auth/login?next=/some/path` — start the Google sign-in flow.
- `GET /auth/callback` — exchange the authorization code, set the session cookie, redirect to `next`.
- `GET /auth/logout` — clear the session cookie.

Override paths via `loginPath` / `callbackPath` / `logoutPath`.

## Configuration

| Field | Required | Description |
|---|---|---|
| `clientId` | yes | Google OAuth client ID |
| `clientSecret` | yes | Google OAuth client secret |
| `sessionKey` | yes | HMAC key for signing session cookies. ≥32 random bytes |
| `allowedEmails` | yes | Email addresses permitted to sign in |
| `profileMap` | yes | Email → profile string mapping (used by your handlers) |
| `loginPath` | no | default `/auth/login` |
| `callbackPath` | no | default `/auth/callback` |
| `logoutPath` | no | default `/auth/logout` |
| `cookieName` | no | default `kino_session` |
| `flowCookieName` | no | default `kino_flow` |
| `sessionMaxAgeSeconds` | no | default 7 days |
| `origin` | no | override the redirect_uri origin (useful for proxying) |


## Security notes

- Session cookies are HTTP-only, Secure, SameSite=Lax by default.
- ID tokens are verified against Google's JWK set (signature, issuer, audience, expiry, `email_verified`).
- PKCE (S256) is used for the authorization-code flow — not strictly required for confidential web clients, but doesn't hurt and prepares for future SPA usage.
- The flow cookie carries state + PKCE verifier and is cleared on success.
- `protect()` redirects browsers to `/auth/login`; API/JSON callers get `401 Unauthorized`.
