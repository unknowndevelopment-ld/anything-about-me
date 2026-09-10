# Authenticated Cloudflare Worker proxy

This Worker exposes a deliberately restricted `GET /proxy?url=...` endpoint. Every request must first authenticate, and the target URL must match an explicit allowlist. The allowlist is path-aware: `https://api.example.com/v1` permits `/v1/...`, but not unrelated paths.

After sign-in, the Worker serves a regular-browser UI with tabs, an address bar, back/forward controls, refresh, and sign-out. Each tab loads through the authenticated `/proxy` endpoint in an isolated iframe; upstream redirects are revalidated and routed back through the proxy.

Unauthenticated browser requests show an in-page login modal. Enter the values stored in `PROXY_USERNAME` and `PROXY_PASSWORD`; a successful CSRF-protected submission creates a signed, HttpOnly, Secure, SameSite session cookie valid for exactly 24 hours. After expiry, deletion, or sign-out, the next navigation, tab reload, or proxy request requires the modal again. Invalid credentials receive a plain `403 Access Denied` response.

## Deploy

Install dependencies and authenticate Wrangler:

```sh
npm install
npx wrangler login
```

Set the required Worker secrets. Do not put these values in `wrangler.toml`, source control, or logs:

```sh
npx wrangler secret put PROXY_USERNAME
npx wrangler secret put PROXY_PASSWORD
npx wrangler secret put SESSION_SECRET
```

`SESSION_SECRET` should be a long, random value (for example, `openssl rand -base64 32`). Configure at least one approved upstream as a non-secret Worker variable before deploying:

```sh
npx wrangler deploy --var UPSTREAM_ALLOWLIST:https://api.example.com/v1
```

For multiple entries, use a comma- or newline-separated value:

```sh
npx wrangler deploy --var 'UPSTREAM_ALLOWLIST:https://api.example.com/v1,https://status.example.com'
```

If `UPSTREAM_ALLOWLIST` is empty or malformed, all proxy requests are rejected. The Worker only supports `http` and `https` targets, rejects URL credentials and private/reserved host addresses, and only performs GET requests.

## Local validation

```sh
npm test
npx wrangler dev
```

The login form uses Worker secrets, signed 24-hour session cookies, `Secure`/`HttpOnly`/`SameSite=Strict` cookie attributes, and a CSRF token. The Worker never imitates a Cloudflare error page.

## Authentication troubleshooting

Worker secrets are deployment-environment bindings; they are not read from `.env` files, repository files, or local shell variables during a deployed request. Set all three secrets on the exact Worker name and environment that is receiving traffic, then deploy again:

```sh
npx wrangler secret list
npx wrangler secret put PROXY_USERNAME
npx wrangler secret put PROXY_PASSWORD
npx wrangler secret put SESSION_SECRET
npx wrangler deploy
```

Paste the secret values exactly when prompted: do not include surrounding quotes or a trailing newline. `SESSION_SECRET` must be present as well as the username and password, because it signs and verifies the 24-hour session cookie. The Worker sets `Secure` on CSRF and session cookies whenever the request uses HTTPS; use HTTPS for production. This also allows local HTTP development to complete the login flow without a browser dropping the cookies. Never commit `.env` files or credentials.
