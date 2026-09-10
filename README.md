# Authenticated Cloudflare Worker proxy

This Worker exposes a deliberately restricted `GET /proxy?url=...` endpoint. Every request must first authenticate, and the target URL must match an explicit allowlist. The allowlist is path-aware: `https://api.example.com/v1` permits `/v1/...`, but not unrelated paths.

After sign-in, the Worker serves a regular-browser UI with tabs, an address bar, back/forward controls, refresh, and sign-out. Each tab loads through the authenticated `/proxy` endpoint in an isolated iframe; upstream redirects are revalidated and routed back through the proxy.

The first request uses HTTP Basic Auth, so Chrome and other browsers show their native username/password dialog. Enter the values stored in `PROXY_USERNAME` and `PROXY_PASSWORD`. A successful challenge response is exchanged for the existing signed, expiring session cookie; the Basic Auth header is not logged or forwarded upstream. If the header is absent, the Worker returns `401` with `WWW-Authenticate`; malformed or incorrect credentials receive the branded `403 Access Denied` page. The legacy CSRF-protected form remains available at `/login`.

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

The login form uses Worker secrets, signed one-hour session cookies, `Secure`/`HttpOnly`/`SameSite=Strict` cookie attributes, and a CSRF token. Invalid or missing credentials receive a normal branded `403 Access Denied` page; the Worker never imitates a Cloudflare error page.
