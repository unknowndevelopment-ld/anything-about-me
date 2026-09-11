# Authenticated Cloudflare Worker Browser Proxy

A full-featured, secure web proxy running on Cloudflare Workers with an integrated modern browser UI, multi-tab support, HTML/CSS asset rewriting, dynamic navigation interception, and robust authentication.

## Features

- **All Sites Allowed**: Allows browsing any public `http:` and `https:` websites by default (`UPSTREAM_ALLOWLIST = "*"`), while maintaining SSRF defenses against private and metadata IP ranges.
- **HTML & Asset Rewriting**: Uses Cloudflare `HTMLRewriter` to seamlessly rewrite links (`<a>`), forms (`<form>`), stylesheets (`<link>`), scripts (`<script>`), images (`<img>` and `srcset`), and iframes (`<iframe>`).
- **CSS Rewriting**: Automatically proxies background images (`url(...)`) and `@import` stylesheets.
- **Client-Side Navigation Hook**: Injects an active interception layer to catch dynamic navigations, form submissions, `fetch`/`XHR`, and `window.open`, keeping navigation inside the proxy without breaking out into the host browser.
- **Full HTTP Method & Redirect Support**: Handles GET, POST, PUT, DELETE, PATCH, OPTIONS, and HEAD requests. HTTP redirects (301, 302, 303, 307, 308) are rewritten and routed through the proxy.
- **Modern Multi-Tab Browser UI**:
  - Full tab bar with New Tab (`+`), Close Tab (`×`), and active tab switching.
  - Smart address bar with instant search integration (DuckDuckGo fallback) and automatic URL normalization.
  - Per-tab history navigation with Back, Forward, and Reload controls.
  - Real-time address bar and tab title synchronization via `postMessage`.
- **Session Authentication & Security**:
  - HMAC-SHA256 signed 24-hour session cookies.
  - CSRF protection on login/logout forms.
  - Frame-busting header stripping (`X-Frame-Options`, restrictive CSP) for smooth embedded viewing.

## Setup & Deployment

### 1. Install dependencies

```sh
npm install
```

### 2. Configure Worker Secrets

Set the three required authentication secrets:

```sh
npx wrangler secret put PROXY_USERNAME
npx wrangler secret put PROXY_PASSWORD
npx wrangler secret put SESSION_SECRET
```

> `SESSION_SECRET` should be a long random string (e.g. `openssl rand -base64 32`).

### 3. Deploy

```sh
npx wrangler deploy
```

If you ever wish to restrict the proxy to specific domains instead of allowing all public sites, you can set `UPSTREAM_ALLOWLIST`:

```sh
npx wrangler deploy --var 'UPSTREAM_ALLOWLIST:https://api.example.com,https://status.example.com'
```

## Local Development & Testing

Run unit and integration tests:

```sh
npm test
```

Start the local development server:

```sh
npx wrangler dev
```
