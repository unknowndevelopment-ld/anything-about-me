interface Env {
  PROXY_USERNAME?: string;
  PROXY_PASSWORD?: string;
  SESSION_SECRET?: string;
  UPSTREAM_ALLOWLIST?: string;
}

const SESSION_COOKIE = "proxy_session";
const CSRF_COOKIE = "proxy_csrf";
const SESSION_TTL_SECONDS = 24 * 60 * 60;
const CSRF_TTL_SECONDS = 10 * 60;
const encoder = new TextEncoder();

// Cache for parsed allowlists to avoid re-parsing on every request
const allowlistCache = new Map<string, URL[]>();

// Cache for HMAC keys to avoid re-importing on every signature operation
const keyCache = new Map<string, CryptoKey>();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Diagnostic endpoint to check environment setup
    if (url.pathname === "/.well-known/config" && request.method === "GET") {
      const hasUsername = !!env.PROXY_USERNAME;
      const hasPassword = !!env.PROXY_PASSWORD;
      const hasSecret = !!env.SESSION_SECRET;
      const hasAllowlist = !!env.UPSTREAM_ALLOWLIST;
      return new Response(
        JSON.stringify(
          {
            status: "environment_check",
            configured: {
              PROXY_USERNAME: hasUsername,
              PROXY_PASSWORD: hasPassword,
              SESSION_SECRET: hasSecret,
              UPSTREAM_ALLOWLIST: hasAllowlist,
            },
            message:
              hasUsername && hasPassword && hasSecret
                ? "All required variables are set"
                : "Missing required environment variables",
          },
          null,
          2,
        ),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    }

    if (url.pathname === "/login") {
      return handleLogin(request, env);
    }

    const session = await readSession(request, env.SESSION_SECRET ?? "");
    if (!session) {
      if (url.pathname === "/" && request.method === "GET") {
        return loginPageResponse(request, env);
      }
      return request.headers.get("Accept")?.includes("text/html")
        ? loginPageResponse(request, env)
        : new Response("Authentication required.", {
            status: 401,
            headers: { "Cache-Control": "no-store" },
          });
    }

    if (url.pathname === "/logout") {
      return handleLogout(request);
    }

    if (url.pathname === "/proxy") {
      return handleProxy(request, env);
    }

    if (url.pathname === "/" && request.method === "GET") {
      return homeResponse(request);
    }

    return new Response("Not Found", { status: 404 });
  },
};

async function handleLogin(request: Request, env: Env): Promise<Response> {
  // Check if environment variables are set
  if (!env.PROXY_USERNAME || !env.PROXY_PASSWORD || !env.SESSION_SECRET) {
    return new Response(
      "ERROR: Worker is not configured. Missing PROXY_USERNAME, PROXY_PASSWORD, or SESSION_SECRET secrets. " +
        "Run: npx wrangler secret put PROXY_USERNAME && npx wrangler secret put PROXY_PASSWORD && npx wrangler secret put SESSION_SECRET",
      { status: 503, headers: { "Content-Type": "text/plain" } },
    );
  }

  if (request.method === "GET") {
    return loginPageResponse(request, env);
  }
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const form = await request.formData();
  const cookies = parseCookies(request);
  const csrfCookie = cookies.get(CSRF_COOKIE);
  const csrfForm = form.get("csrf");
  const username = form.get("username");
  const password = form.get("password");

  if (
    !csrfCookie ||
    typeof csrfForm !== "string" ||
    !constantTimeEqual(csrfCookie, csrfForm) ||
    typeof username !== "string" ||
    typeof password !== "string" ||
    !constantTimeEqual(username, env.PROXY_USERNAME) ||
    !constantTimeEqual(password, env.PROXY_PASSWORD)
  ) {
    return accessDeniedResponse();
  }

  const session = await createSession(username, env.SESSION_SECRET);
  if (!session) {
    return accessDeniedResponse();
  }

  return new Response(null, {
    status: 303,
    headers: {
      Location: "/",
      "Set-Cookie": serializeCookie(SESSION_COOKIE, session, SESSION_TTL_SECONDS, true, request),
    },
  });
}

async function handleLogout(request: Request): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const form = await request.formData();
  const cookies = parseCookies(request);
  const csrfCookie = cookies.get(CSRF_COOKIE);
  const csrfForm = form.get("csrf");
  if (!csrfCookie || typeof csrfForm !== "string" || !constantTimeEqual(csrfCookie, csrfForm)) {
    return accessDeniedResponse();
  }

  return new Response(null, {
    status: 303,
    headers: {
      Location: "/login",
      "Set-Cookie": serializeCookie(SESSION_COOKIE, "", 0, true, request),
    },
  });
}

async function handleProxy(request: Request, env: Env): Promise<Response> {
  const target = new URL(request.url).searchParams.get("url");
  if (!target) {
    return new Response("A proxy target URL is required (?url=...).", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });
  }

  const validatedTarget = validateTarget(target, env.UPSTREAM_ALLOWLIST);
  if (!validatedTarget) {
    return accessDeniedResponse();
  }

  try {
    const targetParsed = new URL(validatedTarget);

    // Filter and prepare headers to send upstream
    const forwardHeaders = new Headers();
    for (const [key, value] of request.headers.entries()) {
      const lowerKey = key.toLowerCase();
      // Skip Cloudflare, host-specific, and hop-by-hop headers
      if (
        lowerKey.startsWith("cf-") ||
        lowerKey.startsWith("x-forwarded-") ||
        lowerKey.startsWith("x-real-") ||
        lowerKey === "host" ||
        lowerKey === "cookie" ||
        lowerKey === "connection" ||
        lowerKey === "upgrade" ||
        lowerKey === "sec-fetch-dest" ||
        lowerKey === "sec-fetch-mode" ||
        lowerKey === "sec-fetch-site"
      ) {
        continue;
      }
      forwardHeaders.set(key, value);
    }

    forwardHeaders.set("Host", targetParsed.host);
    forwardHeaders.set("Origin", targetParsed.origin);
    forwardHeaders.set("Referer", validatedTarget);
    if (!forwardHeaders.has("User-Agent")) {
      forwardHeaders.set(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      );
    }

    // Forward request body for methods that support it
    const hasBody = !["GET", "HEAD"].includes(request.method.toUpperCase()) && request.body !== null;

    const upstreamResponse = await fetch(validatedTarget, {
      method: request.method,
      headers: forwardHeaders,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
    });

    const headers = new Headers(upstreamResponse.headers);

    // Remove security headers that prevent framing and script execution
    headers.delete("X-Frame-Options");
    headers.delete("Content-Security-Policy");
    headers.delete("Content-Security-Policy-Report-Only");
    headers.delete("Cross-Origin-Opener-Policy");
    headers.delete("Cross-Origin-Embedder-Policy");
    headers.delete("Cross-Origin-Resource-Policy");
    headers.delete("Strict-Transport-Security");

    // Add CORS headers so AJAX / subresources work seamlessly
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
    headers.set("Access-Control-Allow-Headers", "*");
    headers.set("X-Content-Type-Options", "nosniff");

    // Handle HTTP Redirects (301, 302, 303, 307, 308)
    const location = upstreamResponse.headers.get("Location");
    if (location && upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
      try {
        const redirectedTarget = new URL(location, validatedTarget).toString();
        const safeRedirect = validateTarget(redirectedTarget, env.UPSTREAM_ALLOWLIST);
        if (safeRedirect) {
          headers.set("Location", `/proxy?url=${encodeURIComponent(safeRedirect)}`);
        }
      } catch {
        // Leave location header as-is if unresolvable
      }
    }

    const contentType = (headers.get("Content-Type") || "").toLowerCase();

    // Rewrite HTML responses
    if (contentType.includes("text/html")) {
      headers.delete("Content-Length");
      const baseResponse = new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers,
      });
      return rewriteHtml(baseResponse, validatedTarget);
    }

    // Rewrite CSS responses
    if (contentType.includes("text/css")) {
      headers.delete("Content-Length");
      const cssText = await upstreamResponse.text();
      const rewrittenCss = rewriteCss(cssText, validatedTarget);
      return new Response(rewrittenCss, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers,
      });
    }

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return new Response(`The upstream could not be reached: ${message}`, {
      status: 502,
      headers: { "Content-Type": "text/plain" },
    });
  }
}

function resolveProxiedUrl(relativeOrAbsolute: string, baseUrl: string): string {
  if (!relativeOrAbsolute) return relativeOrAbsolute;
  const trimmed = relativeOrAbsolute.trim();
  if (
    trimmed.startsWith("javascript:") ||
    trimmed.startsWith("mailto:") ||
    trimmed.startsWith("tel:") ||
    trimmed.startsWith("data:") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("/proxy?url=")
  ) {
    return relativeOrAbsolute;
  }
  try {
    const resolved = new URL(trimmed, baseUrl).toString();
    return `/proxy?url=${encodeURIComponent(resolved)}`;
  } catch {
    return relativeOrAbsolute;
  }
}

function rewriteSrcset(srcset: string, baseUrl: string): string {
  return srcset
    .split(",")
    .map((entry) => {
      const parts = entry.trim().split(/\s+/);
      if (parts.length > 0 && parts[0]) {
        parts[0] = resolveProxiedUrl(parts[0], baseUrl);
      }
      return parts.join(" ");
    })
    .join(", ");
}

function rewriteCss(cssText: string, baseUrl: string): string {
  return cssText
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, url) => {
      if (!url || url.startsWith("data:") || url.startsWith("#") || url.startsWith("/proxy?url=")) {
        return match;
      }
      const proxied = resolveProxiedUrl(url, baseUrl);
      return `url("${proxied}")`;
    })
    .replace(/@import\s+(['"])(.*?)\1/gi, (match, quote, url) => {
      if (!url || url.startsWith("data:") || url.startsWith("/proxy?url=")) {
        return match;
      }
      const proxied = resolveProxiedUrl(url, baseUrl);
      return `@import "${proxied}"`;
    });
}

function rewriteHtml(response: Response, targetUrl: string): Response {
  const clientHookScript = `<script id="__proxy_client_hook__">
(function() {
  const currentTarget = ${JSON.stringify(targetUrl)};
  const proxyEndpoint = '/proxy?url=';

  function toProxied(rawUrl) {
    if (!rawUrl) return rawUrl;
    const str = String(rawUrl).trim();
    if (str.startsWith('javascript:') || str.startsWith('mailto:') || str.startsWith('tel:') || str.startsWith('data:') || str.startsWith('#') || str.startsWith('/proxy?url=')) {
      return str;
    }
    try {
      const resolved = new URL(str, currentTarget).href;
      return proxyEndpoint + encodeURIComponent(resolved);
    } catch (e) {
      return str;
    }
  }

  function notifyParent() {
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({
          type: 'proxy_navigated',
          url: currentTarget,
          title: document.title || currentTarget
        }, '*');
      }
    } catch(e) {}
  }

  // Intercept click on links
  document.addEventListener('click', function(e) {
    let el = e.target;
    while (el && el.tagName !== 'A') {
      el = el.parentElement;
    }
    if (!el) return;
    const href = el.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;

    e.preventDefault();
    e.stopPropagation();

    try {
      const resolved = new URL(href, currentTarget).href;
      const targetAttr = el.getAttribute('target');
      if (targetAttr === '_blank' && window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'proxy_open_tab', url: resolved }, '*');
      } else {
        window.location.href = proxyEndpoint + encodeURIComponent(resolved);
      }
    } catch(err) {
      window.location.href = proxyEndpoint + encodeURIComponent(el.href);
    }
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (!form || form.tagName !== 'FORM') return;
    try {
      const action = form.getAttribute('action') || '';
      form.action = proxyEndpoint + encodeURIComponent(new URL(action, currentTarget).href);
    } catch(err) {}
  }, true);

  // Intercept window.open
  const origOpen = window.open;
  window.open = function(url, target, features) {
    if (!url) return null;
    try {
      const resolved = new URL(url, currentTarget).href;
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'proxy_open_tab', url: resolved }, '*');
        return null;
      }
      return origOpen.call(window, proxyEndpoint + encodeURIComponent(resolved), target, features);
    } catch(e) {
      return origOpen.apply(window, arguments);
    }
  };

  // Intercept fetch
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    if (typeof input === 'string') {
      input = toProxied(input);
    } else if (input instanceof Request) {
      input = new Request(toProxied(input.url), input);
    }
    return origFetch.call(this, input, init);
  };

  // Intercept XMLHttpRequest
  const origXhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    return origXhrOpen.call(this, method, toProxied(url), ...rest);
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', notifyParent);
  } else {
    notifyParent();
  }
  window.addEventListener('load', notifyParent);
})();
</script>`;

  const rewriter = new HTMLRewriter()
    .on("head", {
      element(element) {
        element.prepend(clientHookScript, { html: true });
      },
    })
    .on("a", {
      element(element) {
        const href = element.getAttribute("href");
        if (href) {
          element.setAttribute("href", resolveProxiedUrl(href, targetUrl));
        }
        if (element.getAttribute("target") === "_top" || element.getAttribute("target") === "_parent") {
          element.setAttribute("target", "_self");
        }
      },
    })
    .on("form", {
      element(element) {
        const action = element.getAttribute("action");
        element.setAttribute("action", resolveProxiedUrl(action ?? "", targetUrl));
        if (element.getAttribute("target") === "_top" || element.getAttribute("target") === "_parent") {
          element.setAttribute("target", "_self");
        }
      },
    })
    .on("link", {
      element(element) {
        const href = element.getAttribute("href");
        if (href) {
          element.setAttribute("href", resolveProxiedUrl(href, targetUrl));
        }
      },
    })
    .on("script", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) {
          element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        }
      },
    })
    .on("img", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) {
          element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        }
        const srcset = element.getAttribute("srcset");
        if (srcset) {
          element.setAttribute("srcset", rewriteSrcset(srcset, targetUrl));
        }
      },
    })
    .on("source", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) {
          element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        }
        const srcset = element.getAttribute("srcset");
        if (srcset) {
          element.setAttribute("srcset", rewriteSrcset(srcset, targetUrl));
        }
      },
    })
    .on("iframe", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) {
          element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        }
      },
    })
    .on("video", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) {
          element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        }
        const poster = element.getAttribute("poster");
        if (poster) {
          element.setAttribute("poster", resolveProxiedUrl(poster, targetUrl));
        }
      },
    })
    .on("audio", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) {
          element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        }
      },
    });

  return rewriter.transform(response);
}

function parseAllowlist(allowlist: string): URL[] {
  if (allowlistCache.has(allowlist)) {
    return allowlistCache.get(allowlist)!;
  }

  const entries: URL[] = [];
  for (const entry of allowlist.split(/[\n,]/)) {
    const trimmed = entry.trim();
    if (trimmed && trimmed !== "*" && trimmed.toLowerCase() !== "all") {
      try {
        const normalized = /^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`;
        entries.push(new URL(normalized));
      } catch {
        // Invalid allowlist entries ignored
      }
    }
  }

  allowlistCache.set(allowlist, entries);
  return entries;
}

function validateTarget(rawTarget: string, allowlist?: string): string | null {
  if (!rawTarget || typeof rawTarget !== "string") {
    return null;
  }

  let targetStr = rawTarget.trim();
  // If no scheme present (e.g. example.com or google.com/search), prepend https://
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(targetStr)) {
    targetStr = `https://${targetStr}`;
  }

  let target: URL;
  try {
    target = new URL(targetStr);
  } catch {
    return null;
  }

  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.username ||
    target.password ||
    isBlockedHostname(target.hostname)
  ) {
    return null;
  }

  // If allowlist is empty, "*", "all", "https://" or not specified, allow all public websites
  const trimmedAllowlist = (allowlist ?? "").trim();
  if (
    !trimmedAllowlist ||
    trimmedAllowlist === "*" ||
    trimmedAllowlist.toLowerCase() === "all" ||
    trimmedAllowlist === "https://" ||
    trimmedAllowlist === "http://,https://"
  ) {
    return target.toString();
  }

  const entries = parseAllowlist(trimmedAllowlist);
  if (entries.length === 0) {
    return target.toString();
  }

  for (const allowed of entries) {
    if (
      allowed.protocol === target.protocol &&
      allowed.hostname.toLowerCase() === target.hostname.toLowerCase() &&
      (allowed.port === target.port || (!allowed.port && !target.port)) &&
      (target.pathname === allowed.pathname ||
        target.pathname.startsWith(allowed.pathname.endsWith("/") ? allowed.pathname : `${allowed.pathname}/`))
    ) {
      return target.toString();
    }
  }

  return null;
}

function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  // Check reserved hostnames
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "metadata.google.internal" ||
    host === "metadata.google" ||
    host === "instance-data.ec2.internal"
  ) {
    return true;
  }

  // Check IPv6 loopback and link-local
  if (host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:")) {
    return true;
  }

  // Try to parse as IPv4
  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = [
      parseInt(ipv4Match[1], 10),
      parseInt(ipv4Match[2], 10),
      parseInt(ipv4Match[3], 10),
      parseInt(ipv4Match[4], 10),
    ];

    // Validate octet range
    if (octets.some((octet) => octet > 255)) {
      return true;
    }

    // Check reserved IPv4 ranges
    return (
      octets[0] === 0 ||
      octets[0] === 10 ||
      octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168)
    );
  }

  return false;
}

async function createSession(username: string, secret: string): Promise<string | null> {
  if (!secret) {
    return null;
  }
  const payload = base64UrlEncode(JSON.stringify({ username, exp: Date.now() + SESSION_TTL_SECONDS * 1000 }));
  const signature = await sign(payload, secret);
  return `${payload}.${signature}`;
}

async function readSession(request: Request, secret: string): Promise<{ username: string } | null> {
  const cookies = parseCookies(request);
  const value = cookies.get(SESSION_COOKIE);
  if (!value || !secret) {
    return null;
  }
  const separator = value.lastIndexOf(".");
  if (separator < 1) {
    return null;
  }
  const payload = value.slice(0, separator);
  const signature = value.slice(separator + 1);
  const expected = await sign(payload, secret);
  if (!constantTimeEqual(signature, expected)) {
    return null;
  }
  try {
    const decoded = JSON.parse(new TextDecoder().decode(base64UrlDecode(payload))) as {
      username?: unknown;
      exp?: unknown;
    };
    return typeof decoded.username === "string" && typeof decoded.exp === "number" && decoded.exp > Date.now()
      ? { username: decoded.username }
      : null;
  } catch {
    return null;
  }
}

async function getSigningKey(secret: string): Promise<CryptoKey> {
  if (keyCache.has(secret)) {
    return keyCache.get(secret)!;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  keyCache.set(secret, key);
  return key;
}

async function sign(value: string, secret: string): Promise<string> {
  const key = await getSigningKey(secret);
  return base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}

function loginPageResponse(request: Request, env: Env): Response {
  const csrf = crypto.randomUUID();
  return new Response(loginPage(csrf, env), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Set-Cookie": serializeCookie(CSRF_COOKIE, csrf, CSRF_TTL_SECONDS, false, request),
    },
  });
}

function homeResponse(request: Request): Response {
  const cookies = parseCookies(request);
  const csrf = cookies.get(CSRF_COOKIE) ?? crypto.randomUUID();
  return new Response(homePage(csrf), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      ...(cookies.has(CSRF_COOKIE)
        ? {}
        : { "Set-Cookie": serializeCookie(CSRF_COOKIE, csrf, CSRF_TTL_SECONDS, false, request) }),
    },
  });
}

function accessDeniedResponse(): Response {
  return new Response("403 Access Denied", {
    status: 403,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function loginPage(csrf: string, env: Env): string {
  const envStatus =
    !env.PROXY_USERNAME || !env.PROXY_PASSWORD || !env.SESSION_SECRET
      ? `<div style="background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;padding:12px;margin-bottom:16px;border-radius:6px;font-size:14px;"><strong>⚠️ Setup Required:</strong> Missing environment secrets. Set them with:<br><code>npx wrangler secret put PROXY_USERNAME</code><br><code>npx wrangler secret put PROXY_PASSWORD</code><br><code>npx wrangler secret put SESSION_SECRET</code></div>`
      : "";

  return page(
    "Sign in - Browser Proxy",
    `${envStatus}<div class="login-modal" role="dialog" aria-modal="true" aria-labelledby="login-title">
    <div class="brand-icon">🌐</div>
    <h2 id="login-title">Sign in to Browser Proxy</h2>
    <p>Access the full unrestricted web proxy. Your secure session remains active for 24 hours.</p>
    <form method="post" action="/login">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <label>Username <input name="username" autocomplete="username" placeholder="Username" required autofocus></label>
      <label>Password <input type="password" name="password" autocomplete="current-password" placeholder="Password" required></label>
      <button type="submit" class="btn-primary">Sign in</button>
    </form>
  </div>`,
  );
}

function homePage(csrf: string): string {
  return page(
    "Browser Proxy",
    `<div class="browser">
    <div class="tabs-bar">
      <div class="tabs" id="tab-list" role="tablist"></div>
      <button id="new-tab-btn" class="new-tab-btn" type="button" title="New Tab" aria-label="New Tab">+</button>
    </div>
    <div class="toolbar">
      <div class="nav-buttons">
        <button class="icon-button" id="back" type="button" title="Back" aria-label="Back">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <button class="icon-button" id="forward" type="button" title="Forward" aria-label="Forward">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </button>
        <button class="icon-button" id="refresh" type="button" title="Reload" aria-label="Reload">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        </button>
        <button class="icon-button" id="home" type="button" title="Home" aria-label="Home">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
        </button>
      </div>
      <form id="address-form" class="address-form">
        <div class="address-input-wrapper">
          <span class="url-lock">🔒</span>
          <input id="address" type="text" placeholder="Search with DuckDuckGo or enter URL (e.g. wikipedia.org)" autocomplete="off" spellcheck="false" required>
          <div id="loader" class="loader hidden"></div>
        </div>
        <button type="submit" class="btn-go">Go</button>
      </form>
      <div class="toolbar-actions">
        <form method="post" action="/logout" style="margin:0;">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <button type="submit" class="signout-btn" title="Sign out">Sign out</button>
        </form>
      </div>
    </div>
    <div class="quick-bookmarks">
      <span class="quick-title">Suggestions:</span>
      <button type="button" class="quick-link" data-url="https://en.wikipedia.org">Wikipedia</button>
      <button type="button" class="quick-link" data-url="https://duckduckgo.com/html/">DuckDuckGo</button>
      <button type="button" class="quick-link" data-url="https://news.ycombinator.com">Hacker News</button>
      <button type="button" class="quick-link" data-url="https://github.com">GitHub</button>
      <button type="button" class="quick-link" data-url="https://example.com">Example.com</button>
    </div>
    <div class="viewport-container">
      <iframe id="viewport" title="Proxy viewport" sandbox="allow-forms allow-scripts allow-same-origin allow-popups allow-modals allow-presentation allow-downloads allow-pointer-lock" referrerpolicy="no-referrer"></iframe>
    </div>
  </div>
  <script>
  (() => {
    const tabs = [];
    let activeIndex = -1;
    const tabList = document.getElementById('tab-list');
    const viewport = document.getElementById('viewport');
    const address = document.getElementById('address');
    const form = document.getElementById('address-form');
    const backBtn = document.getElementById('back');
    const forwardBtn = document.getElementById('forward');
    const refreshBtn = document.getElementById('refresh');
    const homeBtn = document.getElementById('home');
    const newTabBtn = document.getElementById('new-tab-btn');
    const loader = document.getElementById('loader');

    function formatInputToUrl(input) {
      const trimmed = input.trim();
      if (!trimmed) return 'https://duckduckgo.com/html/';
      if (/^https?:\\/\\//i.test(trimmed)) return trimmed;
      // Check if it looks like a domain name (contains a dot and no spaces)
      if (!/\\s/.test(trimmed) && trimmed.includes('.')) {
        return 'https://' + trimmed;
      }
      // Otherwise treat as search query
      return 'https://duckduckgo.com/html/?q=' + encodeURIComponent(trimmed);
    }

    function renderTabs() {
      tabList.innerHTML = '';
      tabs.forEach((tab, index) => {
        const tabEl = document.createElement('div');
        tabEl.className = 'tab' + (index === activeIndex ? ' active' : '');
        tabEl.setAttribute('role', 'tab');
        
        const titleSpan = document.createElement('span');
        titleSpan.className = 'tab-title';
        titleSpan.textContent = tab.title || 'New Tab';
        titleSpan.onclick = () => selectTab(index);
        
        const closeBtn = document.createElement('button');
        closeBtn.className = 'tab-close';
        closeBtn.type = 'button';
        closeBtn.innerHTML = '&times;';
        closeBtn.title = 'Close tab';
        closeBtn.onclick = (e) => {
          e.stopPropagation();
          closeTab(index);
        };

        tabEl.appendChild(titleSpan);
        if (tabs.length > 1) {
          tabEl.appendChild(closeBtn);
        }
        tabList.appendChild(tabEl);
      });
    }

    function selectTab(index) {
      if (index < 0 || index >= tabs.length) return;
      activeIndex = index;
      const tab = tabs[activeIndex];
      address.value = tab.url || '';
      
      if (tab.url) {
        showLoader();
        viewport.src = '/proxy?url=' + encodeURIComponent(tab.url);
      } else {
        hideLoader();
        viewport.src = 'about:blank';
      }
      renderTabs();
      updateButtons();
    }

    function addTab(initialUrl = '') {
      const tab = {
        title: initialUrl ? extractHost(initialUrl) : 'New Tab',
        url: initialUrl,
        history: initialUrl ? [initialUrl] : [],
        cursor: initialUrl ? 0 : -1
      };
      tabs.push(tab);
      selectTab(tabs.length - 1);
      if (!initialUrl) {
        address.focus();
        address.select();
      }
    }

    function closeTab(index) {
      if (tabs.length <= 1) return;
      tabs.splice(index, 1);
      if (activeIndex >= tabs.length) {
        activeIndex = tabs.length - 1;
      }
      selectTab(activeIndex);
    }

    function extractHost(urlStr) {
      try {
        const u = new URL(urlStr);
        return u.hostname || urlStr;
      } catch {
        return urlStr || 'New Tab';
      }
    }

    function navigate(rawInput, replace = false) {
      const url = formatInputToUrl(rawInput);
      const tab = tabs[activeIndex];
      if (!tab) return;

      tab.url = url;
      tab.title = extractHost(url);
      if (!replace) {
        tab.history = tab.history.slice(0, tab.cursor + 1);
        tab.history.push(url);
        tab.cursor = tab.history.length - 1;
      }

      address.value = url;
      showLoader();
      viewport.src = '/proxy?url=' + encodeURIComponent(url);
      renderTabs();
      updateButtons();
    }

    function updateButtons() {
      const tab = tabs[activeIndex];
      backBtn.disabled = !tab || tab.cursor <= 0;
      forwardBtn.disabled = !tab || tab.cursor >= tab.history.length - 1;
    }

    function showLoader() {
      loader.classList.remove('hidden');
    }

    function hideLoader() {
      loader.classList.add('hidden');
    }

    viewport.addEventListener('load', () => {
      hideLoader();
    });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      navigate(address.value, false);
    });

    backBtn.addEventListener('click', () => {
      const tab = tabs[activeIndex];
      if (!tab || tab.cursor <= 0) return;
      tab.cursor -= 1;
      tab.url = tab.history[tab.cursor];
      tab.title = extractHost(tab.url);
      address.value = tab.url;
      showLoader();
      viewport.src = '/proxy?url=' + encodeURIComponent(tab.url);
      renderTabs();
      updateButtons();
    });

    forwardBtn.addEventListener('click', () => {
      const tab = tabs[activeIndex];
      if (!tab || tab.cursor >= tab.history.length - 1) return;
      tab.cursor += 1;
      tab.url = tab.history[tab.cursor];
      tab.title = extractHost(tab.url);
      address.value = tab.url;
      showLoader();
      viewport.src = '/proxy?url=' + encodeURIComponent(tab.url);
      renderTabs();
      updateButtons();
    });

    refreshBtn.addEventListener('click', () => {
      const tab = tabs[activeIndex];
      if (tab && tab.url) {
        showLoader();
        viewport.src = '/proxy?url=' + encodeURIComponent(tab.url);
      }
    });

    homeBtn.addEventListener('click', () => {
      navigate('https://duckduckgo.com/html/', false);
    });

    newTabBtn.addEventListener('click', () => addTab());

    document.querySelectorAll('.quick-link').forEach((btn) => {
      btn.addEventListener('click', () => {
        const u = btn.getAttribute('data-url');
        if (u) navigate(u, false);
      });
    });

    // Listen to messages sent from the proxied page inside iframe
    window.addEventListener('message', (event) => {
      if (!event.data) return;
      if (event.data.type === 'proxy_navigated') {
        const tab = tabs[activeIndex];
        if (tab && event.data.url) {
          tab.url = event.data.url;
          if (event.data.title) {
            tab.title = event.data.title;
          }
          if (tab.history[tab.cursor] !== event.data.url) {
            tab.history = tab.history.slice(0, tab.cursor + 1);
            tab.history.push(event.data.url);
            tab.cursor = tab.history.length - 1;
          }
          address.value = tab.url;
          renderTabs();
          updateButtons();
          hideLoader();
        }
      } else if (event.data.type === 'proxy_open_tab' && event.data.url) {
        addTab(event.data.url);
      }
    });

    // Initialize with default search tab
    addTab('https://duckduckgo.com/html/');
  })();
  </script>`,
  );
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg-main: #0f172a;
      --bg-surface: #1e293b;
      --bg-input: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --border: #334155;
      --tab-active: #1e293b;
      --tab-inactive: #0f172a;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 0;
      background: var(--bg-main);
      color: var(--text-main);
      height: 100vh;
      overflow: hidden;
    }
    .login-modal {
      background: var(--bg-surface);
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      border: 1px solid var(--border);
      padding: 36px;
      max-width: 400px;
      margin: 80px auto;
      text-align: center;
    }
    .brand-icon { font-size: 40px; margin-bottom: 12px; }
    .login-modal h2 { margin: 0 0 8px; font-size: 22px; color: #fff; }
    .login-modal p { font-size: 14px; color: var(--text-muted); margin-bottom: 24px; line-height: 1.5; }
    .login-modal label { display: block; text-align: left; font-size: 13px; font-weight: 500; margin-bottom: 16px; color: var(--text-muted); }
    .login-modal input { width: 100%; padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px; color: #fff; font-size: 15px; margin-top: 6px; }
    .login-modal input:focus { outline: none; border-color: var(--primary); }
    .btn-primary { width: 100%; padding: 12px; background: var(--primary); color: #fff; border: none; border-radius: 6px; font-weight: 600; font-size: 15px; cursor: pointer; transition: background 0.2s; margin-top: 8px; }
    .btn-primary:hover { background: var(--primary-hover); }

    .browser {
      display: flex;
      flex-direction: column;
      height: 100vh;
      background: var(--bg-surface);
    }
    .tabs-bar {
      display: flex;
      align-items: center;
      background: var(--bg-main);
      padding: 6px 8px 0;
      gap: 4px;
      border-bottom: 1px solid var(--border);
      user-select: none;
    }
    .tabs {
      display: flex;
      gap: 4px;
      overflow-x: auto;
      flex: 1;
      scrollbar-width: none;
    }
    .tabs::-webkit-scrollbar { display: none; }
    .tab {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 14px;
      background: var(--tab-inactive);
      color: var(--text-muted);
      border-radius: 8px 8px 0 0;
      font-size: 13px;
      max-width: 200px;
      cursor: pointer;
      border: 1px solid transparent;
      border-bottom: none;
      transition: all 0.15s;
    }
    .tab:hover { background: #1e293b88; color: #fff; }
    .tab.active {
      background: var(--tab-active);
      color: #fff;
      font-weight: 500;
      border-color: var(--border);
    }
    .tab-title {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      flex: 1;
    }
    .tab-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 16px;
      line-height: 1;
      padding: 2px 4px;
      border-radius: 4px;
    }
    .tab-close:hover { background: #475569; color: #fff; }
    .new-tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 18px;
      cursor: pointer;
      padding: 4px 10px;
      border-radius: 6px;
      margin-bottom: 2px;
    }
    .new-tab-btn:hover { background: var(--bg-input); color: #fff; }

    .toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border);
    }
    .nav-buttons { display: flex; gap: 4px; align-items: center; }
    .icon-button {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 6px 8px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon-button:hover:not(:disabled) { background: var(--bg-input); color: #fff; }
    .icon-button:disabled { opacity: 0.3; cursor: not-allowed; }

    .address-form {
      display: flex;
      flex: 1;
      gap: 8px;
      align-items: center;
    }
    .address-input-wrapper {
      position: relative;
      display: flex;
      align-items: center;
      flex: 1;
    }
    .url-lock {
      position: absolute;
      left: 10px;
      font-size: 12px;
      opacity: 0.7;
    }
    #address {
      width: 100%;
      padding: 8px 36px 8px 32px;
      background: var(--bg-input);
      border: 1px solid transparent;
      border-radius: 20px;
      color: #fff;
      font-size: 14px;
      font-family: inherit;
    }
    #address:focus {
      outline: none;
      border-color: var(--primary);
      background: #1e293b;
    }
    .btn-go {
      padding: 6px 16px;
      background: var(--primary);
      border: none;
      border-radius: 20px;
      color: #fff;
      font-weight: 500;
      font-size: 13px;
      cursor: pointer;
    }
    .btn-go:hover { background: var(--primary-hover); }
    .signout-btn {
      padding: 6px 12px;
      background: transparent;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-muted);
      font-size: 12px;
      cursor: pointer;
    }
    .signout-btn:hover { background: #e11d4822; border-color: #e11d48; color: #f43f5e; }

    .loader {
      position: absolute;
      right: 12px;
      width: 14px;
      height: 14px;
      border: 2px solid #64748b;
      border-top-color: var(--primary);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    .loader.hidden { display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }

    .quick-bookmarks {
      display: flex;
      gap: 8px;
      padding: 6px 14px;
      background: #0f172a88;
      border-bottom: 1px solid var(--border);
      align-items: center;
      font-size: 12px;
    }
    .quick-title { color: var(--text-muted); }
    .quick-link {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      color: #93c5fd;
      border-radius: 4px;
      padding: 2px 8px;
      cursor: pointer;
      font-size: 12px;
    }
    .quick-link:hover { background: #3b82f622; border-color: var(--primary); color: #fff; }

    .viewport-container {
      flex: 1;
      width: 100%;
      position: relative;
      background: #fff;
    }
    #viewport {
      width: 100%;
      height: 100%;
      border: none;
      display: block;
      background: #fff;
    }
  </style>
</head>
<body>
  ${body}
</body>
</html>`;
}

function parseCookies(request: Request): Map<string, string> {
  const cookies = new Map<string, string>();
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) {
    return cookies;
  }

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      const name = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      if (value) {
        try {
          cookies.set(name, decodeURIComponent(value));
        } catch {
          // Ignore malformed cookie values
        }
      }
    }
  }
  return cookies;
}

function serializeCookie(
  name: string,
  value: string,
  maxAge: number,
  httpOnly: boolean,
  request: Request,
): string {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}${secure}; SameSite=Strict${httpOnly ? "; HttpOnly" : ""}`;
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  let difference = leftBytes.length ^ rightBytes.length;
  const length = Math.max(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

function base64UrlEncode(value: string | Uint8Array): string {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character,
  );
}

export {
  validateTarget,
  isBlockedHostname,
  accessDeniedResponse,
  serializeCookie,
  resolveProxiedUrl,
  rewriteCss,
  rewriteSrcset,
};
