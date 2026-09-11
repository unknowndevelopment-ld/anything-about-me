interface Env {
  PROXY_USERNAME?: string;
  PROXY_PASSWORD?: string;
  SESSION_SECRET?: string;
  UPSTREAM_ALLOWLIST?: string;
}

const SESSION_COOKIE = "session_token";
const CSRF_COOKIE = "csrf_token";
const TARGET_COOKIE = "active_target";
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

    if (url.pathname === "/" && request.method === "GET") {
      return homeResponse(request);
    }

    // Direct proxy endpoints
    if (url.pathname === "/service" || url.pathname === "/proxy") {
      return handleProxy(request, env);
    }

    // Dynamic Asset & Fallback Routing:
    // When a page inside the browser loads relative assets (e.g. /load.php, /app.js, /api/...)
    // resolve against Referer or active target cookie
    return handleFallbackAsset(request, env);
  },
};

async function handleLogin(request: Request, env: Env): Promise<Response> {
  if (!env.PROXY_USERNAME || !env.PROXY_PASSWORD || !env.SESSION_SECRET) {
    return new Response(
      "ERROR: Server configuration missing. Ensure PROXY_USERNAME, PROXY_PASSWORD, and SESSION_SECRET are set.",
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

async function handleFallbackAsset(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  // 1. Check if ?url= is passed in query
  if (url.searchParams.has("url")) {
    return handleProxy(request, env);
  }

  // 2. Check Referer header
  const referer = request.headers.get("Referer");
  if (referer) {
    try {
      const refUrl = new URL(referer);
      const refTarget = refUrl.searchParams.get("url");
      if (refTarget) {
        const resolved = new URL(url.pathname + url.search, refTarget).toString();
        return fetchUpstream(request, resolved, env);
      }
    } catch {}
  }

  // 3. Check active target cookie
  const cookies = parseCookies(request);
  const activeTarget = cookies.get(TARGET_COOKIE);
  if (activeTarget) {
    try {
      const resolved = new URL(url.pathname + url.search, activeTarget).toString();
      return fetchUpstream(request, resolved, env);
    } catch {}
  }

  return new Response("Not Found", { status: 404 });
}

async function handleProxy(request: Request, env: Env): Promise<Response> {
  const target = new URL(request.url).searchParams.get("url");
  if (!target) {
    return new Response("Target URL is required (?url=...).", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });
  }

  return fetchUpstream(request, target, env);
}

async function fetchUpstream(request: Request, rawTarget: string, env: Env): Promise<Response> {
  const validatedTarget = validateTarget(rawTarget, env.UPSTREAM_ALLOWLIST);
  if (!validatedTarget) {
    return accessDeniedResponse();
  }

  try {
    const targetParsed = new URL(validatedTarget);

    // Filter and prepare headers to send upstream
    const forwardHeaders = new Headers();
    for (const [key, value] of request.headers.entries()) {
      const lowerKey = key.toLowerCase();
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
    if (!forwardHeaders.has("Accept")) {
      forwardHeaders.set(
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
      );
    }
    if (!forwardHeaders.has("Accept-Language")) {
      forwardHeaders.set("Accept-Language", "en-US,en;q=0.9");
    }

    const hasBody = !["GET", "HEAD"].includes(request.method.toUpperCase()) && request.body !== null;

    const upstreamResponse = await fetch(validatedTarget, {
      method: request.method,
      headers: forwardHeaders,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
    });

    const headers = new Headers(upstreamResponse.headers);

    // CRITICAL: Strip compression headers because Cloudflare automatically decompresses the stream
    headers.delete("content-encoding");
    headers.delete("content-length");
    headers.delete("transfer-encoding");

    // Remove security headers that prevent framing and script execution
    headers.delete("x-frame-options");
    headers.delete("content-security-policy");
    headers.delete("content-security-policy-report-only");
    headers.delete("cross-origin-opener-policy");
    headers.delete("cross-origin-embedder-policy");
    headers.delete("cross-origin-resource-policy");
    headers.delete("strict-transport-security");
    headers.delete("permissions-policy");

    // Add open CORS headers
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
    headers.set("Access-Control-Allow-Headers", "*");
    headers.set("X-Content-Type-Options", "nosniff");

    // Set cookie tracking the active upstream origin
    headers.append(
      "Set-Cookie",
      serializeCookie(TARGET_COOKIE, targetParsed.origin, SESSION_TTL_SECONDS, false, request),
    );

    // Handle HTTP Redirects (301, 302, 303, 307, 308)
    const location = upstreamResponse.headers.get("Location");
    if (location && upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
      try {
        const redirectedTarget = new URL(location, validatedTarget).toString();
        const safeRedirect = validateTarget(redirectedTarget, env.UPSTREAM_ALLOWLIST);
        if (safeRedirect) {
          headers.set("Location", `/service?url=${encodeURIComponent(safeRedirect)}`);
        }
      } catch {
        // Leave location header as-is if unresolvable
      }
    }

    const contentType = (headers.get("Content-Type") || "").toLowerCase();

    // Rewrite HTML responses
    if (contentType.includes("text/html")) {
      const baseResponse = new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers,
      });
      return rewriteHtml(baseResponse, validatedTarget);
    }

    // Rewrite CSS responses
    if (contentType.includes("text/css")) {
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
    const message = err instanceof Error ? err.message : "Error connecting";
    return new Response(`Unable to reach target: ${message}`, {
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
    trimmed.startsWith("/service?url=") ||
    trimmed.startsWith("/proxy?url=")
  ) {
    return relativeOrAbsolute;
  }
  try {
    const resolved = new URL(trimmed, baseUrl).toString();
    return `/service?url=${encodeURIComponent(resolved)}`;
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
      if (
        !url ||
        url.startsWith("data:") ||
        url.startsWith("#") ||
        url.startsWith("/service?url=") ||
        url.startsWith("/proxy?url=")
      ) {
        return match;
      }
      const proxied = resolveProxiedUrl(url, baseUrl);
      return `url("${proxied}")`;
    })
    .replace(/@import\s+(['"])(.*?)\1/gi, (match, quote, url) => {
      if (!url || url.startsWith("data:") || url.startsWith("/service?url=") || url.startsWith("/proxy?url=")) {
        return match;
      }
      const proxied = resolveProxiedUrl(url, baseUrl);
      return `@import "${proxied}"`;
    });
}

function rewriteHtml(response: Response, targetUrl: string): Response {
  const targetParsed = new URL(targetUrl);
  const baseTag = `<base href="${targetUrl}">`;

  const clientHookScript = `<script id="__client_nav_hook__">
(function() {
  const currentTarget = ${JSON.stringify(targetUrl)};
  const currentOrigin = ${JSON.stringify(targetParsed.origin)};
  const endpoint = '/service?url=';

  // Disable ServiceWorker registration cleanly to prevent worker scope conflicts
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register = function() {
      return Promise.reject(new Error('ServiceWorker not supported in container'));
    };
  }

  function toRouted(rawUrl) {
    if (!rawUrl) return rawUrl;
    const str = String(rawUrl).trim();
    if (str.startsWith('javascript:') || str.startsWith('mailto:') || str.startsWith('tel:') || str.startsWith('data:') || str.startsWith('#') || str.startsWith('/service?url=') || str.startsWith('/proxy?url=')) {
      return str;
    }
    try {
      const resolved = new URL(str, currentTarget).href;
      return endpoint + encodeURIComponent(resolved);
    } catch (e) {
      return str;
    }
  }

  function notifyParent(urlOverride) {
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({
          type: 'client_navigated',
          url: urlOverride || currentTarget,
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
        window.parent.postMessage({ type: 'client_open_tab', url: resolved }, '*');
      } else {
        window.location.href = endpoint + encodeURIComponent(resolved);
      }
    } catch(err) {
      window.location.href = el.href;
    }
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (!form || form.tagName !== 'FORM') return;
    try {
      const action = form.getAttribute('action') || '';
      form.action = endpoint + encodeURIComponent(new URL(action, currentTarget).href);
    } catch(err) {}
  }, true);

  // Intercept window.open
  const origOpen = window.open;
  window.open = function(url, target, features) {
    if (!url) return null;
    try {
      const resolved = new URL(url, currentTarget).href;
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'client_open_tab', url: resolved }, '*');
        return null;
      }
      return origOpen.call(window, endpoint + encodeURIComponent(resolved), target, features);
    } catch(e) {
      return origOpen.apply(window, arguments);
    }
  };

  // Intercept SPA navigation (pushState / replaceState)
  const origPushState = history.pushState;
  history.pushState = function(state, unused, url) {
    if (url) {
      try {
        const resolved = new URL(url, currentTarget).href;
        notifyParent(resolved);
      } catch(e) {}
    }
    return origPushState.apply(this, arguments);
  };

  const origReplaceState = history.replaceState;
  history.replaceState = function(state, unused, url) {
    if (url) {
      try {
        const resolved = new URL(url, currentTarget).href;
        notifyParent(resolved);
      } catch(e) {}
    }
    return origReplaceState.apply(this, arguments);
  };

  // Intercept fetch
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    try {
      if (typeof input === 'string') {
        input = toRouted(input);
      } else if (input && typeof input === 'object' && 'url' in input) {
        input = toRouted(input.url);
      }
    } catch(e) {}
    return origFetch.call(this, input, init);
  };

  // Intercept XMLHttpRequest
  const origXhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      url = toRouted(url);
    } catch(e) {}
    return origXhrOpen.call(this, method, url, ...rest);
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { notifyParent(); });
  } else {
    notifyParent();
  }
  window.addEventListener('load', function() { notifyParent(); });
})();
</script>`;

  const rewriter = new HTMLRewriter()
    .on("head", {
      element(element) {
        element.prepend(baseTag + clientHookScript, { html: true });
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

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "metadata.google.internal" ||
    host === "metadata.google" ||
    host === "instance-data.ec2.internal"
  ) {
    return true;
  }

  if (host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:")) {
    return true;
  }

  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = [
      parseInt(ipv4Match[1], 10),
      parseInt(ipv4Match[2], 10),
      parseInt(ipv4Match[3], 10),
      parseInt(ipv4Match[4], 10),
    ];

    if (octets.some((octet) => octet > 255)) {
      return true;
    }

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
  return new Response("403 Forbidden", {
    status: 403,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function loginPage(csrf: string, env: Env): string {
  const envStatus =
    !env.PROXY_USERNAME || !env.PROXY_PASSWORD || !env.SESSION_SECRET
      ? `<div style="background:#1f1212;border:1px solid #3d1c1c;color:#f87171;padding:12px;margin-bottom:20px;border-radius:6px;font-size:13px;text-align:left;">Setup required: secrets not configured.</div>`
      : "";

  return page(
    "",
    `<div class="login-wrapper">
    <div class="login-modal">
      ${envStatus}
      <form method="post" action="/login">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <input name="username" autocomplete="username" placeholder="Username" required autofocus spellcheck="false">
        <input type="password" name="password" autocomplete="current-password" placeholder="Password" required>
        <button type="submit" class="btn-primary">Sign in</button>
      </form>
    </div>
  </div>`,
  );
}

function homePage(csrf: string): string {
  return page(
    "",
    `<div class="app-container">
    <div class="tabs-bar">
      <div class="tabs" id="tab-list" role="tablist"></div>
      <button id="new-tab-btn" class="new-tab-btn" type="button" title="New Tab" aria-label="New Tab">+</button>
    </div>
    <div class="toolbar">
      <div class="nav-buttons">
        <button class="icon-button" id="back" type="button" title="Back" aria-label="Back">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <button class="icon-button" id="forward" type="button" title="Forward" aria-label="Forward">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </button>
        <button class="icon-button" id="refresh" type="button" title="Reload" aria-label="Reload">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        </button>
        <button class="icon-button" id="home" type="button" title="Home" aria-label="Home">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
        </button>
      </div>
      <form id="address-form" class="address-form">
        <div class="address-input-wrapper">
          <input id="address" type="text" placeholder="Search or enter URL..." autocomplete="off" spellcheck="false" required>
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
    <div class="viewport-container">
      <iframe id="viewport" title="Viewport" allow="fullscreen; clipboard-read; clipboard-write; microphone; camera; midi; encrypted-media; autodiscovery" referrerpolicy="no-referrer"></iframe>
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
      if (!/\\s/.test(trimmed) && trimmed.includes('.')) {
        return 'https://' + trimmed;
      }
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
        viewport.src = '/service?url=' + encodeURIComponent(tab.url);
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
      viewport.src = '/service?url=' + encodeURIComponent(url);
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
      viewport.src = '/service?url=' + encodeURIComponent(tab.url);
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
      viewport.src = '/service?url=' + encodeURIComponent(tab.url);
      renderTabs();
      updateButtons();
    });

    refreshBtn.addEventListener('click', () => {
      const tab = tabs[activeIndex];
      if (tab && tab.url) {
        showLoader();
        viewport.src = '/service?url=' + encodeURIComponent(tab.url);
      }
    });

    homeBtn.addEventListener('click', () => {
      navigate('https://duckduckgo.com/html/', false);
    });

    newTabBtn.addEventListener('click', () => addTab());

    window.addEventListener('message', (event) => {
      if (!event.data) return;
      if (event.data.type === 'client_navigated') {
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
      } else if (event.data.type === 'client_open_tab' && event.data.url) {
        addTab(event.data.url);
      }
    });

    addTab('https://duckduckgo.com/html/');
  })();
  </script>`,
  );
}

function page(title: string, body: string): string {
  const pageTitle = title ? escapeHtml(title) : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${pageTitle}</title>
  <style>
    :root {
      --bg-root: #0a0a0a;
      --bg-surface: #141414;
      --bg-card: #171717;
      --bg-input: #1f1f1f;
      --border-subtle: #262626;
      --border-hover: #404040;
      --text-main: #ededed;
      --text-muted: #737373;
      --btn-bg: #222222;
      --btn-hover: #2e2e2e;
      --tab-active: #141414;
      --tab-inactive: #0a0a0a;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: var(--bg-root);
      color: var(--text-main);
      height: 100vh;
      overflow: hidden;
      -webkit-font-smoothing: antialiased;
    }
    .login-wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      width: 100vw;
      background: var(--bg-root);
    }
    .login-modal {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.8);
      padding: 32px 28px;
      width: 100%;
      max-width: 320px;
    }
    .login-modal form {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .login-modal input {
      width: 100%;
      padding: 12px 14px;
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      color: var(--text-main);
      font-size: 14px;
      transition: border-color 0.15s, background 0.15s;
    }
    .login-modal input:focus {
      outline: none;
      border-color: var(--border-hover);
      background: #242424;
    }
    .login-modal input::placeholder {
      color: var(--text-muted);
    }
    .btn-primary {
      width: 100%;
      padding: 12px;
      background: var(--btn-bg);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      border-radius: 6px;
      font-weight: 500;
      font-size: 14px;
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s;
      margin-top: 4px;
    }
    .btn-primary:hover {
      background: var(--btn-hover);
      border-color: var(--border-hover);
    }

    .app-container {
      display: flex;
      flex-direction: column;
      height: 100vh;
      background: var(--bg-surface);
    }
    .tabs-bar {
      display: flex;
      align-items: center;
      background: var(--bg-root);
      padding: 6px 8px 0;
      gap: 3px;
      border-bottom: 1px solid var(--border-subtle);
      user-select: none;
    }
    .tabs {
      display: flex;
      gap: 3px;
      overflow-x: auto;
      flex: 1;
      scrollbar-width: none;
    }
    .tabs::-webkit-scrollbar { display: none; }
    .tab {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 7px 12px;
      background: var(--tab-inactive);
      color: var(--text-muted);
      border-radius: 6px 6px 0 0;
      font-size: 12px;
      max-width: 180px;
      cursor: pointer;
      border: 1px solid transparent;
      border-bottom: none;
      transition: all 0.15s;
    }
    .tab:hover { background: #171717; color: #d4d4d4; }
    .tab.active {
      background: var(--tab-active);
      color: #fafafa;
      border-color: var(--border-subtle);
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
      font-size: 14px;
      line-height: 1;
      padding: 1px 3px;
      border-radius: 3px;
    }
    .tab-close:hover { background: #333333; color: #fff; }
    .new-tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 16px;
      cursor: pointer;
      padding: 4px 8px;
      border-radius: 4px;
      margin-bottom: 2px;
    }
    .new-tab-btn:hover { background: #171717; color: #fff; }

    .toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-subtle);
    }
    .nav-buttons { display: flex; gap: 2px; align-items: center; }
    .icon-button {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 6px 7px;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon-button:hover:not(:disabled) { background: #262626; color: #fff; }
    .icon-button:disabled { opacity: 0.2; cursor: not-allowed; }

    .address-form {
      display: flex;
      flex: 1;
      gap: 6px;
      align-items: center;
    }
    .address-input-wrapper {
      position: relative;
      display: flex;
      align-items: center;
      flex: 1;
    }
    #address {
      width: 100%;
      padding: 6px 30px 6px 12px;
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      color: var(--text-main);
      font-size: 13px;
      font-family: inherit;
    }
    #address:focus {
      outline: none;
      border-color: var(--border-hover);
      background: #242424;
    }
    #address::placeholder {
      color: var(--text-muted);
    }
    .btn-go {
      padding: 6px 12px;
      background: var(--btn-bg);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      color: var(--text-main);
      font-size: 12px;
      cursor: pointer;
    }
    .btn-go:hover { background: var(--btn-hover); border-color: var(--border-hover); }
    .signout-btn {
      padding: 6px 10px;
      background: transparent;
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      color: var(--text-muted);
      font-size: 12px;
      cursor: pointer;
    }
    .signout-btn:hover { background: #262626; color: #d4d4d4; }

    .loader {
      position: absolute;
      right: 10px;
      width: 12px;
      height: 12px;
      border: 2px solid #404040;
      border-top-color: #ededed;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    .loader.hidden { display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }

    .viewport-container {
      flex: 1;
      width: 100%;
      position: relative;
      background: #000;
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
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}${secure}; SameSite=Lax${httpOnly ? "; HttpOnly" : ""}`;
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
