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

const allowlistCache = new Map<string, URL[]>();
const keyCache = new Map<string, CryptoKey>();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // 1. Diagnostic endpoint
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

    // 2. Authentication endpoints
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

    // 3. Browser UI home
    if (url.pathname === "/" && request.method === "GET") {
      return homeResponse(request);
    }

    // 4. Query-based Proxy endpoints (/service?url=... or /proxy?url=...)
    if (url.pathname === "/service" || url.pathname === "/proxy") {
      return handleProxy(request, env);
    }

    // 5. Path-based direct routing (e.g. /discord.com/login, /https://discord.com/login, /https:/discord.com/login)
    const directTarget = extractTargetFromPath(url.pathname, url.search);
    if (directTarget) {
      return fetchUpstream(request, directTarget, env);
    }

    // 6. Dynamic Asset & Fallback Routing via Referer or active target cookie
    return handleFallbackAsset(request, env);
  },
};

function extractTargetFromPath(pathname: string, search: string): string | null {
  const cleanPath = pathname.replace(/^\/+/, "");
  if (!cleanPath) return null;

  // Pattern 1: https://... or http://...
  if (/^https?:\/\//i.test(cleanPath)) {
    return cleanPath + search;
  }

  // Pattern 2: https:/... or http:/... (single slash normalization)
  if (/^https?:\/[^/]/i.test(cleanPath)) {
    const normalized = cleanPath.replace(
      /^https?:\//i,
      (m) => (m.toLowerCase().startsWith("https") ? "https://" : "http://"),
    );
    return normalized + search;
  }

  // Pattern 3: domain.tld/path (e.g. discord.com/login, en.wikipedia.org/wiki/Main_Page)
  const firstSlash = cleanPath.indexOf("/");
  const hostPart = firstSlash === -1 ? cleanPath : cleanPath.slice(0, firstSlash);

  if (
    hostPart.includes(".") &&
    !hostPart.includes(" ") &&
    !hostPart.endsWith(".well-known") &&
    !["login", "logout", "service", "proxy"].includes(hostPart.toLowerCase()) &&
    /^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(hostPart)
  ) {
    return `https://${cleanPath}${search}`;
  }

  return null;
}

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

  if (url.searchParams.has("url")) {
    return handleProxy(request, env);
  }

  const referer = request.headers.get("Referer");
  if (referer) {
    try {
      const refUrl = new URL(referer);
      let refTarget = refUrl.searchParams.get("url");
      if (!refTarget) {
        refTarget = extractTargetFromPath(refUrl.pathname, refUrl.search);
      }
      if (refTarget) {
        const resolved = new URL(url.pathname + url.search, refTarget).toString();
        return fetchUpstream(request, resolved, env);
      }
    } catch {}
  }

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

    let upstreamReferer = validatedTarget;
    const hostLower = targetParsed.hostname.toLowerCase();
    if (
      hostLower.endsWith(".redd.it") ||
      hostLower.endsWith(".redditmedia.com") ||
      hostLower === "redd.it"
    ) {
      upstreamReferer = "https://www.reddit.com/";
    } else if (
      hostLower.endsWith(".discordapp.com") ||
      hostLower.endsWith(".discord.gg") ||
      hostLower.endsWith(".discord.com")
    ) {
      upstreamReferer = "https://discord.com/";
    }

    forwardHeaders.set("Host", targetParsed.host);
    forwardHeaders.set("Origin", targetParsed.origin);
    forwardHeaders.set("Referer", upstreamReferer);

    // Forward client cookies to upstream (filtering out internal proxy cookies)
    const clientCookies = parseCookies(request);
    const upstreamCookiePairs: string[] = [];
    for (const [cName, cVal] of clientCookies.entries()) {
      if (![SESSION_COOKIE, CSRF_COOKIE, TARGET_COOKIE].includes(cName)) {
        upstreamCookiePairs.push(`${cName}=${encodeURIComponent(cVal)}`);
      }
    }
    if (upstreamCookiePairs.length > 0) {
      forwardHeaders.set("Cookie", upstreamCookiePairs.join("; "));
    }

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

    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const wsHeaders = new Headers(request.headers);
      wsHeaders.set("Host", targetParsed.host);
      wsHeaders.set("Origin", targetParsed.origin);
      wsHeaders.set("Referer", validatedTarget);
      return fetch(validatedTarget.replace(/^http(s?):/i, "ws$1:"), {
        headers: wsHeaders,
      });
    }

    const hasBody = !["GET", "HEAD"].includes(request.method.toUpperCase()) && request.body !== null;

    const upstreamResponse = await fetch(validatedTarget, {
      method: request.method,
      headers: forwardHeaders,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
    });

    const headers = new Headers(upstreamResponse.headers);

    headers.delete("content-encoding");
    headers.delete("content-length");
    headers.delete("transfer-encoding");

    headers.delete("x-frame-options");
    headers.delete("content-security-policy");
    headers.delete("content-security-policy-report-only");
    headers.delete("cross-origin-opener-policy");
    headers.delete("cross-origin-embedder-policy");
    headers.delete("cross-origin-resource-policy");
    headers.delete("strict-transport-security");
    headers.delete("permissions-policy");

    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
    headers.set("Access-Control-Allow-Headers", "*");
    headers.set("X-Content-Type-Options", "nosniff");

    // Rewrite upstream Set-Cookie headers so browser stores them on the proxy domain
    const rawSetCookies = upstreamResponse.headers.getSetCookie
      ? upstreamResponse.headers.getSetCookie()
      : [upstreamResponse.headers.get("Set-Cookie")].filter(Boolean) as string[];

    headers.delete("set-cookie");
    const isHttps = new URL(request.url).protocol === "https:";
    for (const sc of rawSetCookies) {
      const rewritten = sc
        .replace(/;\s*Domain=[^;]+/gi, "")
        .replace(/;\s*SameSite=[^;]+/gi, "")
        .replace(/;\s*Secure/gi, "");
      headers.append("Set-Cookie", `${rewritten}; SameSite=None${isHttps ? "; Secure" : ""}`);
    }

    headers.append(
      "Set-Cookie",
      serializeCookie(TARGET_COOKIE, validatedTarget, SESSION_TTL_SECONDS, false, request),
    );

    const location = upstreamResponse.headers.get("Location");
    if (location && upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
      try {
        const redirectedTarget = new URL(location, validatedTarget).toString();
        const safeRedirect = validateTarget(redirectedTarget, env.UPSTREAM_ALLOWLIST);
        if (safeRedirect) {
          headers.set("Location", `/service?url=${encodeURIComponent(safeRedirect)}`);
          headers.append(
            "Set-Cookie",
            serializeCookie(TARGET_COOKIE, safeRedirect, SESSION_TTL_SECONDS, false, request),
          );
        }
      } catch {}
    }

    const contentType = (headers.get("Content-Type") || "").toLowerCase();

    if (contentType.includes("text/html")) {
      const baseResponse = new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers,
      });
      return rewriteHtml(baseResponse, validatedTarget);
    }

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

function decodeHtmlEntities(str: string): string {
  if (!str) return str;
  return str
    .replace(/&amp;/g, "&")
    .replace(/&#38;/g, "&")
    .replace(/&#x26;/gi, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#34;/g, '"')
    .replace(/&#x22;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&lt;/g, "<")
    .replace(/&#60;/g, "<")
    .replace(/&#x3c;/gi, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#62;/g, ">")
    .replace(/&#x3e;/gi, ">");
}

function resolveProxiedUrl(relativeOrAbsolute: string, baseUrl: string): string {
  if (!relativeOrAbsolute) return relativeOrAbsolute;
  const decoded = decodeHtmlEntities(relativeOrAbsolute.trim());
  if (
    decoded.startsWith("javascript:") ||
    decoded.startsWith("mailto:") ||
    decoded.startsWith("tel:") ||
    decoded.startsWith("data:") ||
    decoded.startsWith("#") ||
    decoded.startsWith("/service?url=") ||
    decoded.startsWith("/proxy?url=")
  ) {
    return decoded;
  }
  try {
    const resolved = new URL(decoded, baseUrl).toString();
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
      const cleanUrl = decodeHtmlEntities(url || "").trim();
      if (
        !cleanUrl ||
        cleanUrl.startsWith("data:") ||
        cleanUrl.startsWith("#") ||
        cleanUrl.startsWith("/service?url=") ||
        cleanUrl.startsWith("/proxy?url=")
      ) {
        return match;
      }
      const proxied = resolveProxiedUrl(cleanUrl, baseUrl);
      return `url("${proxied}")`;
    })
    .replace(/@import\s+(['"])(.*?)\1/gi, (match, quote, url) => {
      const cleanUrl = decodeHtmlEntities(url || "").trim();
      if (
        !cleanUrl ||
        cleanUrl.startsWith("data:") ||
        cleanUrl.startsWith("/service?url=") ||
        cleanUrl.startsWith("/proxy?url=")
      ) {
        return match;
      }
      const proxied = resolveProxiedUrl(cleanUrl, baseUrl);
      return `@import "${proxied}"`;
    });
}

function rewriteHtml(response: Response, targetUrl: string): Response {
  const clientHookScript = `<script id="__client_nav_hook__">
(function() {
  const realParent = window.parent;
  const realTop = window.top;
  const currentTarget = ${JSON.stringify(targetUrl)};
  const endpoint = '/service?url=';
  let virtualUrl;
  try {
    virtualUrl = new URL(currentTarget);
  } catch (e) {
    virtualUrl = new URL(window.location.href);
  }

  try {
    Object.defineProperty(window, 'top', {
      get: function() { return window.self; },
      set: function(val) {
        if (typeof val === 'string' && val) {
          window.location.href = endpoint + encodeURIComponent(new URL(val, virtualUrl ? virtualUrl.href : currentTarget).href);
        }
      },
      configurable: true
    });
  } catch(e) {}

  try {
    Object.defineProperty(window, 'parent', {
      get: function() { return window.self; },
      set: function(val) {
        if (typeof val === 'string' && val) {
          window.location.href = endpoint + encodeURIComponent(new URL(val, virtualUrl ? virtualUrl.href : currentTarget).href);
        }
      },
      configurable: true
    });
  } catch(e) {}

  function decodeEntities(str) {
    if (!str) return str;
    return String(str)
      .replace(/&amp;/g, '&')
      .replace(/&#38;/g, '&')
      .replace(/&#x26;/gi, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#34;/g, '"')
      .replace(/&#x22;/gi, '"')
      .replace(/&#39;/g, "'")
      .replace(/&#x27;/gi, "'")
      .replace(/&lt;/g, '<')
      .replace(/&#60;/g, '<')
      .replace(/&#x3c;/gi, '<')
      .replace(/&gt;/g, '>')
      .replace(/&#62;/g, '>')
      .replace(/&#x3e;/gi, '>');
  }

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register = function() {
      return Promise.reject(new Error('ServiceWorker disabled'));
    };
  }

  function toRouted(rawUrl) {
    if (!rawUrl) return rawUrl;
    const str = decodeEntities(rawUrl).trim();
    if (
      str.startsWith('javascript:') ||
      str.startsWith('mailto:') ||
      str.startsWith('tel:') ||
      str.startsWith('data:') ||
      str.startsWith('#') ||
      str.startsWith('/service?url=') ||
      str.startsWith('/proxy?url=')
    ) {
      return str;
    }
    try {
      const resolved = new URL(str, virtualUrl ? virtualUrl.href : currentTarget).href;
      return endpoint + encodeURIComponent(resolved);
    } catch (e) {
      return str;
    }
  }

  // Intercept Discord GLOBAL_ENV configuration
  try {
    let globalEnvStore;
    Object.defineProperty(window, 'GLOBAL_ENV', {
      get: function() {
        return globalEnvStore;
      },
      set: function(val) {
        if (val && typeof val === 'object') {
          try {
            if (val.API_ENDPOINT && typeof val.API_ENDPOINT === 'string') {
              val.API_ENDPOINT = endpoint + encodeURIComponent(new URL(val.API_ENDPOINT, currentTarget).href);
            }
            if (val.ASSET_ENDPOINT && typeof val.ASSET_ENDPOINT === 'string') {
              val.ASSET_ENDPOINT = endpoint + encodeURIComponent(new URL(val.ASSET_ENDPOINT, currentTarget).href);
            }
            if (val.DEVELOPERS_ENDPOINT && typeof val.DEVELOPERS_ENDPOINT === 'string') {
              val.DEVELOPERS_ENDPOINT = endpoint + encodeURIComponent(new URL(val.DEVELOPERS_ENDPOINT, currentTarget).href);
            }
            if (val.MARKETING_ENDPOINT && typeof val.MARKETING_ENDPOINT === 'string') {
              val.MARKETING_ENDPOINT = endpoint + encodeURIComponent(new URL(val.MARKETING_ENDPOINT, currentTarget).href);
            }
            if (val.WEBAPP_ENDPOINT && typeof val.WEBAPP_ENDPOINT === 'string') {
              val.WEBAPP_ENDPOINT = endpoint + encodeURIComponent(new URL(val.WEBAPP_ENDPOINT, currentTarget).href);
            }
            if (val.WIDGET_ENDPOINT && typeof val.WIDGET_ENDPOINT === 'string') {
              val.WIDGET_ENDPOINT = endpoint + encodeURIComponent(new URL(val.WIDGET_ENDPOINT, currentTarget).href);
            }
          } catch(e) {}
        }
        globalEnvStore = val;
      },
      configurable: true,
      enumerable: true
    });
  } catch(e) {}

  // Location prototype hooks for SPA routing
  try {
    const locProto = Location.prototype;
    const props = ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'];
    props.forEach(function(prop) {
      try {
        Object.defineProperty(locProto, prop, {
          get: function() {
            return virtualUrl[prop];
          },
          set: function(val) {
            if (prop === 'href') {
              try {
                const resolved = new URL(val, virtualUrl.href).href;
                virtualUrl = new URL(resolved);
                window.location.href = endpoint + encodeURIComponent(resolved);
              } catch (e) {
                window.location.href = endpoint + encodeURIComponent(val);
              }
            } else if (prop === 'pathname') {
              try {
                virtualUrl.pathname = val;
                window.location.href = endpoint + encodeURIComponent(virtualUrl.href);
              } catch (e) {}
            } else if (prop === 'search') {
              try {
                virtualUrl.search = val;
                window.location.href = endpoint + encodeURIComponent(virtualUrl.href);
              } catch (e) {}
            } else if (prop === 'hash') {
              virtualUrl.hash = val;
            }
          },
          configurable: true,
          enumerable: true,
        });
      } catch (e) {}
    });
  } catch (e) {}

  function notifyParent(urlOverride) {
    try {
      if (realParent && realParent !== window) {
        realParent.postMessage({
          type: 'client_navigated',
          url: urlOverride || (virtualUrl ? virtualUrl.href : currentTarget),
          title: document.title || currentTarget,
        }, '*');
      }
    } catch (e) {}
  }

  function rewriteNode(node) {
    if (!node || node.nodeType !== 1) return;
    const tag = node.tagName;
    if (tag === 'A') {
      const h = node.getAttribute('href');
      if (h && !h.startsWith('#') && !h.startsWith('javascript:') && !h.startsWith('/service?url=') && !h.startsWith('/proxy?url=')) {
        try {
          const res = new URL(h, virtualUrl ? virtualUrl.href : currentTarget).href;
          node.setAttribute('href', endpoint + encodeURIComponent(res));
          if (node.getAttribute('target') === '_top' || node.getAttribute('target') === '_parent') {
            node.setAttribute('target', '_self');
          }
        } catch (e) {}
      }
    } else if (tag === 'FORM') {
      const a = node.getAttribute('action');
      if (a && !a.startsWith('/service?url=') && !a.startsWith('/proxy?url=')) {
        try {
          const res = new URL(a, virtualUrl ? virtualUrl.href : currentTarget).href;
          node.setAttribute('action', endpoint + encodeURIComponent(res));
        } catch (e) {}
      }
    } else if (['IMG', 'SCRIPT', 'IFRAME', 'SOURCE', 'VIDEO', 'AUDIO', 'FACEPLATE-IMG', 'FACEPLATE-IMAGE'].indexOf(tag) !== -1) {
      const src = node.getAttribute('src');
      if (src && !src.startsWith('data:') && !src.startsWith('/service?url=') && !src.startsWith('/proxy?url=')) {
        try {
          const res = new URL(src, virtualUrl ? virtualUrl.href : currentTarget).href;
          node.setAttribute('src', endpoint + encodeURIComponent(res));
        } catch (e) {}
      }
      const dataSrc = node.getAttribute('data-src');
      if (dataSrc && !dataSrc.startsWith('data:') && !dataSrc.startsWith('/service?url=') && !dataSrc.startsWith('/proxy?url=')) {
        try {
          const res = new URL(dataSrc, virtualUrl ? virtualUrl.href : currentTarget).href;
          node.setAttribute('data-src', endpoint + encodeURIComponent(res));
        } catch (e) {}
      }
    } else if (tag === 'LINK') {
      const href = node.getAttribute('href');
      if (href && !href.startsWith('data:') && !href.startsWith('/service?url=') && !href.startsWith('/proxy?url=')) {
        try {
          const res = new URL(href, virtualUrl ? virtualUrl.href : currentTarget).href;
          node.setAttribute('href', endpoint + encodeURIComponent(res));
        } catch (e) {}
      }
    }
  }

  // Intercept Element.prototype.setAttribute for React / DOM frameworks
  try {
    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
      if (typeof value === 'string' && value) {
        const lower = name.toLowerCase();
        if (
          lower === 'src' ||
          lower === 'data-src' ||
          lower === 'data-lazy-src' ||
          lower === 'poster' ||
          lower === 'background' ||
          lower === 'data-url'
        ) {
          value = toRouted(value);
        } else if (lower === 'href' && !value.startsWith('#') && !value.startsWith('javascript:') && !value.startsWith('mailto:')) {
          value = toRouted(value);
        } else if (lower === 'action') {
          value = toRouted(value);
        } else if (lower === 'srcset' || lower === 'data-srcset') {
          value = value.split(',').map(function(s) {
            const parts = s.trim().split(/\s+/);
            if (parts[0]) parts[0] = toRouted(parts[0]);
            return parts.join(' ');
          }).join(', ');
        }
      }
      return origSetAttribute.call(this, name, value);
    };
  } catch(e) {}

  // Intercept DOM Image src setter
  try {
    const origImgDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    if (origImgDescriptor && origImgDescriptor.set) {
      Object.defineProperty(HTMLImageElement.prototype, 'src', {
        get: function() {
          return origImgDescriptor.get.call(this);
        },
        set: function(val) {
          origImgDescriptor.set.call(this, toRouted(val));
        },
        configurable: true,
        enumerable: true,
      });
    }
  } catch (e) {}

  // Wrap Worker & SharedWorker
  if (window.Worker) {
    const OrigWorker = window.Worker;
    window.Worker = function(scriptURL, options) {
      return new OrigWorker(toRouted(scriptURL), options);
    };
    window.Worker.prototype = OrigWorker.prototype;
  }
  if (window.SharedWorker) {
    const OrigSharedWorker = window.SharedWorker;
    window.SharedWorker = function(scriptURL, options) {
      return new OrigSharedWorker(toRouted(scriptURL), options);
    };
    window.SharedWorker.prototype = OrigSharedWorker.prototype;
  }

  // Wrap WebSocket
  if (window.WebSocket) {
    const OrigWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      try {
        if (typeof url === 'string') {
          const str = url.trim();
          if (str.startsWith('wss://') || str.startsWith('ws://')) {
            const locProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const proxyWsUrl = locProto + '//' + window.location.host + endpoint + encodeURIComponent(str.replace(/^ws(s?):/i, 'http$1:'));
            return protocols !== undefined ? new OrigWebSocket(proxyWsUrl, protocols) : new OrigWebSocket(proxyWsUrl);
          }
        }
      } catch(e) {}
      return protocols !== undefined ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
    };
    window.WebSocket.prototype = OrigWebSocket.prototype;
  }

  // Wrap Beacon & EventSource
  if (navigator.sendBeacon) {
    const origBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function(url, data) {
      try {
        url = toRouted(url);
      } catch(e) {}
      return origBeacon.call(navigator, url, data);
    };
  }
  if (window.EventSource) {
    const OrigEventSource = window.EventSource;
    window.EventSource = function(url, dict) {
      return new OrigEventSource(toRouted(url), dict);
    };
    window.EventSource.prototype = OrigEventSource.prototype;
  }

  try {
    const observer = new MutationObserver(function(mutations) {
      for (let i = 0; i < mutations.length; i++) {
        const added = mutations[i].addedNodes;
        for (let j = 0; j < added.length; j++) {
          const n = added[j];
          if (n.nodeType === 1) {
            rewriteNode(n);
            const children = n.querySelectorAll ? n.querySelectorAll('a, form, img, script, link, iframe, faceplate-img') : [];
            for (let k = 0; k < children.length; k++) {
              rewriteNode(children[k]);
            }
          }
        }
      }
    });
    observer.observe(document.documentElement || document, { childList: true, subtree: true });
  } catch (e) {}

  window.addEventListener('click', function(e) {
    let el = e.target;
    while (el && el.tagName !== 'A') {
      el = el.parentElement;
    }
    if (!el) return;

    let href = el.getAttribute('href') || el.href;
    if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) return;

    e.preventDefault();
    e.stopPropagation();

    try {
      let resolved;
      if (href.includes('/service?url=') || href.includes('/proxy?url=')) {
        const match = href.match(/[?&]url=([^&]+)/);
        resolved = match ? decodeURIComponent(match[1]) : href;
      } else {
        resolved = new URL(href, virtualUrl ? virtualUrl.href : currentTarget).href;
      }

      const targetAttr = el.getAttribute('target');
      if (targetAttr === '_blank' && window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'client_open_tab', url: resolved }, '*');
      } else {
        window.location.href = endpoint + encodeURIComponent(resolved);
      }
    } catch (err) {
      window.location.href = el.href;
    }
  }, true);

  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (!form || form.tagName !== 'FORM') return;
    try {
      const action = form.getAttribute('action') || '';
      form.action = endpoint + encodeURIComponent(new URL(action, virtualUrl ? virtualUrl.href : currentTarget).href);
    } catch (err) {}
  }, true);

  const origOpen = window.open;
  window.open = function(url, target, features) {
    if (!url) return null;
    try {
      const resolved = new URL(url, virtualUrl ? virtualUrl.href : currentTarget).href;
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'client_open_tab', url: resolved }, '*');
        return null;
      }
      return origOpen.call(window, endpoint + encodeURIComponent(resolved), target, features);
    } catch (e) {
      return origOpen.apply(window, arguments);
    }
  };

  try {
    const origAssign = window.location.assign;
    if (origAssign) {
      window.location.assign = function(url) {
        try {
          const resolved = new URL(url, virtualUrl ? virtualUrl.href : currentTarget).href;
          window.location.href = endpoint + encodeURIComponent(resolved);
        } catch (e) {
          origAssign.call(window.location, url);
        }
      };
    }
    const origReplace = window.location.replace;
    if (origReplace) {
      window.location.replace = function(url) {
        try {
          const resolved = new URL(url, virtualUrl ? virtualUrl.href : currentTarget).href;
          window.location.href = endpoint + encodeURIComponent(resolved);
        } catch (e) {
          origReplace.call(window.location, url);
        }
      };
    }
  } catch (e) {}

  const origPushState = history.pushState;
  history.pushState = function(state, unused, url) {
    if (url) {
      try {
        const resolved = new URL(url, virtualUrl ? virtualUrl.href : currentTarget).href;
        virtualUrl = new URL(resolved);
        notifyParent(resolved);
      } catch (e) {}
    }
    return origPushState.apply(this, arguments);
  };

  const origReplaceState = history.replaceState;
  history.replaceState = function(state, unused, url) {
    if (url) {
      try {
        const resolved = new URL(url, virtualUrl ? virtualUrl.href : currentTarget).href;
        virtualUrl = new URL(resolved);
        notifyParent(resolved);
      } catch (e) {}
    }
    return origReplaceState.apply(this, arguments);
  };

  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    try {
      if (typeof input === 'string') {
        input = toRouted(input);
      } else if (input instanceof Request) {
        return origFetch.call(this, new Request(toRouted(input.url), input), init);
      } else if (input && typeof input === 'object' && 'url' in input) {
        try {
          return origFetch.call(this, new Request(toRouted(input.url), input), init);
        } catch(e) {
          input.url = toRouted(input.url);
        }
      }
    } catch (e) {}
    return origFetch.call(this, input, init);
  };

  const origXhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      url = toRouted(url);
    } catch (e) {}
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
        element.removeAttribute("integrity");
        element.removeAttribute("crossorigin");
      },
    })
    .on("script", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) {
          element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        }
        element.removeAttribute("integrity");
        element.removeAttribute("crossorigin");
        element.removeAttribute("nonce");
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
        element.removeAttribute("integrity");
        element.removeAttribute("crossorigin");
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
    })
    .on("faceplate-img, faceplate-image, shreddit-player, reddit-player, gallery-carousel", {
      element(element) {
        const src = element.getAttribute("src");
        if (src) element.setAttribute("src", resolveProxiedUrl(src, targetUrl));
        const srcset = element.getAttribute("srcset");
        if (srcset) element.setAttribute("srcset", rewriteSrcset(srcset, targetUrl));
        const poster = element.getAttribute("poster");
        if (poster) element.setAttribute("poster", resolveProxiedUrl(poster, targetUrl));
        const dataSrc = element.getAttribute("data-src");
        if (dataSrc) element.setAttribute("data-src", resolveProxiedUrl(dataSrc, targetUrl));
      },
    })
    .on("[data-src], [data-lazy-src], [data-href], [data-url]", {
      element(element) {
        const dataSrc = element.getAttribute("data-src");
        if (dataSrc) element.setAttribute("data-src", resolveProxiedUrl(dataSrc, targetUrl));
        const lazySrc = element.getAttribute("data-lazy-src");
        if (lazySrc) element.setAttribute("data-lazy-src", resolveProxiedUrl(lazySrc, targetUrl));
        const dataHref = element.getAttribute("data-href");
        if (dataHref) element.setAttribute("data-href", resolveProxiedUrl(dataHref, targetUrl));
        const dataUrl = element.getAttribute("data-url");
        if (dataUrl) element.setAttribute("data-url", resolveProxiedUrl(dataUrl, targetUrl));
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
      } catch {}
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
    `<div class="chrome-window">
    <!-- Top Tab Strip -->
    <div class="chrome-tabstrip">
      <div class="tabs-container" id="tabs-container"></div>
      <button class="new-tab-btn" id="new-tab-btn" title="New Tab" aria-label="New Tab">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M5 12h14"/></svg>
      </button>
      <div class="window-controls">
        <div class="win-btn win-min" title="Minimize">&#x2014;</div>
        <div class="win-btn win-max" title="Maximize">&#x25A2;</div>
        <div class="win-btn win-close" title="Close">&#x2715;</div>
      </div>
    </div>

    <!-- Chromium Navigation Toolbar -->
    <div class="chrome-toolbar">
      <div class="nav-controls">
        <button class="tool-btn" id="btn-back" title="Click to go back" disabled>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <button class="tool-btn" id="btn-forward" title="Click to go forward" disabled>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </button>
        <button class="tool-btn" id="btn-reload" title="Reload this page">
          <svg id="icon-reload" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        </button>
      </div>

      <!-- Omnibox (Address Bar) -->
      <div class="omnibox-wrapper">
        <div class="omnibox" id="omnibox-container">
          <div class="omnibox-leading-icon">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <form id="url-form" class="url-form">
            <input id="omnibox-input" type="text" placeholder="Search DuckDuckGo or type a URL" autocomplete="off" spellcheck="false" required>
          </form>
          <div class="omnibox-trailing-icon" id="btn-bookmark" title="Bookmark this tab">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          </div>
        </div>
      </div>

      <!-- Right Menu Actions -->
      <div class="menu-controls">
        <button class="tool-btn" id="btn-menu" title="Customize and control">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>
        </button>
        <div class="chrome-menu hidden" id="chrome-dropdown">
          <div class="menu-item" id="menu-new-tab"><span>New tab</span><span class="menu-shortcut">Ctrl+T</span></div>
          <div class="menu-item" id="menu-reload"><span>Reload</span><span class="menu-shortcut">Ctrl+R</span></div>
          <div class="menu-divider"></div>
          <form method="post" action="/logout" style="margin:0;">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
            <button type="submit" class="menu-item-btn"><span>Sign out</span></button>
          </form>
        </div>
      </div>
    </div>

    <!-- Bookmarks Bar -->
    <div class="chrome-bookmarks">
      <button type="button" class="bookmark-chip" data-url="https://duckduckgo.com">
        <span class="bm-icon">🦆</span> DuckDuckGo
      </button>
      <button type="button" class="bookmark-chip" data-url="https://en.wikipedia.org">
        <span class="bm-icon">📖</span> Wikipedia
      </button>
      <button type="button" class="bookmark-chip" data-url="https://github.com">
        <span class="bm-icon">🐙</span> GitHub
      </button>
      <button type="button" class="bookmark-chip" data-url="https://discord.com">
        <span class="bm-icon">💬</span> Discord
      </button>
      <button type="button" class="bookmark-chip" data-url="https://news.ycombinator.com">
        <span class="bm-icon">🟧</span> Hacker News
      </button>
      <button type="button" class="bookmark-chip" data-url="https://reddit.com">
        <span class="bm-icon">🔴</span> Reddit
      </button>
    </div>

    <!-- Multi-Viewport Container -->
    <div class="viewports-deck" id="viewports-deck"></div>
  </div>

  <script>
  (() => {
    let tabs = [];
    let activeId = null;
    let tabIdCounter = 1;

    const tabsContainer = document.getElementById('tabs-container');
    const viewportsDeck = document.getElementById('viewports-deck');
    const omniboxInput = document.getElementById('omnibox-input');
    const urlForm = document.getElementById('url-form');
    const btnBack = document.getElementById('btn-back');
    const btnForward = document.getElementById('btn-forward');
    const btnReload = document.getElementById('btn-reload');
    const newTabBtn = document.getElementById('new-tab-btn');
    const btnMenu = document.getElementById('btn-menu');
    const chromeDropdown = document.getElementById('chrome-dropdown');

    function formatInputToUrl(input) {
      const trimmed = input.trim();
      if (!trimmed) return 'https://duckduckgo.com';
      if (/^https?:\\/\\//i.test(trimmed)) return trimmed;
      if (!/\\s/.test(trimmed) && trimmed.includes('.')) {
        return 'https://' + trimmed;
      }
      return 'https://duckduckgo.com/?q=' + encodeURIComponent(trimmed);
    }

    function extractDomain(urlStr) {
      if (!urlStr) return 'New Tab';
      try {
        const u = new URL(urlStr);
        return u.hostname || urlStr;
      } catch {
        return urlStr;
      }
    }

    function createTab(initialUrl = '') {
      const id = 'tab-' + (tabIdCounter++);
      const url = initialUrl ? formatInputToUrl(initialUrl) : '';
      const tab = {
        id: id,
        title: url ? extractDomain(url) : 'New Tab',
        url: url,
        history: url ? [url] : [],
        cursor: url ? 0 : -1,
        isLoading: false
      };

      const viewportEl = document.createElement('div');
      viewportEl.className = 'tab-viewport';
      viewportEl.id = 'viewport-' + id;

      const iframe = document.createElement('iframe');
      iframe.className = 'tab-frame';
      iframe.setAttribute('allow', 'fullscreen; clipboard-read; clipboard-write; microphone; camera; midi; encrypted-media; autodiscovery; payment');
      iframe.setAttribute('referrerpolicy', 'origin-when-cross-origin');
      
      iframe.onload = () => {
        tab.isLoading = false;
        updateToolbarState();
      };

      viewportEl.appendChild(iframe);
      viewportsDeck.appendChild(viewportEl);

      tabs.push(tab);

      if (url) {
        navigateTab(tab, url, false);
      } else {
        renderNewTabPage(viewportEl, tab);
      }

      selectTab(id);
      if (!initialUrl) {
        omniboxInput.focus();
        omniboxInput.select();
      }
    }

    function renderNewTabPage(viewportEl, tab) {
      const iframe = viewportEl.querySelector('.tab-frame');
      if (iframe) iframe.style.display = 'none';

      let ntp = viewportEl.querySelector('.ntp-container');
      if (!ntp) {
        ntp = document.createElement('div');
        ntp.className = 'ntp-container';
        ntp.innerHTML = \`
          <div class="ntp-center">
            <div class="ntp-search-box">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
              <input type="text" class="ntp-input" placeholder="Search DuckDuckGo or type a URL" autofocus>
            </div>
            <div class="ntp-grid">
              <div class="ntp-tile" data-url="https://duckduckgo.com"><div class="ntp-icon">🦆</div><div class="ntp-title">DuckDuckGo</div></div>
              <div class="ntp-tile" data-url="https://en.wikipedia.org"><div class="ntp-icon">📖</div><div class="ntp-title">Wikipedia</div></div>
              <div class="ntp-tile" data-url="https://github.com"><div class="ntp-icon">🐙</div><div class="ntp-title">GitHub</div></div>
              <div class="ntp-tile" data-url="https://discord.com"><div class="ntp-icon">💬</div><div class="ntp-title">Discord</div></div>
              <div class="ntp-tile" data-url="https://news.ycombinator.com"><div class="ntp-icon">🟧</div><div class="ntp-title">Hacker News</div></div>
              <div class="ntp-tile" data-url="https://reddit.com"><div class="ntp-icon">🔴</div><div class="ntp-title">Reddit</div></div>
            </div>
          </div>
        \`;
        viewportEl.appendChild(ntp);

        const ntpInput = ntp.querySelector('.ntp-input');
        ntpInput.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            navigateTab(tab, ntpInput.value, false);
          }
        });

        ntp.querySelectorAll('.ntp-tile').forEach((tile) => {
          tile.addEventListener('click', () => {
            const u = tile.getAttribute('data-url');
            if (u) navigateTab(tab, u, false);
          });
        });
      }
      ntp.style.display = 'flex';
    }

    function selectTab(id) {
      activeId = id;
      const activeTab = tabs.find(t => t.id === id);
      if (!activeTab) return;

      document.querySelectorAll('.tab-viewport').forEach((vp) => {
        vp.style.display = vp.id === ('viewport-' + id) ? 'block' : 'none';
      });

      omniboxInput.value = activeTab.url || '';
      renderTabs();
      updateToolbarState();
    }

    function closeTab(id) {
      const index = tabs.findIndex(t => t.id === id);
      if (index === -1) return;

      const vp = document.getElementById('viewport-' + id);
      if (vp) vp.remove();

      tabs.splice(index, 1);

      if (tabs.length === 0) {
        createTab('');
        return;
      }

      if (activeId === id) {
        const nextIndex = Math.min(index, tabs.length - 1);
        selectTab(tabs[nextIndex].id);
      } else {
        renderTabs();
      }
    }

    function navigateTab(tab, rawInput, replace = false) {
      const url = formatInputToUrl(rawInput);
      const viewportEl = document.getElementById('viewport-' + tab.id);
      if (!viewportEl) return;

      const ntp = viewportEl.querySelector('.ntp-container');
      if (ntp) ntp.style.display = 'none';

      const iframe = viewportEl.querySelector('.tab-frame');
      if (iframe) {
        iframe.style.display = 'block';
        tab.isLoading = true;
        iframe.src = '/service?url=' + encodeURIComponent(url);
      }

      tab.url = url;
      tab.title = extractDomain(url);
      if (!replace) {
        tab.history = tab.history.slice(0, tab.cursor + 1);
        tab.history.push(url);
        tab.cursor = tab.history.length - 1;
      }

      if (tab.id === activeId) {
        omniboxInput.value = url;
      }

      renderTabs();
      updateToolbarState();
    }

    function renderTabs() {
      tabsContainer.innerHTML = '';
      tabs.forEach((tab) => {
        const tabEl = document.createElement('div');
        tabEl.className = 'chrome-tab' + (tab.id === activeId ? ' active' : '');
        tabEl.title = tab.title;

        tabEl.innerHTML = \`
          <div class="tab-favicon">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          </div>
          <span class="tab-label">\${escapeHtml(tab.title)}</span>
          <button class="tab-close-btn" type="button" title="Close tab">&times;</button>
        \`;

        tabEl.addEventListener('click', (e) => {
          if (!e.target.classList.contains('tab-close-btn')) {
            selectTab(tab.id);
          }
        });

        const closeBtn = tabEl.querySelector('.tab-close-btn');
        closeBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          closeTab(tab.id);
        });

        tabEl.addEventListener('auxclick', (e) => {
          if (e.button === 1) {
            e.preventDefault();
            closeTab(tab.id);
          }
        });

        tabsContainer.appendChild(tabEl);
      });
    }

    function updateToolbarState() {
      const tab = tabs.find(t => t.id === activeId);
      if (!tab) return;

      btnBack.disabled = tab.cursor <= 0;
      btnForward.disabled = tab.cursor >= tab.history.length - 1;
    }

    function escapeHtml(str) {
      return (str || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] || c);
    }

    newTabBtn.addEventListener('click', () => createTab(''));

    urlForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const tab = tabs.find(t => t.id === activeId);
      if (tab) {
        navigateTab(tab, omniboxInput.value, false);
      }
    });

    omniboxInput.addEventListener('focus', () => omniboxInput.select());

    btnBack.addEventListener('click', () => {
      const tab = tabs.find(t => t.id === activeId);
      if (!tab || tab.cursor <= 0) return;
      tab.cursor--;
      navigateTab(tab, tab.history[tab.cursor], true);
    });

    btnForward.addEventListener('click', () => {
      const tab = tabs.find(t => t.id === activeId);
      if (!tab || tab.cursor >= tab.history.length - 1) return;
      tab.cursor++;
      navigateTab(tab, tab.history[tab.cursor], true);
    });

    btnReload.addEventListener('click', () => {
      const tab = tabs.find(t => t.id === activeId);
      if (tab && tab.url) {
        navigateTab(tab, tab.url, true);
      }
    });

    btnMenu.addEventListener('click', (e) => {
      e.stopPropagation();
      chromeDropdown.classList.toggle('hidden');
    });

    document.addEventListener('click', () => {
      chromeDropdown.classList.add('hidden');
    });

    document.getElementById('menu-new-tab').addEventListener('click', () => {
      createTab('');
      chromeDropdown.classList.add('hidden');
    });

    document.getElementById('menu-reload').addEventListener('click', () => {
      const tab = tabs.find(t => t.id === activeId);
      if (tab && tab.url) navigateTab(tab, tab.url, true);
      chromeDropdown.classList.add('hidden');
    });

    document.querySelectorAll('.bookmark-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        const u = chip.getAttribute('data-url');
        if (u) {
          const tab = tabs.find(t => t.id === activeId);
          if (tab) navigateTab(tab, u, false);
        }
      });
    });

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 't') {
        e.preventDefault();
        createTab('');
      } else if ((e.ctrlKey || e.metaKey) && e.key === 'w') {
        e.preventDefault();
        if (activeId) closeTab(activeId);
      } else if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'e')) {
        e.preventDefault();
        omniboxInput.focus();
        omniboxInput.select();
      } else if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
        e.preventDefault();
        const tab = tabs.find(t => t.id === activeId);
        if (tab && tab.url) navigateTab(tab, tab.url, true);
      }
    });

    window.addEventListener('message', (event) => {
      if (!event.data) return;
      if (event.data.type === 'client_navigated') {
        const tab = tabs.find(t => t.id === activeId);
        if (tab && event.data.url) {
          tab.url = event.data.url;
          if (event.data.title) tab.title = event.data.title;
          if (tab.history[tab.cursor] !== event.data.url) {
            tab.history = tab.history.slice(0, tab.cursor + 1);
            tab.history.push(event.data.url);
            tab.cursor = tab.history.length - 1;
          }
          if (tab.id === activeId) {
            omniboxInput.value = tab.url;
          }
          renderTabs();
          updateToolbarState();
        }
      } else if (event.data.type === 'client_open_tab' && event.data.url) {
        createTab(event.data.url);
      }
    });

    createTab('https://duckduckgo.com');
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
      --cr-bg: #202124;
      --cr-tabstrip-bg: #1f1f23;
      --cr-toolbar-bg: #28292a;
      --cr-omnibox-bg: #1e1f22;
      --cr-omnibox-focus-bg: #17181a;
      --cr-tab-active-bg: #28292a;
      --cr-tab-hover-bg: #262729;
      --cr-text-primary: #e8eaed;
      --cr-text-secondary: #9aa0a6;
      --cr-border: #3c4043;
      --cr-btn-hover: #35363a;
      --cr-btn-active: #3c4043;
      --cr-accent: #8ab4f8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Roboto, -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      background: var(--cr-bg);
      color: var(--cr-text-primary);
      height: 100vh;
      overflow: hidden;
      user-select: none;
      -webkit-font-smoothing: antialiased;
    }

    .login-wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      width: 100vw;
      background: #0a0a0a;
    }
    .login-modal {
      background: #171717;
      border: 1px solid #262626;
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
      background: #1f1f1f;
      border: 1px solid #262626;
      border-radius: 6px;
      color: #ededed;
      font-size: 14px;
      transition: border-color 0.15s, background 0.15s;
    }
    .login-modal input:focus {
      outline: none;
      border-color: #404040;
      background: #242424;
    }
    .login-modal input::placeholder {
      color: #737373;
    }
    .btn-primary {
      width: 100%;
      padding: 12px;
      background: #222222;
      border: 1px solid #262626;
      color: #ededed;
      border-radius: 6px;
      font-weight: 500;
      font-size: 14px;
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s;
      margin-top: 4px;
    }
    .btn-primary:hover {
      background: #2e2e2e;
      border-color: #404040;
    }

    .chrome-window {
      display: flex;
      flex-direction: column;
      height: 100vh;
      background: var(--cr-toolbar-bg);
    }

    .chrome-tabstrip {
      display: flex;
      align-items: flex-end;
      height: 40px;
      background: var(--cr-tabstrip-bg);
      padding: 6px 8px 0 8px;
      position: relative;
    }
    .tabs-container {
      display: flex;
      gap: 2px;
      overflow-x: auto;
      flex: 1;
      height: 100%;
      scrollbar-width: none;
    }
    .tabs-container::-webkit-scrollbar { display: none; }
    .chrome-tab {
      display: flex;
      align-items: center;
      gap: 8px;
      height: 34px;
      min-width: 140px;
      max-width: 240px;
      padding: 0 10px 0 12px;
      border-radius: 8px 8px 0 0;
      background: transparent;
      color: var(--cr-text-secondary);
      font-size: 12px;
      cursor: pointer;
      position: relative;
      transition: background 0.1s, color 0.1s;
    }
    .chrome-tab:hover:not(.active) {
      background: var(--cr-tab-hover-bg);
      color: var(--cr-text-primary);
    }
    .chrome-tab.active {
      background: var(--cr-tab-active-bg);
      color: var(--cr-text-primary);
      font-weight: 500;
    }
    .tab-favicon {
      display: flex;
      align-items: center;
      justify-content: center;
      opacity: 0.8;
      flex-shrink: 0;
    }
    .tab-label {
      flex: 1;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-size: 12px;
    }
    .tab-close-btn {
      background: transparent;
      border: none;
      color: var(--cr-text-secondary);
      cursor: pointer;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
      line-height: 1;
      opacity: 0.7;
    }
    .tab-close-btn:hover {
      background: #474a4f;
      color: #fff;
      opacity: 1;
    }
    .new-tab-btn {
      background: transparent;
      border: none;
      color: var(--cr-text-secondary);
      width: 28px;
      height: 28px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      margin-left: 6px;
      margin-bottom: 3px;
    }
    .new-tab-btn:hover {
      background: var(--cr-btn-hover);
      color: var(--cr-text-primary);
    }

    .window-controls {
      display: flex;
      align-items: center;
      margin-left: auto;
      height: 100%;
      margin-bottom: 4px;
    }
    .win-btn {
      width: 38px;
      height: 28px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      color: var(--cr-text-secondary);
      cursor: pointer;
    }
    .win-btn:hover { background: var(--cr-btn-hover); color: #fff; }
    .win-close:hover { background: #e81123; color: #fff; }

    .chrome-toolbar {
      display: flex;
      align-items: center;
      height: 44px;
      background: var(--cr-toolbar-bg);
      padding: 0 8px;
      gap: 6px;
      border-bottom: 1px solid #1e1f22;
    }
    .nav-controls {
      display: flex;
      align-items: center;
      gap: 2px;
    }
    .tool-btn {
      background: transparent;
      border: none;
      color: var(--cr-text-secondary);
      width: 28px;
      height: 28px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background 0.1s, color 0.1s;
    }
    .tool-btn:hover:not(:disabled) {
      background: var(--cr-btn-hover);
      color: var(--cr-text-primary);
    }
    .tool-btn:disabled {
      opacity: 0.3;
      cursor: default;
    }

    .omnibox-wrapper {
      flex: 1;
      display: flex;
      align-items: center;
    }
    .omnibox {
      display: flex;
      align-items: center;
      width: 100%;
      height: 32px;
      background: var(--cr-omnibox-bg);
      border-radius: 20px;
      padding: 0 12px;
      transition: background 0.15s, box-shadow 0.15s;
    }
    .omnibox:focus-within {
      background: var(--cr-omnibox-focus-bg);
      box-shadow: 0 0 0 2px var(--cr-accent);
    }
    .omnibox-leading-icon {
      color: var(--cr-text-secondary);
      display: flex;
      align-items: center;
      margin-right: 8px;
      opacity: 0.8;
    }
    .url-form {
      flex: 1;
      display: flex;
      align-items: center;
    }
    #omnibox-input {
      width: 100%;
      background: transparent;
      border: none;
      color: var(--cr-text-primary);
      font-size: 13px;
      outline: none;
      font-family: inherit;
    }
    #omnibox-input::placeholder {
      color: var(--cr-text-secondary);
    }
    .omnibox-trailing-icon {
      color: var(--cr-text-secondary);
      display: flex;
      align-items: center;
      cursor: pointer;
      padding: 4px;
      border-radius: 50%;
    }
    .omnibox-trailing-icon:hover { color: #fff; }

    .menu-controls {
      position: relative;
    }
    .chrome-menu {
      position: absolute;
      top: 36px;
      right: 0;
      background: #28292a;
      border: 1px solid var(--cr-border);
      border-radius: 8px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.6);
      width: 220px;
      padding: 6px 0;
      z-index: 1000;
    }
    .chrome-menu.hidden { display: none; }
    .menu-item, .menu-item-btn {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 8px 16px;
      background: transparent;
      border: none;
      color: var(--cr-text-primary);
      font-size: 13px;
      cursor: pointer;
      text-align: left;
      font-family: inherit;
    }
    .menu-item:hover, .menu-item-btn:hover {
      background: var(--cr-btn-hover);
    }
    .menu-shortcut {
      color: var(--cr-text-secondary);
      font-size: 11px;
    }
    .menu-divider {
      height: 1px;
      background: var(--cr-border);
      margin: 4px 0;
    }

    .chrome-bookmarks {
      display: flex;
      align-items: center;
      height: 30px;
      background: var(--cr-toolbar-bg);
      padding: 0 8px;
      gap: 4px;
      border-bottom: 1px solid #1c1d1f;
      overflow-x: auto;
      scrollbar-width: none;
    }
    .chrome-bookmarks::-webkit-scrollbar { display: none; }
    .bookmark-chip {
      display: flex;
      align-items: center;
      gap: 6px;
      background: transparent;
      border: none;
      color: var(--cr-text-secondary);
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 11.5px;
      cursor: pointer;
      white-space: nowrap;
    }
    .bookmark-chip:hover {
      background: var(--cr-btn-hover);
      color: var(--cr-text-primary);
    }
    .bm-icon { font-size: 12px; }

    .viewports-deck {
      flex: 1;
      width: 100%;
      position: relative;
      background: #000;
    }
    .tab-viewport {
      width: 100%;
      height: 100%;
      display: none;
      position: relative;
    }
    .tab-frame {
      width: 100%;
      height: 100%;
      border: none;
      display: block;
      background: #fff;
    }

    .ntp-container {
      width: 100%;
      height: 100%;
      background: #202124;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      user-select: none;
    }
    .ntp-center {
      width: 100%;
      max-width: 560px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 28px;
      margin-top: -60px;
    }
    .ntp-search-box {
      display: flex;
      align-items: center;
      width: 100%;
      height: 48px;
      background: #303134;
      border-radius: 24px;
      padding: 0 18px;
      box-shadow: 0 1px 6px rgba(0,0,0,0.28);
      gap: 12px;
      color: var(--cr-text-secondary);
    }
    .ntp-search-box:focus-within {
      background: #3c4043;
      box-shadow: 0 2px 8px rgba(0,0,0,0.4);
    }
    .ntp-input {
      flex: 1;
      background: transparent;
      border: none;
      color: #fff;
      font-size: 15px;
      outline: none;
      font-family: inherit;
    }
    .ntp-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      width: 100%;
    }
    .ntp-tile {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      padding: 12px;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.15s;
    }
    .ntp-tile:hover {
      background: #303134;
    }
    .ntp-icon {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      background: #3c4043;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
    }
    .ntp-title {
      font-size: 12px;
      color: var(--cr-text-primary);
      text-align: center;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      width: 100%;
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
        } catch {}
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
  decodeHtmlEntities,
  rewriteCss,
  rewriteSrcset,
  extractTargetFromPath,
};
