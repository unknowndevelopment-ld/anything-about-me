interface Env {
  PROXY_USERNAME: string;
  PROXY_PASSWORD: string;
  SESSION_SECRET: string;
  UPSTREAM_ALLOWLIST: string;
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
        JSON.stringify({
          status: "environment_check",
          configured: {
            PROXY_USERNAME: hasUsername,
            PROXY_PASSWORD: hasPassword,
            SESSION_SECRET: hasSecret,
            UPSTREAM_ALLOWLIST: hasAllowlist,
          },
          message: hasUsername && hasPassword && hasSecret ? "All required variables are set" : "Missing required environment variables",
        }, null, 2),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    if (url.pathname === "/login") {
      return handleLogin(request, env);
    }

    const session = await readSession(request, env.SESSION_SECRET);
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

    if (url.pathname === "/proxy" && request.method === "GET") {
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
      { status: 503, headers: { "Content-Type": "text/plain" } }
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
    return new Response("A proxy target is required.", { status: 400 });
  }

  const validatedTarget = validateTarget(target, env.UPSTREAM_ALLOWLIST);
  if (!validatedTarget) {
    return accessDeniedResponse();
  }

  try {
    const upstreamResponse = await fetch(validatedTarget, {
      method: "GET",
      redirect: "manual",
      headers: {
        Accept: request.headers.get("Accept") ?? "*/*",
        "User-Agent": "authenticated-worker-proxy",
      },
    });
    const headers = new Headers(upstreamResponse.headers);
    headers.delete("Content-Security-Policy");
    headers.delete("X-Frame-Options");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Content-Security-Policy", "frame-ancestors 'self'");
    const location = upstreamResponse.headers.get("Location");
    if (location && upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
      const redirectedTarget = validateTarget(new URL(location, validatedTarget).toString(), env.UPSTREAM_ALLOWLIST);
      if (redirectedTarget) {
        headers.set("Location", `/proxy?url=${encodeURIComponent(redirectedTarget)}`);
      } else {
        headers.delete("Location");
      }
    }
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers,
    });
  } catch {
    return new Response("The upstream could not be reached.", { status: 502 });
  }
}

function parseAllowlist(allowlist: string): URL[] {
  if (allowlistCache.has(allowlist)) {
    return allowlistCache.get(allowlist)!;
  }

  const entries: URL[] = [];
  for (const entry of allowlist.split(/[\n,]/)) {
    const trimmed = entry.trim();
    if (trimmed) {
      try {
        entries.push(new URL(trimmed));
      } catch {
        // Invalid allowlist entries do not grant access.
      }
    }
  }

  allowlistCache.set(allowlist, entries);
  return entries;
}

function validateTarget(rawTarget: string, allowlist: string): string | null {
  let target: URL;
  try {
    target = new URL(rawTarget);
  } catch {
    return null;
  }

  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.username ||
    target.password ||
    target.hash ||
    isBlockedHostname(target.hostname)
  ) {
    return null;
  }

  const entries = parseAllowlist(allowlist);
  for (const allowed of entries) {
    if (
      allowed.protocol === target.protocol &&
      allowed.hostname === target.hostname &&
      allowed.port === target.port &&
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
  const envStatus = !env.PROXY_USERNAME || !env.PROXY_PASSWORD || !env.SESSION_SECRET
    ? `<div style="background:#f8d7da;border:1px solid #f5c6cb;color:#721c24;padding:12px;margin-bottom:16px;border-radius:4px;"><strong>⚠️ Configuration Error:</strong> Missing environment secrets. Set them with: <code>npx wrangler secret put PROXY_USERNAME</code>, <code>npx wrangler secret put PROXY_PASSWORD</code>, <code>npx wrangler secret put SESSION_SECRET</code></div>`
    : "";

  return page("Sign in", `${envStatus}<div class="login-modal" role="dialog" aria-modal="true" aria-labelledby="login-title">
    <h2 id="login-title">Sign in to the proxy</h2>
    <p>Your secure session lasts 24 hours. You will be asked to sign in again after it expires or when you sign out.</p>
    <form method="post" action="/login">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <label>Username <input name="username" autocomplete="username" required autofocus></label>
      <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
      <button type="submit">Sign in</button>
    </form>
  </div>`);
}

function homePage(csrf: string): string {
  return page("Authenticated Worker Proxy", `<div class="browser" aria-label="Browser-like proxy">
    <div class="toolbar">
      <button class="icon-button" id="back" type="button" title="Back" aria-label="Back">&larr;</button>
      <button class="icon-button" id="forward" type="button" title="Forward" aria-label="Forward">&rarr;</button>
      <button class="icon-button" id="refresh" type="button" title="Refresh" aria-label="Refresh">&#8635;</button>
      <form id="address-form" class="address-form">
        <label class="sr-only" for="address">Address</label>
        <input id="address" type="url" placeholder="https://approved.example/path" autocomplete="off" required>
        <button type="submit">Go</button>
      </form>
      <form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit">Sign out</button></form>
    </div>
    <div class="tabs" role="tablist" aria-label="Proxy tabs">
      <button id="new-tab" class="new-tab" type="button" title="New tab" aria-label="New tab">+</button>
    </div>
    <div class="browser-status">Only explicitly approved upstreams can be opened.</div>
    <iframe id="viewport" title="Proxy browser viewport" sandbox="allow-forms allow-scripts" referrerpolicy="no-referrer"></iframe>
  </div>
  <script>
  (() => {
    const tabs = [];
    let active = -1;
    const tabBar = document.querySelector('.tabs');
    const viewport = document.getElementById('viewport');
    const address = document.getElementById('address');
    const form = document.getElementById('address-form');
    const back = document.getElementById('back');
    const forward = document.getElementById('forward');
    const refresh = document.getElementById('refresh');
    const newTab = document.getElementById('new-tab');

    function updateTabButton(index, tab) {
      const existingButton = tabBar.querySelector(\`[data-tab="\${index}"]\`);
      if (existingButton) {
        existingButton.className = index === active ? 'tab active' : 'tab';
        existingButton.textContent = tab.title || 'New tab';
      } else {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.tab = String(index);
        button.className = index === active ? 'tab active' : 'tab';
        button.textContent = tab.title || 'New tab';
        button.onclick = () => selectTab(index);
        tabBar.insertBefore(button, newTab);
      }
    }

    function renderTabs() {
      tabs.forEach((tab, index) => updateTabButton(index, tab));
    }

    function selectTab(index) {
      active = index;
      const tab = tabs[active];
      address.value = tab.url;
      viewport.src = tab.url ? '/proxy?url=' + encodeURIComponent(tab.url) : 'about:blank';
      renderTabs();
      updateButtons();
    }

    function addTab() {
      tabs.push({ title: 'New tab', url: '', history: [], cursor: -1 });
      selectTab(tabs.length - 1);
      address.focus();
    }

    function navigate(value, replace) {
      let parsed;
      try { parsed = new URL(value); } catch { alert('Enter a complete http or https URL.'); return; }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        alert('Only http and https URLs are supported.'); return;
      }
      const tab = tabs[active];
      tab.url = parsed.toString();
      tab.title = parsed.hostname;
      if (!replace) {
        tab.history = tab.history.slice(0, tab.cursor + 1);
        tab.history.push(tab.url);
        tab.cursor = tab.history.length - 1;
      }
      address.value = tab.url;
      viewport.src = '/proxy?url=' + encodeURIComponent(tab.url);
      renderTabs();
      updateButtons();
    }

    function updateButtons() {
      const tab = tabs[active];
      back.disabled = !tab || tab.cursor <= 0;
      forward.disabled = !tab || tab.cursor >= tab.history.length - 1;
    }

    form.addEventListener('submit', (event) => { event.preventDefault(); navigate(address.value, false); });
    back.addEventListener('click', () => {
      const tab = tabs[active]; if (!tab || tab.cursor <= 0) return;
      tab.cursor -= 1; tab.url = tab.history[tab.cursor]; selectTab(active);
    });
    forward.addEventListener('click', () => {
      const tab = tabs[active]; if (!tab || tab.cursor >= tab.history.length - 1) return;
      tab.cursor += 1; tab.url = tab.history[tab.cursor]; selectTab(active);
    });
    refresh.addEventListener('click', () => { if (tabs[active] && tabs[active].url) navigate(tabs[active].url, true); });
    newTab.addEventListener('click', addTab);
    addTab();
  })();
  </script>`);
}

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font:16px system-ui,sans-serif;margin:0;padding:16px;background:#f5f5f5}.login-modal{background:white;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1);padding:32px;max-width:400px;margin:0 auto}h2{margin-top:0}.browser{display:flex;flex-direction:column;height:100vh;background:white;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1);overflow:hidden}.toolbar{display:flex;align-items:center;gap:8px;padding:8px;background:#f0f0f0;border-bottom:1px solid #ddd}.icon-button{padding:8px;background:white;border:1px solid #ddd;border-radius:4px;cursor:pointer}.icon-button:hover{background:#f9f9f9}.address-form{display:flex;flex:1;gap:8px}#address{flex:1;padding:8px;border:1px solid #ddd;border-radius:4px;font-family:monospace}.tabs{display:flex;gap:4px;padding:8px;background:#f9f9f9;border-bottom:1px solid #ddd;align-items:center;overflow-x:auto}.tab{padding:8px 12px;background:white;border:1px solid #ddd;border-radius:4px 4px 0 0;cursor:pointer}.tab.active{background:white;border-bottom-color:white;font-weight:bold}.new-tab{padding:8px 12px;background:white;border:1px solid #ddd;border-radius:4px;cursor:pointer}.browser-status{padding:8px 16px;background:#fff3cd;border-bottom:1px solid #ffc107;font-size:14px}#viewport{flex:1;border:none;width:100%}label{display:block;margin:16px 0}input{width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:16px;box-sizing:border-box}button[type=submit]{padding:8px 16px;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer}button[type=submit]:hover{background:#0056b3}code{background:#f4f4f4;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:12px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0}</style></head><body>${body}</body></html>`;
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
      // Store the decoded value as-is (already stored URL-encoded in cookie)
      if (value) {
        try {
          cookies.set(name, decodeURIComponent(value));
        } catch {
          // Ignore malformed cookie values.
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
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character);
}

export { validateTarget, isBlockedHostname, accessDeniedResponse, serializeCookie };
