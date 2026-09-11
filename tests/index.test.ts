import { describe, expect, it } from "vitest";
import worker, {
  accessDeniedResponse,
  decodeHtmlEntities,
  extractTargetFromPath,
  isBlockedHostname,
  resolveProxiedUrl,
  rewriteCss,
  rewriteSrcset,
  serializeCookie,
  validateTarget,
} from "../src/index";

describe("target validation and path extraction", () => {
  it("allows all public websites by default or when wildcard is set", () => {
    expect(validateTarget("https://api.example.test/data", "")).toBe("https://api.example.test/data");
    expect(validateTarget("https://api.example.test/data", "*")).toBe("https://api.example.test/data");
    expect(validateTarget("https://api.example.test/data", "all")).toBe("https://api.example.test/data");
    expect(validateTarget("example.com", "*")).toBe("https://example.com/");
  });

  it("extracts direct target URLs from pathnames", () => {
    expect(extractTargetFromPath("/discord.com/login", "")).toBe("https://discord.com/login");
    expect(extractTargetFromPath("/https://discord.com/login", "")).toBe("https://discord.com/login");
    expect(extractTargetFromPath("/https:/discord.com/login", "")).toBe("https://discord.com/login");
    expect(extractTargetFromPath("/en.wikipedia.org/wiki/Main_Page", "?lang=en")).toBe(
      "https://en.wikipedia.org/wiki/Main_Page?lang=en",
    );
    expect(extractTargetFromPath("/login", "")).toBeNull();
    expect(extractTargetFromPath("/logout", "")).toBeNull();
  });

  it("supports explicit allowlist restrictions when specified", () => {
    expect(validateTarget("https://api.example.test/data", "https://api.example.test")).toBe(
      "https://api.example.test/data",
    );
    expect(validateTarget("https://other.example.test/data", "https://api.example.test")).toBeNull();
  });

  it("rejects unsafe protocols, credentials, and private hosts", () => {
    expect(validateTarget("file:///etc/passwd", "*")).toBeNull();
    expect(validateTarget("https://user:pass@api.example.test", "*")).toBeNull();
    expect(validateTarget("http://127.0.0.1/admin", "*")).toBeNull();
    expect(validateTarget("http://localhost:8080", "*")).toBeNull();
    expect(validateTarget("http://192.168.1.1", "*")).toBeNull();
    expect(validateTarget("http://10.0.0.1", "*")).toBeNull();
    expect(isBlockedHostname("169.254.169.254")).toBe(true);
    expect(isBlockedHostname("metadata.google.internal")).toBe(true);
    expect(isBlockedHostname("::1")).toBe(true);
  });

  it("returns a plain denial for invalid credentials", async () => {
    const denied = accessDeniedResponse();
    expect(denied.status).toBe(403);
    expect(denied.headers.get("Content-Type")).toContain("text/plain");
    expect(await denied.text()).toBe("403 Forbidden");
  });

  it("only marks cookies Secure when the request is HTTPS", () => {
    expect(serializeCookie("session", "value", 60, true, new Request("http://localhost/"))).not.toContain(
      "; Secure",
    );
    expect(serializeCookie("session", "value", 60, true, new Request("https://portal.example/"))).toContain(
      "; Secure",
    );
  });
});

describe("URL and asset rewriting", () => {
  it("decodes HTML entities in URLs and attributes", () => {
    expect(decodeHtmlEntities("https://preview.redd.it/test.jpg?width=640&amp;crop=smart&amp;s=abc123")).toBe(
      "https://preview.redd.it/test.jpg?width=640&crop=smart&s=abc123",
    );
    expect(decodeHtmlEntities("&quot;test&quot; &lt;tag&gt; &#39;quote&#39;")).toBe('"test" <tag> \'quote\'');
  });

  it("resolves relative and absolute URLs through service endpoint including Reddit images", () => {
    expect(resolveProxiedUrl("/about", "https://example.com/sub/page")).toBe(
      "/service?url=https%3A%2F%2Fexample.com%2Fabout",
    );
    expect(resolveProxiedUrl("details.html", "https://example.com/sub/page")).toBe(
      "/service?url=https%3A%2F%2Fexample.com%2Fsub%2Fdetails.html",
    );
    expect(resolveProxiedUrl("https://other.com/image.png", "https://example.com")).toBe(
      "/service?url=https%3A%2F%2Fother.com%2Fimage.png",
    );
    expect(resolveProxiedUrl("#section", "https://example.com")).toBe("#section");
    expect(resolveProxiedUrl("javascript:void(0)", "https://example.com")).toBe("javascript:void(0)");

    // Reddit encoded image URLs
    const rawRedditImg = "https://preview.redd.it/sample.png?width=960&amp;crop=smart&amp;format=pjpg&amp;auto=webp&amp;s=abcdef123456";
    const resolvedRedditImg = resolveProxiedUrl(rawRedditImg, "https://reddit.com");
    expect(resolvedRedditImg).toBe(
      "/service?url=https%3A%2F%2Fpreview.redd.it%2Fsample.png%3Fwidth%3D960%26crop%3Dsmart%26format%3Dpjpg%26auto%3Dwebp%26s%3Dabcdef123456",
    );
  });

  it("rewrites srcset attributes correctly", () => {
    const srcset = "small.jpg 300w, large.jpg 800w";
    const rewritten = rewriteSrcset(srcset, "https://example.com/");
    expect(rewritten).toContain("/service?url=https%3A%2F%2Fexample.com%2Fsmall.jpg 300w");
    expect(rewritten).toContain("/service?url=https%3A%2F%2Fexample.com%2Flarge.jpg 800w");
  });

  it("rewrites CSS url() and @import statements", () => {
    const css = 'body { background: url("bg.jpg"); } @import "theme.css";';
    const rewritten = rewriteCss(css, "https://example.com/style/");
    expect(rewritten).toContain('url("/service?url=https%3A%2F%2Fexample.com%2Fstyle%2Fbg.jpg")');
    expect(rewritten).toContain('@import "/service?url=https%3A%2F%2Fexample.com%2Fstyle%2Ftheme.css"');
  });
});

describe("fetch handling and diagnostics", () => {
  const env = {
    PROXY_USERNAME: "admin",
    PROXY_PASSWORD: "secretpassword123",
    SESSION_SECRET: "test-super-secret-key-32-bytes-long!",
    UPSTREAM_ALLOWLIST: "*",
  };

  it("responds to /.well-known/config", async () => {
    const res = await worker.fetch(new Request("http://localhost/.well-known/config"), env);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { status: string; message: string };
    expect(json.status).toBe("environment_check");
    expect(json.message).toBe("All required variables are set");
  });

  it("serves minimalist anonymous login page for unauthenticated GET /", async () => {
    const res = await worker.fetch(new Request("http://localhost/"), env);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain("proxy");
    expect(html).not.toContain("Proxy");
    expect(html).toContain('placeholder="Username"');
    expect(html).toContain('placeholder="Password"');
    expect(html).toContain('name="csrf"');
  });

  it("rejects unauthenticated non-html requests with 401", async () => {
    const res = await worker.fetch(
      new Request("http://localhost/service?url=https://example.com", {
        headers: { Accept: "application/json" },
      }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("rewrites redirects safely to proxy format", () => {
    const rawRedirect = "https://discord.com/login";
    const validated = validateTarget(rawRedirect, "*");
    expect(validated).toBe("https://discord.com/login");
    const proxiedLocation = `/service?url=${encodeURIComponent(validated!)}`;
    expect(proxiedLocation).toBe("/service?url=https%3A%2F%2Fdiscord.com%2Flogin");
  });
});
