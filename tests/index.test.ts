import { describe, expect, it } from "vitest";
import { accessDeniedResponse, isBlockedHostname, validateTarget } from "../src/index";

describe("proxy target validation", () => {
  it("requires an explicit allowlist entry", () => {
    expect(validateTarget("https://api.example.test/data", "")).toBeNull();
    expect(validateTarget("https://api.example.test/data", "https://api.example.test")).toBe(
      "https://api.example.test/data",
    );
  });

  it("rejects unsafe protocols, credentials, and private hosts", () => {
    expect(validateTarget("file:///etc/passwd", "file:///")).toBeNull();
    expect(validateTarget("https://user:pass@api.example.test", "https://api.example.test")).toBeNull();
    expect(validateTarget("http://127.0.0.1/admin", "http://127.0.0.1")).toBeNull();
    expect(isBlockedHostname("169.254.169.254")).toBe(true);
  });

  it("returns a plain denial for invalid credentials", async () => {
    const denied = accessDeniedResponse();
    expect(denied.status).toBe(403);
    expect(denied.headers.get("Content-Type")).toContain("text/plain");
    expect(await denied.text()).toBe("403 Access Denied");
  });
});
