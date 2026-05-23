import { describe, expect, it } from "vitest";
import { issue, verify, b64urlEncode, b64urlDecode } from "../src/session";

const SECRET = "test-secret-32-chars-long-aaaaaaa";

describe("session cookie", () => {
  it("issues and verifies a valid session", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = await issue({ email: "kryklia@gmail.com", profile: "oleksandr", exp }, SECRET);
    const got = await verify(token, SECRET);
    expect(got).toEqual({ email: "kryklia@gmail.com", profile: "oleksandr", exp });
  });

  it("rejects when the secret differs", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = await issue({ email: "x@x", profile: "p", exp }, SECRET);
    expect(await verify(token, "different-secret-32-chars-aaaaaa")).toBeNull();
  });

  it("rejects when the payload was tampered with", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = await issue({ email: "x@x", profile: "p", exp }, SECRET);
    const [, sig] = token.split(".");
    const evilPayload = b64urlEncode(new TextEncoder().encode(JSON.stringify({ email: "x@x", profile: "admin", exp })));
    expect(await verify(`${evilPayload}.${sig}`, SECRET)).toBeNull();
  });

  it("rejects expired tokens", async () => {
    const exp = Math.floor(Date.now() / 1000) - 1;
    const token = await issue({ email: "x@x", profile: "p", exp }, SECRET);
    expect(await verify(token, SECRET)).toBeNull();
  });

  it("rejects malformed tokens", async () => {
    expect(await verify("garbage", SECRET)).toBeNull();
    expect(await verify("just.one.dot.too.many", SECRET)).toBeNull();
  });

  it("base64url roundtrip preserves bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(Array.from(b64urlDecode(b64urlEncode(bytes)))).toEqual(Array.from(bytes));
  });
});
