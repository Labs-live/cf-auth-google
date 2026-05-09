import { describe, expect, it } from "vitest";
import { buildAuthorizeUrl, exchangeCode, generatePkce, generateState } from "../src/oauth";

describe("oauth helpers", () => {
  it("buildAuthorizeUrl includes required params", () => {
    const url = new URL(
      buildAuthorizeUrl({
        clientId: "id",
        redirectUri: "https://app.example/auth/callback",
        state: "S",
        codeChallenge: "C",
      }),
    );
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("client_id")).toBe("id");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example/auth/callback");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toContain("openid");
  });

  it("generatePkce produces base64url-safe verifier and SHA-256 challenge of length 43", async () => {
    const { verifier, challenge } = await generatePkce();
    expect(verifier.length).toBeGreaterThan(40);
    expect(challenge.length).toBe(43);
    expect(verifier).not.toMatch(/[+/=]/);
    expect(challenge).not.toMatch(/[+/=]/);
  });

  it("generateState yields a non-trivial random string", () => {
    const a = generateState();
    const b = generateState();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThan(10);
  });

  it("exchangeCode posts form-encoded body and parses response", async () => {
    let captured: { url: string; method: string; body: string; ct: string } | null = null;
    const fakeFetch: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      captured = {
        url,
        method: (init?.method ?? "GET") as string,
        body: (init?.body ?? "") as string,
        ct: (init?.headers as Record<string, string>)?.["Content-Type"] ?? "",
      };
      return new Response(JSON.stringify({ id_token: "eyJ", access_token: "at", expires_in: 3599 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const tokens = await exchangeCode(
      { clientId: "id", clientSecret: "sec", redirectUri: "https://x/cb", code: "abc", codeVerifier: "ver" },
      fakeFetch,
    );
    expect(tokens.id_token).toBe("eyJ");
    expect(captured!.url).toBe("https://oauth2.googleapis.com/token");
    expect(captured!.method).toBe("POST");
    expect(captured!.ct).toBe("application/x-www-form-urlencoded");
    const params = new URLSearchParams(captured!.body);
    expect(params.get("code")).toBe("abc");
    expect(params.get("code_verifier")).toBe("ver");
    expect(params.get("grant_type")).toBe("authorization_code");
  });

  it("exchangeCode throws AuthError on non-2xx", async () => {
    const fakeFetch: typeof fetch = async () => new Response("nope", { status: 400 });
    const { AuthError } = await import("../src/idtoken");
    try {
      await exchangeCode({ clientId: "i", clientSecret: "s", redirectUri: "r", code: "c", codeVerifier: "v" }, fakeFetch);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AuthError);
      expect((e as AuthErrorLike).code).toBe("token_exchange_failed");
    }
  });
});

type AuthErrorLike = { code: string; message: string };

describe("noop", () => {
  it("type-only helper", () => {
    expect(true).toBe(true);
  });
});
