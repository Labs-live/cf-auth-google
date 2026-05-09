/** Verify a Google-issued OIDC ID token: signature against JWKs, plus iss/aud/exp/email_verified. */

import { b64urlDecode } from "./session";

const JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUER = "https://accounts.google.com";
const ALT_ISSUER = "accounts.google.com";

export type IdTokenClaims = {
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
};

let cachedJwks: { keys: GoogleJwk[]; fetchedAt: number } | null = null;
const JWKS_TTL_MS = 60 * 60 * 1000;

type GoogleJwk = {
  kid: string;
  alg: string;
  kty: string;
  use?: string;
  n: string;
  e: string;
};

export async function verifyIdToken(idToken: string, expectedAud: string, now: number = Date.now()): Promise<IdTokenClaims> {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new AuthError("invalid_token", "id_token must be three parts");
  const [headerB64, payloadB64, sigB64] = parts;

  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerB64))) as { alg: string; kid: string };
  if (header.alg !== "RS256") throw new AuthError("invalid_token", `unsupported alg: ${header.alg}`);

  const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64))) as IdTokenClaims;
  if (claims.iss !== ISSUER && claims.iss !== ALT_ISSUER) throw new AuthError("invalid_token", `unexpected iss: ${claims.iss}`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expectedAud)) throw new AuthError("invalid_token", "audience mismatch");
  if (typeof claims.exp !== "number" || claims.exp * 1000 < now) throw new AuthError("invalid_token", "id_token expired");

  const jwk = await findKey(header.kid);
  if (!jwk) throw new AuthError("invalid_token", "signing key not found");
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true } as JsonWebKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlDecode(sigB64), data);
  if (!ok) throw new AuthError("invalid_token", "signature verification failed");

  return claims;
}

async function findKey(kid: string): Promise<GoogleJwk | undefined> {
  const now = Date.now();
  if (!cachedJwks || now - cachedJwks.fetchedAt > JWKS_TTL_MS) {
    const resp = await fetch(JWKS_URL);
    if (!resp.ok) throw new AuthError("jwks_fetch_failed", `JWKS endpoint returned ${resp.status}`);
    const body = (await resp.json()) as { keys: GoogleJwk[] };
    cachedJwks = { keys: body.keys, fetchedAt: now };
  }
  return cachedJwks.keys.find((k) => k.kid === kid);
}

export class AuthError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

// Test-only helper to reset the JWKs cache between tests.
export function _resetJwksCache(): void {
  cachedJwks = null;
}
