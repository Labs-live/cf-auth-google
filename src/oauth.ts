/** OAuth 2.0 + PKCE flow against Google's authorization and token endpoints. */

import { b64urlEncode } from "./session";
import { AuthError } from "./idtoken";

const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";

export type AuthorizeParams = {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scopes?: string[];
  loginHint?: string;
};

export function buildAuthorizeUrl(p: AuthorizeParams): string {
  const params = new URLSearchParams({
    client_id: p.clientId,
    redirect_uri: p.redirectUri,
    response_type: "code",
    scope: (p.scopes ?? ["openid", "email", "profile"]).join(" "),
    state: p.state,
    code_challenge: p.codeChallenge,
    code_challenge_method: "S256",
    access_type: "online",
    prompt: "select_account",
  });
  if (p.loginHint) params.set("login_hint", p.loginHint);
  return `${AUTH_URL}?${params.toString()}`;
}

export type TokenExchangeParams = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
};

export type TokenResponse = {
  id_token: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
};

export async function exchangeCode(p: TokenExchangeParams, fetcher: typeof fetch = fetch): Promise<TokenResponse> {
  const body = new URLSearchParams({
    client_id: p.clientId,
    client_secret: p.clientSecret,
    code: p.code,
    code_verifier: p.codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: p.redirectUri,
  });
  const resp = await fetcher(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new AuthError("token_exchange_failed", `Google token endpoint ${resp.status}: ${text}`);
  }
  return (await resp.json()) as TokenResponse;
}

export async function generatePkce(): Promise<{ verifier: string; challenge: string }> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const verifier = b64urlEncode(bytes);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: b64urlEncode(new Uint8Array(digest)) };
}

export function generateState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return b64urlEncode(bytes);
}
