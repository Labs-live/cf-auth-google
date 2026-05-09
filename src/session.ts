/** Signed session cookies: payload.signature, HMAC-SHA256, base64url-encoded. */

export type SessionPayload = {
  email: string;
  profile: string;
  exp: number;
};

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

export async function issue(payload: SessionPayload, secret: string): Promise<string> {
  const json = JSON.stringify(payload);
  const body = b64urlEncode(ENCODER.encode(json));
  const sig = await sign(body, secret);
  return `${body}.${sig}`;
}

export async function verify(token: string, secret: string, now: number = Date.now()): Promise<SessionPayload | null> {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = await sign(body, secret);
  if (!constantTimeEqual(sig, expected)) return null;
  let payload: SessionPayload;
  try {
    payload = JSON.parse(DECODER.decode(b64urlDecode(body))) as SessionPayload;
  } catch {
    return null;
  }
  if (typeof payload.exp !== "number" || payload.exp * 1000 < now) return null;
  return payload;
}

async function sign(body: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", ENCODER.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, ENCODER.encode(body));
  return b64urlEncode(new Uint8Array(mac));
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function b64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (padded.length % 4)) % 4);
  const bin = atob(padded + padding);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
