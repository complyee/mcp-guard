/**
 * Zero-dependency check of an ACR grant JWT (EdDSA / Ed25519, RFC 8037) with
 * WebCrypto. Every comparison uses what THIS server expects — its own agent,
 * action and payload hash — never values read back from the answer.
 */
import type { GrantClaims } from "./types";
import type { JwksCache } from "./jwks";

export const GRANT_JWT_VERSION = "acr-grant-jwt-v1";

export type ExpectedGrant = {
  issuer: string;
  audience: string;
  agent: string;
  action: string;
  payloadHash: string;
  decisionId: string;
  parentDecisionId: string | null;
  nowMs: number;
  clockSkewSec: number;
};

export type VerifyResult = { ok: true; claims: GrantClaims } | { ok: false; reason: string };

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("not base64url");
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeJson<T>(segment: string): T | null {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment))) as T;
  } catch {
    return null;
  }
}

const fail = (reason: string): VerifyResult => ({ ok: false, reason });

export async function verifyGrantToken(
  token: string,
  keys: JwksCache,
  expected: ExpectedGrant,
): Promise<VerifyResult> {
  const parts = token.split(".");
  if (parts.length !== 3) return fail("malformed token");
  const [h, p, s] = parts as [string, string, string];
  const header = decodeJson<{ alg?: string; kid?: string }>(h);
  const claims = decodeJson<GrantClaims>(p);
  if (!header || !claims || typeof claims !== "object") return fail("malformed token");
  if (header.alg !== "EdDSA") return fail("algorithm is not EdDSA");
  if (!header.kid) return fail("no key id");

  let jwk;
  try {
    jwk = await keys.getKey(header.kid);
  } catch {
    return fail("public keys unavailable");
  }
  if (!jwk?.x) return fail("unknown key id");

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      base64UrlToBytes(jwk.x),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "Ed25519",
      key,
      base64UrlToBytes(s),
      new TextEncoder().encode(`${h}.${p}`),
    );
  } catch {
    valid = false;
  }
  if (!valid) return fail("bad signature");

  const now = Math.floor(expected.nowMs / 1000);
  const acr = claims.acr;
  if (claims.iss !== expected.issuer) return fail("wrong issuer");
  if (claims.aud !== expected.audience) return fail("wrong audience");
  if (claims.sub !== expected.agent) return fail("wrong agent");
  if (typeof claims.exp !== "number" || now >= claims.exp + expected.clockSkewSec)
    return fail("expired");
  if (typeof claims.nbf !== "number" || now + expected.clockSkewSec < claims.nbf)
    return fail("not yet valid");
  if (!acr || acr.ver !== GRANT_JWT_VERSION) return fail("unknown grant version");
  if (acr.action !== expected.action) return fail("wrong action");
  if (acr.payloadHash !== expected.payloadHash) return fail("wrong payload");
  if (claims.jti !== expected.decisionId || acr.decisionId !== expected.decisionId)
    return fail("wrong decision");
  if ((acr.lineage?.parentDecisionId ?? null) !== expected.parentDecisionId)
    return fail("wrong lineage");
  return { ok: true, claims };
}
