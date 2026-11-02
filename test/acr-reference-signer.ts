/**
 * Test-only copy of Agent Control Room's grant signing (acr-grant-jwt-v1) and
 * JWK Set publication, so the guard is tested against the same token shape the
 * engine issues. Keys are derived exactly as ACR derives them: seed =
 * SHA-256(secret), kid = first 16 hex chars of SHA-256(raw public key).
 * test/real-grant.test.ts additionally checks a grant minted by ACR itself.
 *
 * Never use this in production: only Agent Control Room signs grants.
 */

const ISSUER = "https://agent-cr.com";
const ENV = {
  current: "POLICY_GRANT_SIGNING_KEY",
  previous: "POLICY_GRANT_SIGNING_KEY_PREVIOUS",
  next: "POLICY_GRANT_SIGNING_KEY_NEXT",
} as const;

const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

type LoadedKey = { keyId: string; publicKey: string; privateKey: CryptoKey };
const cache = new Map<string, Promise<LoadedKey>>();
const encoder = new TextEncoder();

function bytesToBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

const toHex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

async function loadKey(secret: string): Promise<LoadedKey> {
  const seed = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(secret)));
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed, PKCS8_PREFIX.length);
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  const publicKey = jwk.x ?? "";
  const keyId = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", base64UrlToBytes(publicKey)))).slice(0, 16);
  return { keyId, publicKey, privateKey };
}

function keyFor(secret: string): Promise<LoadedKey> {
  let entry = cache.get(secret);
  if (!entry) {
    entry = loadKey(secret);
    cache.set(secret, entry);
  }
  return entry;
}

export type GrantJwtInput = {
  tenantId: string;
  tenantSlug: string;
  decisionId: string;
  agent: string;
  action: string;
  resourceRef: string | null;
  payloadHash: string;
  issuedAt: string;
  expiresAt: string;
  policyVersion: string | null;
  ruleId: string | null;
  lineage: { parentDecisionId: string; rootDecisionId: string; depth: number } | null;
};

const segment = (value: unknown) => bytesToBase64Url(encoder.encode(JSON.stringify(value)));
const seconds = (iso: string, fallback: number) => {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : fallback;
};
const signable = (v: string) => v.length > 0 && !v.includes("|");

/** Compact JWS signed with the current key; "" when no key is configured. */
export async function signGrantJwt(input: GrantJwtInput): Promise<string> {
  const secret = process.env[ENV.current] ?? "";
  if (!secret || !input.tenantSlug || !signable(input.agent) || !signable(input.action)) return "";
  const key = await keyFor(secret);
  const now = Math.floor(Date.now() / 1000);
  const iat = seconds(input.issuedAt, now);
  const claims = {
    iss: ISSUER,
    sub: input.agent,
    aud: `https://${input.tenantSlug}.agent-cr.com`,
    jti: input.decisionId,
    iat,
    nbf: iat,
    exp: seconds(input.expiresAt, now),
    acr: {
      ver: "acr-grant-jwt-v1",
      workspaceId: input.tenantId,
      decisionId: input.decisionId,
      action: input.action,
      payloadHash: input.payloadHash,
      resourceRef: input.resourceRef,
      policyVersion: input.policyVersion,
      ruleId: input.ruleId,
      lineage: {
        parentDecisionId: input.lineage?.parentDecisionId ?? null,
        rootDecisionId: input.lineage?.rootDecisionId ?? input.decisionId,
        depth: input.lineage?.depth ?? 0,
      },
    },
  };
  const signingInput = `${segment({ alg: "EdDSA", typ: "JWT", kid: key.keyId })}.${segment(claims)}`;
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, key.privateKey, encoder.encode(signingInput));
  return `${signingInput}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

/** RFC 7517 JWK Set of the current, previous and next keys — public members only. */
export async function grantJwks(): Promise<{ keys: Array<Record<string, string>> }> {
  const current = process.env[ENV.current] ?? "";
  const previous = process.env[ENV.previous] ?? "";
  const next = process.env[ENV.next] ?? "";
  const secrets: string[] = [];
  if (current) secrets.push(current);
  if (previous && previous !== current) secrets.push(previous);
  if (next && next !== current && next !== previous) secrets.push(next);
  const keys = [];
  for (const secret of secrets) {
    const key = await keyFor(secret);
    keys.push({ kty: "OKP", crv: "Ed25519", x: key.publicKey, kid: key.keyId, use: "sig", alg: "EdDSA" });
  }
  return { keys };
}
