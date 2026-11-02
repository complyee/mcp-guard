import { expect, test } from "vitest";
import fixture from "./fixtures/grant.json";
import { createJwksCache, verifyGrantToken, toolCallPayloadHash } from "../src/index";

// A grant minted by Agent Control Room's own signing code (not the test signer),
// shared with the Python companion. Proves the guard accepts exactly what ACR issues.
const issuedMs = Date.parse(fixture.issuedAt);

const keys = createJwksCache({
  url: "https://agent-cr.com/.well-known/jwks.json",
  ttlMs: 300_000,
  now: () => issuedMs,
  fetch: (async () => new Response(JSON.stringify(fixture.jwks), { status: 200 })) as typeof fetch,
});

const expected = (over: Record<string, unknown> = {}) => ({
  issuer: "https://agent-cr.com",
  audience: fixture.workspaceUrl,
  agent: fixture.agent,
  action: fixture.action,
  payloadHash: fixture.payloadHash,
  decisionId: fixture.decisionId,
  parentDecisionId: null,
  nowMs: issuedMs + 10_000,
  clockSkewSec: 30,
  ...over,
});

test("the fixture's payload hash is the guard's own fingerprint of its tool call", async () => {
  expect(await toolCallPayloadHash(fixture.tool, fixture.arguments as Record<string, unknown>)).toBe(
    fixture.payloadHash,
  );
});

test("accepts a grant minted by Agent Control Room", async () => {
  const result = await verifyGrantToken(fixture.grantJwt, keys, expected());
  expect(result.ok).toBe(true);
});

test.each([
  [{ payloadHash: "0".repeat(64) }, "wrong payload"],
  [{ agent: "someone-else" }, "wrong agent"],
  [{ action: "refund.other" }, "wrong action"],
  [{ audience: "https://other.agent-cr.com" }, "wrong audience"],
  [{ issuer: "https://evil.example" }, "wrong issuer"],
  [{ nowMs: Date.parse(fixture.expiresAt) + 60_000 }, "expired"],
])("rejects the ACR grant when %o differs", async (over, reason) => {
  const result = await verifyGrantToken(fixture.grantJwt, keys, expected(over));
  expect(result).toEqual({ ok: false, reason });
});
