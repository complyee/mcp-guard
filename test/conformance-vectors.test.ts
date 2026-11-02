import { expect, test } from "vitest";
import vectors from "./conformance-vectors.json";
import { canonicalToolCall, toolCallPayloadHash } from "../src/fingerprint";

// The same file is asserted by the Python companion (complyee/agent-guard-python), so both
// companions and ACR hash a tool call identically.
for (const v of vectors.vectors) {
  test(`fingerprint vector: ${v.name}`, async () => {
    const args = v.arguments as Record<string, unknown>;
    expect(canonicalToolCall(v.tool, args)).toBe(v.canonical);
    expect(await toolCallPayloadHash(v.tool, args)).toBe(v.payloadHash);
  });
}
