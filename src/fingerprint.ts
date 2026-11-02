/**
 * Canonical fingerprint of an MCP tools/call — byte-for-byte the function
 * Agent Control Room uses, so the payloadHash the guard sends is exactly what
 * decideToolCall would compute, while the arguments never leave the server.
 * test/conformance-vectors.json is generated from ACR's code and must keep passing.
 *
 * Algorithm "sha256-canonical-json-v1": SHA-256 (lowercase hex) over the
 * canonical JSON of { "tool": toolName, "arguments": toolArguments } —
 * object keys sorted by code unit, no whitespace, arrays kept in order.
 */

export const TOOL_CALL_HASH_ALGORITHM = "sha256-canonical-json-v1" as const;
export const TOOL_ARGUMENTS_MAX_BYTES = 64 * 1024;

export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new Error("non-finite number in tool arguments");
      return JSON.stringify(value);
    case "object": {
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
    }
    default:
      throw new Error(`unsupported value in tool arguments: ${typeof value}`);
  }
}

export function canonicalToolCall(toolName: string, toolArguments: Record<string, unknown>): string {
  return canonicalJson({ tool: toolName, arguments: toolArguments });
}

export async function toolCallPayloadHash(
  toolName: string,
  toolArguments: Record<string, unknown>,
): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalToolCall(toolName, toolArguments));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}
