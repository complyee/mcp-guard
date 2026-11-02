# Changelog

## 0.1.0 — first public release

- `createMcpGuard` and `guard.tool()` wrap any MCP tool handler.
- Local `sha256-canonical-json-v1` fingerprint; raw tool arguments never leave the server.
- `decideAction` with `grantFormat: "jwt"` and one Idempotency-Key per call.
- Approval handling: `poll` (default, 30 s) or `immediate_return`, configurable per tool.
- Grant JWT verified with WebCrypto (Ed25519) against the published JWK Set, with caching and key-rotation refetch.
- Fails closed on refusal, unreachable engine, unavailable keys or any failed check.
- Outcome reporting (`executed` / `downstream_error`) that never changes the tool result.
