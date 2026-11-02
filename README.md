# @complyee/mcp-guard

A customer-run companion that puts an Agent Control Room grant check in front of
any MCP tool. It does the repeatable work — fingerprinting, asking, waiting for a
person, claiming, verifying the grant token and reporting the outcome — so the
tool author supplies only the action name and the context facts rules need.

Status: 0.1 (beta). Zero runtime dependencies; Node.js 20 or later (or any runtime
with WebCrypto Ed25519 and `fetch`).

```bash
npm install @complyee/mcp-guard
```

[Agent Control Room](https://agent-cr.com) is the decision point; this package is
the enforcement point that runs inside your MCP server. See
[agent-cr.com/plugins](https://agent-cr.com/plugins) and
[agent-cr.com/enforcement-point](https://agent-cr.com/enforcement-point).

## Use

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createMcpGuard } from "@complyee/mcp-guard";

const server = new McpServer({ name: "payments", version: "1.0.0" });

const guard = createMcpGuard({
  workspaceUrl: "https://acme.agent-cr.com",   // your workspace address (also the JWT audience)
  apiKey: process.env.ACR_API_KEY!,            // scopes: policy.decide, policy.read
  agent: "finance-assistant",
  approvals: { mode: "poll", pollTimeoutMs: 30_000, pollIntervalMs: 2_000 }, // the defaults
});

server.registerTool(
  "issue_refund",
  { description: "Refund a payment", inputSchema: { paymentId: z.string(), amount: z.number() } },
  guard.tool("issue_refund", {
    action: "payment.refund",                        // defaults to the tool name
    context: (args) => ({ amount: args.amount }),    // facts your rules read
    execute: async (args, grant) => {
      // Runs only on a verified grant for exactly these arguments.
      await payments.refund(args, { idempotencyKey: grant.decisionId });
      return { content: [{ type: "text", text: `Refunded ${args.amount}.` }] };
    },
  }),
);
```

## What happens on each call

1. The tool name and arguments are fingerprinted locally with
   `sha256-canonical-json-v1` — the same value `decideToolCall` would compute.
   The arguments themselves never leave the server; only the hash, the action
   and the declared context facts are sent.
2. `decideAction` is called with `grantFormat: "jwt"` and one Idempotency-Key per
   call (reused for a retry after a lost connection and for the claim).
3. If a person must decide:
   - `poll` (default): `getApprovalStatus` every 2 s for up to 30 s; on
     `granted` the identical request is sent once to claim the grant.
   - `immediate_return`, or poll timeout, or a cancelled call: the tool returns a
     non-error result saying it is waiting for a person, with the approval id.
     Calling the tool again with the same arguments within fifteen minutes of
     approval claims it.
4. `decision.grantJwt` is verified with WebCrypto against
   `https://agent-cr.com/.well-known/jwks.json` (cached five minutes, refetched
   once on an unknown key id): EdDSA, issuer, audience = workspace address,
   sub = agent, action, payload hash, decision id, lineage, nbf/exp (30 s skew).
5. The tool runs, and `reportExecutionOutcome` records `executed` or
   `downstream_error`. A failed report never changes the tool result.

## Fail closed

A refusal, an unreachable engine, unavailable keys, a missing token or a token
that fails any check returns an MCP error result and the tool never runs.
There is no fallback from a rejected token to another format.
`result._meta["agent-cr.com/guard"].status` is one of `executed`, `refused`,
`held`, `unverified`, `unavailable`.

An offline check cannot see a revocation made after the grant was issued; for a
high-value step also call `verifyDecision` before acting.

## Development

```bash
npm install
npm run typecheck && npm test && npm run build
```

`test/conformance-vectors.json` and `test/fixtures/grant.json` are generated from
Agent Control Room's own code and are shared with the Python companion
([complyee/agent-guard-python](https://github.com/complyee/agent-guard-python)),
so all three hash and verify identically. Do not edit them by hand.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Copyright Complyee AB.
