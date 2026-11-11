# MCP guard (`@complyee/mcp-guard`)

A customer-run companion that puts an Agent Control Room grant check in front of
any MCP tool. It does the repeatable work — fingerprinting, asking, waiting for a
person, claiming, verifying the grant token and reporting the outcome — so the
tool author supplies only the action name and the context facts rules need.

Status: published as `@complyee/mcp-guard` (npm) from github.com/complyee/mcp-guard. This folder is the source; push every change there. The code lives in the ACR repository with its tests.

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
  { description: "Refund a payment", inputSchema: { refundRequestId: z.string(), paymentId: z.string(), amount: z.number() } },
  guard.tool("issue_refund", {
    action: "payment.refund",                        // defaults to the tool name
    context: (args) => ({ amount: args.amount }),    // facts your rules read
    execute: async (args, grant) => {
      // Runs only on a verified grant for exactly these arguments.
      // The idempotency key is your stable business reference, never grant.decisionId:
      // a retry is a new decision with a new id. decisionId is the audit reference.
      await payments.refund(args, {
        idempotencyKey: args.refundRequestId,
        metadata: { acrDecisionId: grant.decisionId },
      });
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

## Retries and duplicate execution

A grant authorises one decision; it is not a lock on the work. If a call times
out and the agent or client retries, the guard asks again and Agent Control Room
returns a **new decision with a new `decisionId`**. Using `decisionId` as the
downstream idempotency key would therefore let the retry execute twice.

- Give the downstream system a **stable business reference** as its idempotency
  key (a refund request id, transfer id or order id that stays the same across
  retries), and let that system refuse duplicates.
- Keep `decisionId` as the **audit reference** (metadata on the downstream
  record) so the action can be traced back to its decision.
- Prefer a business reference supplied by your own system over one the model
  invents; a model can produce a fresh id on every attempt.

## Fail closed

A refusal, an unreachable engine, unavailable keys, a missing token or a token
that fails any check returns an MCP error result and the tool never runs.
There is no fallback from a rejected token to another format.
`result._meta["agent-cr.com/guard"].status` is one of `executed`, `refused`,
`held`, `unverified`, `unavailable`.

An offline check cannot see a revocation made after the grant was issued; for a
high-value step also call `verifyDecision` before acting.

## Extracting into a package

Copy this folder and `src/lib/tool-call-fingerprint.ts` (into `fingerprint.ts`).
The conformance vector in `mcp-guard.test.ts` must keep passing so the guard and
ACR always hash identically.
