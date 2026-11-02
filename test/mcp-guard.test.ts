import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createHash } from "node:crypto";

// A faithful copy of ACR's signing and JWK Set code mints the tokens (see
// acr-reference-signer.ts); real-grant.test.ts checks a grant ACR itself minted.
const { signGrantJwt } = await import("./acr-reference-signer");
const { grantJwks } = await import("./acr-reference-signer");
const { createMcpGuard, GUARD_META_KEY } = await import("../src/index");
const { canonicalToolCall, toolCallPayloadHash } = await import("../src/fingerprint");

const ENV = [
  "POLICY_GRANT_SIGNING_KEY",
  "POLICY_GRANT_SIGNING_KEY_PREVIOUS",
  "POLICY_GRANT_SIGNING_KEY_NEXT",
] as const;
let saved: Record<string, string | undefined> = {};

const WORKSPACE = "https://acme.agent-cr.com";
const GATEWAY = `${WORKSPACE}/api/public/v1/gateway`;
const JWKS = "https://agent-cr.com/.well-known/jwks.json";
const APPROVAL_ID = "22222222-2222-4222-8222-222222222222";

type Sent = {
  operation: string;
  parameters: Record<string, unknown>;
  idempotencyKey: string | null;
  raw: string;
};
type Mint = {
  slug?: string;
  agent?: string;
  action?: string;
  payloadHash?: string;
  expiresAt?: string;
};

let sent: Sent[];
let jwksFetches: number;
let effects: Array<"grant" | "reject" | "pending" | "grant-no-jwt">;
let approvalStatuses: string[];
let mint: Mint;
let tamperToken: ((t: string) => string) | null;
let gatewayFailures: number;
let jwksDown: boolean;
let reportFails: boolean;
let clock: number;
let decisionCounter: number;

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  process.env["POLICY_GRANT_SIGNING_KEY"] = "mcp-guard-test-current";
  delete process.env["POLICY_GRANT_SIGNING_KEY_PREVIOUS"];
  delete process.env["POLICY_GRANT_SIGNING_KEY_NEXT"];
  sent = [];
  jwksFetches = 0;
  effects = ["grant"];
  approvalStatuses = [];
  mint = {};
  tamperToken = null;
  gatewayFailures = 0;
  jwksDown = false;
  reportFails = false;
  clock = Date.now();
  decisionCounter = 0;
});
afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify({ statusCode: status, ...(body as object) }), { status });

const fakeFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  if (url === JWKS) {
    jwksFetches++;
    if (jwksDown) return new Response("down", { status: 503 });
    return new Response(JSON.stringify(await grantJwks()), { status: 200 });
  }
  if (url !== GATEWAY) throw new Error(`unexpected url ${url}`);
  const raw = String(init?.body);
  const { operation, parameters } = JSON.parse(raw);
  const headers = new Headers(init?.headers);
  sent.push({ operation, parameters, idempotencyKey: headers.get("idempotency-key"), raw });
  if (gatewayFailures > 0) {
    gatewayFailures--;
    throw new TypeError("fetch failed");
  }
  if (headers.get("x-api-key") !== "cmp_live_test")
    return json({ error: { code: "unauthorized" } }, 401);

  if (operation === "getApprovalStatus") {
    return json({
      approval: {
        approvalId: parameters.approvalId,
        status: approvalStatuses.shift() ?? "pending",
      },
    });
  }
  if (operation === "reportExecutionOutcome") {
    if (reportFails) return json({ error: { code: "conflict", message: "already reported" } }, 409);
    return json({ execution: { decisionId: parameters.decisionId, outcome: parameters.outcome } });
  }
  const effect = effects.shift() ?? "grant";
  const decisionId = `11111111-1111-4111-8111-11111111111${decisionCounter++}`;
  if (effect === "reject")
    return json({
      decision: { decisionId, effect: "reject", rationale: "Refunds above 500 are not allowed" },
    });
  if (effect === "pending")
    return json({
      decision: {
        decisionId,
        effect: "pending",
        approvalId: APPROVAL_ID,
        rationale: "Ask a person",
      },
    });
  const expiresAt = mint.expiresAt ?? new Date(clock + 300_000).toISOString();
  const decision: Record<string, unknown> = {
    decisionId,
    effect: "grant",
    expiresAt,
    signature: "sig",
    publicSignature: "legacy",
    keyId: "k",
  };
  if (effect === "grant") {
    let token = await signGrantJwt({
      tenantId: "tenant-a",
      tenantSlug: mint.slug ?? "acme",
      decisionId,
      agent: mint.agent ?? parameters.agent,
      action: mint.action ?? parameters.action,
      resourceRef: parameters.resourceRef ?? null,
      payloadHash: mint.payloadHash ?? parameters.payloadHash,
      issuedAt: new Date(clock).toISOString(),
      expiresAt,
      policyVersion: "v1",
      ruleId: "r-1",
      lineage: null,
    });
    if (tamperToken) token = tamperToken(token);
    decision["grantJwt"] = token;
  }
  return json({ decision });
}) as typeof fetch;

const sleep = vi.fn(async (ms: number) => {
  clock += ms;
});

const makeGuard = (over: Record<string, unknown> = {}) =>
  createMcpGuard({
    workspaceUrl: WORKSPACE,
    apiKey: "cmp_live_test",
    agent: "finance-assistant",
    fetch: fakeFetch,
    now: () => clock,
    sleep,
    ...over,
  });

const ARGS = { paymentId: "pay_1", amount: 120, iban: "SE45-SECRET-IBAN" };

function refundTool(
  guard = makeGuard(),
  approvals?: { mode?: "poll" | "immediate_return"; pollTimeoutMs?: number },
) {
  const execute = vi.fn(async (args: typeof ARGS, grant: { decisionId: string }) => ({
    content: [{ type: "text" as const, text: `Refunded ${args.amount} (${grant.decisionId})` }],
  }));
  const handler = guard.tool<typeof ARGS>("issue_refund", {
    action: "payment.refund",
    context: (a) => ({ amount: a.amount }),
    ...(approvals ? { approvals } : {}),
    execute,
  });
  return { handler, execute };
}

const meta = (r: { _meta?: Record<string, unknown> }) =>
  r._meta?.[GUARD_META_KEY] as Record<string, unknown>;
const ops = () => sent.map((s) => s.operation);

test("the fingerprint matches ACR's sha256-canonical-json-v1 conformance vector", async () => {
  const args = { b: [2, { y: 1, x: 0 }], a: "z" };
  const canonical = '{"arguments":{"a":"z","b":[2,{"x":0,"y":1}]},"tool":"catalogue.read"}';
  expect(canonicalToolCall("catalogue.read", args)).toBe(canonical);
  expect(await toolCallPayloadHash("catalogue.read", args)).toBe(
    createHash("sha256").update(canonical).digest("hex"),
  );
});

test("a verified grant runs the tool once and reports executed against the same fingerprint", async () => {
  const { handler, execute } = refundTool();
  const res = await handler(ARGS);
  const hash = await toolCallPayloadHash("issue_refund", ARGS);

  expect(execute).toHaveBeenCalledTimes(1);
  expect(meta(res)).toMatchObject({ status: "executed" });
  expect(res.isError).toBeFalsy();
  expect(ops()).toEqual(["decideAction", "reportExecutionOutcome"]);
  expect(sent[0]!.parameters).toMatchObject({
    agent: "finance-assistant",
    action: "payment.refund",
    payloadHash: hash,
    grantFormat: "jwt",
    context: { amount: 120 },
  });
  expect(sent[1]!.parameters).toMatchObject({
    outcome: "executed",
    payloadHash: hash,
    decisionId: meta(res)["decisionId"],
  });
  // The decision id reaches the tool, for use as the downstream idempotency key.
  expect(execute.mock.calls[0]![1].decisionId).toBe(meta(res)["decisionId"]);
});

test("raw tool arguments never leave the MCP server", async () => {
  const { handler } = refundTool();
  await handler(ARGS);
  for (const s of sent) expect(s.raw).not.toContain("SE45-SECRET-IBAN");
});

test("a refusal returns an error result and the tool never runs", async () => {
  effects = ["reject"];
  const { handler, execute } = refundTool();
  const res = await handler(ARGS);
  expect(execute).not.toHaveBeenCalled();
  expect(res.isError).toBe(true);
  expect(meta(res)["status"]).toBe("refused");
  expect(ops()).toEqual(["decideAction"]);
});

test("poll mode waits for a person, then claims with the identical request and the same Idempotency-Key", async () => {
  effects = ["pending", "grant"];
  approvalStatuses = ["pending", "granted"];
  const { handler, execute } = refundTool();
  const res = await handler(ARGS);

  expect(execute).toHaveBeenCalledTimes(1);
  expect(meta(res)["status"]).toBe("executed");
  expect(ops()).toEqual([
    "decideAction",
    "getApprovalStatus",
    "getApprovalStatus",
    "decideAction",
    "reportExecutionOutcome",
  ]);
  expect(sent[3]!.parameters).toEqual(sent[0]!.parameters);
  expect(sent[3]!.idempotencyKey).toBe(sent[0]!.idempotencyKey);
});

test("poll mode gives up after the default 30 seconds with a held result and does not run the tool", async () => {
  effects = ["pending"];
  const { handler, execute } = refundTool();
  const start = clock;
  const res = await handler(ARGS);

  expect(execute).not.toHaveBeenCalled();
  expect(res.isError).toBe(false);
  expect(meta(res)).toMatchObject({ status: "held", approvalId: APPROVAL_ID });
  expect(clock - start).toBe(30_000);
  expect(sent.filter((s) => s.operation === "getApprovalStatus")).toHaveLength(15); // every 2 s
});

test("immediate_return answers held at once without polling", async () => {
  effects = ["pending"];
  const { handler, execute } = refundTool(makeGuard({ approvals: { mode: "immediate_return" } }));
  const res = await handler(ARGS);
  expect(execute).not.toHaveBeenCalled();
  expect(meta(res)["status"]).toBe("held");
  expect(ops()).toEqual(["decideAction"]);
});

test("a per-tool approval setting overrides the guard default", async () => {
  effects = ["pending"];
  const { handler } = refundTool(makeGuard(), { mode: "immediate_return" });
  await handler(ARGS);
  expect(ops()).toEqual(["decideAction"]);
});

test("a person refusing while the guard polls ends the call without running the tool", async () => {
  effects = ["pending"];
  approvalStatuses = ["refused"];
  const { handler, execute } = refundTool();
  const res = await handler(ARGS);
  expect(execute).not.toHaveBeenCalled();
  expect(meta(res)).toMatchObject({ status: "refused", approvalStatus: "refused" });
});

test("a cancelled call stops polling and answers held", async () => {
  effects = ["pending"];
  const { handler, execute } = refundTool();
  const controller = new AbortController();
  controller.abort();
  const res = await handler(ARGS, { signal: controller.signal });
  expect(execute).not.toHaveBeenCalled();
  expect(meta(res)["status"]).toBe("held");
  expect(ops()).toEqual(["decideAction"]);
});

const rejected: Array<[string, () => void, string]> = [
  ["a grant for a different payload", () => (mint.payloadHash = "b".repeat(64)), "wrong payload"],
  ["a grant for a different agent", () => (mint.agent = "other-agent"), "wrong agent"],
  ["a grant for a different action", () => (mint.action = "payment.transfer"), "wrong action"],
  ["a grant for another workspace", () => (mint.slug = "other"), "wrong audience"],
  [
    "an expired grant",
    () => (mint.expiresAt = new Date(Date.now() - 300_000).toISOString()),
    "expired",
  ],
  [
    "a grant with a broken signature",
    () => (tamperToken = (t) => t.slice(0, -4) + (t.endsWith("AAAA") ? "BBBB" : "AAAA")),
    "bad signature",
  ],
  [
    "a grant whose claims were edited",
    () =>
      (tamperToken = (t) => {
        const [h, p, s] = t.split(".");
        const claims = JSON.parse(Buffer.from(p!, "base64url").toString());
        claims.acr.payloadHash = "c".repeat(64);
        return [h, Buffer.from(JSON.stringify(claims)).toString("base64url"), s].join(".");
      }),
    "bad signature",
  ],
  ["a grant without a token", () => (effects = ["grant-no-jwt"]), ""],
];

for (const [name, arrange, reason] of rejected) {
  test(`${name} fails closed: the tool never runs and nothing is reported`, async () => {
    arrange();
    const { handler, execute } = refundTool();
    const res = await handler(ARGS);
    expect(execute).not.toHaveBeenCalled();
    expect(res.isError).toBe(true);
    expect(meta(res)["status"]).toBe("unverified");
    if (reason) expect(meta(res)["reason"]).toBe(reason);
    expect(ops()).toEqual(["decideAction"]);
  });
}

test("unavailable public keys fail closed", async () => {
  jwksDown = true;
  const { handler, execute } = refundTool();
  const res = await handler(ARGS);
  expect(execute).not.toHaveBeenCalled();
  expect(meta(res)).toMatchObject({ status: "unverified", reason: "public keys unavailable" });
});

test("an unreachable engine fails closed after one retry with the same Idempotency-Key", async () => {
  gatewayFailures = 2;
  const { handler, execute } = refundTool();
  const res = await handler(ARGS);
  expect(execute).not.toHaveBeenCalled();
  expect(meta(res)["status"]).toBe("unavailable");
  expect(sent).toHaveLength(2);
  expect(sent[1]!.idempotencyKey).toBe(sent[0]!.idempotencyKey);
});

test("one lost connection is retried and the tool still runs", async () => {
  gatewayFailures = 1;
  const { handler, execute } = refundTool();
  const res = await handler(ARGS);
  expect(execute).toHaveBeenCalledTimes(1);
  expect(meta(res)["status"]).toBe("executed");
});

test("separate calls of the same tool get separate Idempotency-Keys", async () => {
  const { handler } = refundTool();
  await handler(ARGS);
  await handler(ARGS);
  const keys = sent.filter((s) => s.operation === "decideAction").map((s) => s.idempotencyKey);
  expect(keys[0]).not.toBe(keys[1]);
});

test("keys are cached for five minutes, and an unknown key id triggers one refetch (rotation)", async () => {
  const guard = makeGuard();
  const { handler } = refundTool(guard);
  await handler(ARGS);
  await handler(ARGS);
  expect(jwksFetches).toBe(1);

  // Rotation: a new current key signs. The cached set does not know its kid yet.
  clock += 60_000;
  process.env["POLICY_GRANT_SIGNING_KEY"] = "mcp-guard-test-rotated";
  const res = await handler(ARGS);
  expect(meta(res)["status"]).toBe("executed");
  expect(jwksFetches).toBe(2);

  clock += 301_000;
  await handler(ARGS);
  expect(jwksFetches).toBe(3);
});

test("a tool that throws is reported as downstream_error and the error is passed on", async () => {
  const guard = makeGuard();
  const handler = guard.tool("issue_refund", {
    execute: async () => {
      throw new Error("payment provider down");
    },
  });
  await expect(handler(ARGS)).rejects.toThrow("payment provider down");
  expect(sent.at(-1)!.parameters).toMatchObject({ outcome: "downstream_error" });
});

test("a failed outcome report never changes the tool result", async () => {
  reportFails = true;
  const onReportError = vi.fn();
  const { handler, execute } = refundTool(makeGuard({ onReportError }));
  const res = await handler(ARGS);
  expect(execute).toHaveBeenCalledTimes(1);
  expect(meta(res)["status"]).toBe("executed");
  expect(onReportError).toHaveBeenCalledTimes(1);
});

test("the action defaults to the tool name", async () => {
  const guard = makeGuard();
  await guard.tool("catalogue_read", { execute: async () => ({ content: [] }) })({ id: 1 });
  expect(sent[0]!.parameters["action"]).toBe("catalogue_read");
});

test("unsafe configuration is refused up front", () => {
  expect(() => makeGuard({ workspaceUrl: "http://acme.agent-cr.com" })).toThrow();
  expect(() => makeGuard({ agent: "a|b" })).toThrow();
  expect(() => makeGuard({ apiKey: "" })).toThrow();
  expect(() =>
    makeGuard().tool("t", { action: "x|y", execute: async () => ({ content: [] }) }),
  ).toThrow();
});

test("the wrapped handler plugs into an MCP server's registerTool", async () => {
  const registered: Record<
    string,
    (args: Record<string, unknown>, extra: object) => Promise<unknown>
  > = {};
  const server = {
    registerTool: (
      name: string,
      _config: object,
      cb: (args: Record<string, unknown>, extra: object) => Promise<unknown>,
    ) => {
      registered[name] = cb;
    },
  };
  const { handler } = refundTool();
  server.registerTool("issue_refund", { description: "Refund a payment" }, handler as never);
  const res = (await registered["issue_refund"]!(ARGS, {})) as { _meta?: Record<string, unknown> };
  expect(meta(res)["status"]).toBe("executed");
});
