/**
 * Public types of the MCP guard companion (@complyee/mcp-guard).
 * Self-contained: nothing here depends on the rest of the ACR codebase.
 */

export type ApprovalMode = "poll" | "immediate_return";

export type McpGuardConfig = {
  /** The workspace's own address, e.g. "https://acme.agent-cr.com". Also the expected JWT audience. */
  workspaceUrl: string;
  /** Workspace API key with the policy.decide and policy.read scopes. Keep it in the server process. */
  apiKey: string;
  /** Agent name ACR judges and signs into the grant (JWT sub). */
  agent: string;
  approvals?: {
    /** "poll" waits for a person up to pollTimeoutMs; "immediate_return" answers "held" at once. */
    mode?: ApprovalMode;
    pollTimeoutMs?: number;
    pollIntervalMs?: number;
  };
  /** JWK Set address. Default: https://agent-cr.com/.well-known/jwks.json */
  jwksUrl?: string;
  /** Expected JWT issuer. Default: https://agent-cr.com */
  issuer?: string;
  /** How long fetched keys are reused. Default five minutes. */
  jwksCacheTtlMs?: number;
  /** Allowed clock difference for nbf and exp, in seconds. Default 30. */
  clockSkewSec?: number;
  /** Retries of a decision request after a network failure or a 5xx, with the same Idempotency-Key. Default 1. */
  retries?: number;
  /** Called when reporting an execution outcome fails. The tool result is never changed by it. */
  onReportError?: (error: unknown) => void;
  /** Injection points for tests and unusual runtimes. */
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  randomId?: () => string;
};

/** Minimal MCP tool result shape (CallToolResult in @modelcontextprotocol/sdk). */
export type ToolResult = {
  content: Array<{ type: "text"; text: string } | Record<string, unknown>>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
};

/** The parts of the MCP handler "extra" argument the guard uses. */
export type ToolExtra = { signal?: AbortSignal; [key: string]: unknown };

/** Claims of an ACR grant JWT (acr-grant-jwt-v1). */
export type GrantClaims = {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  acr: {
    ver: string;
    workspaceId: string;
    decisionId: string;
    action: string;
    payloadHash: string;
    resourceRef: string | null;
    policyVersion: string | null;
    ruleId: string | null;
    lineage: { parentDecisionId: string | null; rootDecisionId: string; depth: number };
  };
};

/** What the wrapped tool receives beside its arguments once the grant is verified. */
export type VerifiedGrant = {
  decisionId: string;
  payloadHash: string;
  expiresAt: string;
  claims: GrantClaims;
};

export type GuardedToolOptions<Args extends Record<string, unknown>> = {
  /** Action ACR judges. Defaults to the tool name. */
  action?: string;
  /** Context facts built from trusted sources or the arguments. Sent to ACR; keep it to what rules need. */
  context?: (args: Args) => Record<string, unknown> | Promise<Record<string, unknown>>;
  /** Optional resource reference, e.g. a customer or document id. */
  resourceRef?: (args: Args) => string | null | undefined;
  /** Optional short human-readable description shown to approvers (1–2000 chars). */
  actionDescription?: (args: Args) => string | undefined;
  /** The grant this step is delegated from, when one agent hands work to another. */
  parentDecisionId?: (args: Args) => string | undefined;
  /** Per-tool override of the approval behaviour. */
  approvals?: McpGuardConfig["approvals"];
  /**
   * Runs only after a verified grant. Pass grant.decisionId to the downstream
   * system as its idempotency key so a retry never does the work twice.
   */
  execute: (args: Args, grant: VerifiedGrant, extra: ToolExtra) => Promise<ToolResult> | ToolResult;
};

/** Machine-readable reason in result._meta, so hosts can branch without parsing text. */
export type GuardStatus = "executed" | "refused" | "held" | "unverified" | "unavailable";
