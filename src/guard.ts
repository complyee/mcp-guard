/**
 * createMcpGuard: wraps one MCP tool handler so it runs only on a verified
 * Agent Control Room grant for exactly these arguments.
 *
 *   ask (decideAction, grantFormat "jwt", payload hashed locally)
 *   → a person must decide? poll getApprovalStatus, then claim with the identical request
 *   → verify the grant JWT against the published JWK Set (EdDSA)
 *   → run the tool → report executed / downstream_error
 *
 * Fail closed throughout: a refusal, an unreachable engine, a missing or
 * rejected token all return an MCP error result and the tool never runs.
 * There is no fallback from a rejected token to anything else.
 */
import { toolCallPayloadHash } from "./fingerprint";
import { createAcrClient, type AcrDecision } from "./acr-client";
import { createJwksCache } from "./jwks";
import { verifyGrantToken } from "./jwt-verify";
import type {
  GuardStatus,
  GuardedToolOptions,
  McpGuardConfig,
  ToolExtra,
  ToolResult,
  VerifiedGrant,
} from "./types";

export const ACR_ISSUER = "https://agent-cr.com";
export const ACR_JWKS_URL = `${ACR_ISSUER}/.well-known/jwks.json`;
export const GUARD_META_KEY = "agent-cr.com/guard";
export const APPROVAL_DEFAULTS = {
  mode: "poll" as const,
  pollTimeoutMs: 30_000,
  pollIntervalMs: 2_000,
};

const defaultSleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => (clearTimeout(t), resolve()), { once: true });
  });

function result(status: GuardStatus, text: string, meta: Record<string, unknown> = {}): ToolResult {
  return {
    content: [{ type: "text", text }],
    isError: status !== "held",
    _meta: { [GUARD_META_KEY]: { status, ...meta } },
  };
}

export type McpGuard = {
  tool: <Args extends Record<string, unknown>>(
    toolName: string,
    options: GuardedToolOptions<Args>,
  ) => (args: Args, extra?: ToolExtra) => Promise<ToolResult>;
};

export function createMcpGuard(config: McpGuardConfig): McpGuard {
  const workspaceUrl = config.workspaceUrl.replace(/\/+$/, "");
  if (!/^https:\/\/[^/]+$/.test(workspaceUrl))
    throw new Error("workspaceUrl must be an https origin, e.g. https://acme.agent-cr.com");
  if (!config.apiKey) throw new Error("apiKey is required");
  if (!config.agent || config.agent.includes("|"))
    throw new Error("agent is required and must not contain |");

  const doFetch = config.fetch ?? fetch;
  const now = config.now ?? Date.now;
  const sleep = config.sleep ?? defaultSleep;
  const randomId = config.randomId ?? (() => crypto.randomUUID());
  const issuer = config.issuer ?? ACR_ISSUER;
  const clockSkewSec = config.clockSkewSec ?? 30;
  const acr = createAcrClient({
    workspaceUrl,
    apiKey: config.apiKey,
    fetch: doFetch,
    retries: config.retries ?? 1,
  });
  const keys = createJwksCache({
    url: config.jwksUrl ?? ACR_JWKS_URL,
    ttlMs: config.jwksCacheTtlMs ?? 300_000,
    fetch: doFetch,
    now,
  });

  return {
    tool(toolName, options) {
      const action = options.action ?? toolName;
      if (action.includes("|")) throw new Error(`action "${action}" must not contain |`);
      const approvals = { ...APPROVAL_DEFAULTS, ...config.approvals, ...options.approvals };

      return async (args, extra = {}) => {
        let payloadHash: string;
        try {
          payloadHash = await toolCallPayloadHash(toolName, args);
        } catch (error) {
          return result(
            "refused",
            `'${action}' was not run: its arguments cannot be fingerprinted (${(error as Error).message}).`,
          );
        }

        const parentDecisionId = options.parentDecisionId?.(args) ?? null;
        const resourceRef = options.resourceRef?.(args) ?? null;
        const actionDescription = options.actionDescription?.(args);
        const request: Record<string, unknown> = {
          agent: config.agent,
          action,
          payloadHash,
          grantFormat: "jwt",
          ...(resourceRef ? { resourceRef } : {}),
          ...(options.context ? { context: await options.context(args) } : {}),
          ...(actionDescription ? { actionDescription } : {}),
          ...(parentDecisionId ? { parentDecisionId } : {}),
        };
        // One key per invocation: a retry after a lost answer and the claim after
        // approval reuse it; a later, separate call of the tool gets a new one.
        const idempotencyKey = randomId();

        let decision: AcrDecision;
        try {
          decision = await acr.decideAction(request, idempotencyKey);
          if (decision.effect === "pending") {
            const held = (d: AcrDecision) =>
              result(
                "held",
                `'${action}' is waiting for a person to approve it (approval ${d.approvalId ?? "unknown"}). The tool did not run. Call it again with the same arguments within fifteen minutes of approval to continue.`,
                { approvalId: d.approvalId ?? null, decisionId: d.decisionId ?? null },
              );
            if (approvals.mode === "immediate_return" || !decision.approvalId)
              return held(decision);
            const deadline = now() + approvals.pollTimeoutMs;
            let claimed = false;
            while (now() < deadline && !extra.signal?.aborted) {
              await sleep(
                Math.min(approvals.pollIntervalMs, Math.max(0, deadline - now())),
                extra.signal,
              );
              if (extra.signal?.aborted) break;
              const approval = await acr.getApprovalStatus(decision.approvalId);
              if (approval.status === "pending") continue;
              if (approval.status === "granted") {
                // The identical request claims the approval and returns the signed grant.
                decision = await acr.decideAction(request, idempotencyKey);
                claimed = true;
                break;
              }
              const why =
                approval.status === "refused"
                  ? "a person refused it"
                  : approval.status === "expired"
                    ? "the approval request expired before anyone answered"
                    : approval.status === "consumed"
                      ? "the approval was already used"
                      : `the approval reads ${String(approval.status)}`;
              return result("refused", `'${action}' was not run: ${why}.`, {
                approvalId: decision.approvalId,
                approvalStatus: approval.status ?? null,
                ...(approval.reason ? { reason: approval.reason } : {}),
              });
            }
            if (!claimed || decision.effect === "pending") return held(decision);
          }
        } catch (error) {
          return result("unavailable", `'${action}' was not run: ${(error as Error).message}.`);
        }

        if (decision.effect !== "grant" || !decision.decisionId) {
          return result(
            "refused",
            `'${action}' was refused by policy: ${decision.rationale ?? "no rationale given"}.`,
            {
              decisionId: decision.decisionId ?? null,
              ...(decision.error ? { code: decision.error } : {}),
            },
          );
        }
        if (!decision.grantJwt) {
          return result(
            "unverified",
            `'${action}' was not run: the grant came without a token to verify.`,
            {
              decisionId: decision.decisionId,
            },
          );
        }

        const verified = await verifyGrantToken(decision.grantJwt, keys, {
          issuer,
          audience: workspaceUrl,
          agent: config.agent,
          action,
          payloadHash,
          decisionId: decision.decisionId,
          parentDecisionId,
          nowMs: now(),
          clockSkewSec,
        });
        if (!verified.ok) {
          return result(
            "unverified",
            `'${action}' was not run: grant token rejected (${verified.reason}).`,
            {
              decisionId: decision.decisionId,
              reason: verified.reason,
            },
          );
        }

        const grant: VerifiedGrant = {
          decisionId: decision.decisionId,
          payloadHash,
          expiresAt: decision.expiresAt ?? new Date(verified.claims.exp * 1000).toISOString(),
          claims: verified.claims,
        };
        const report = async (outcome: "executed" | "downstream_error") => {
          try {
            await acr.reportExecutionOutcome({
              decisionId: grant.decisionId,
              payloadHash,
              outcome,
              occurredAt: new Date(now()).toISOString(),
            });
          } catch (error) {
            // Evidence only: a failed report must never turn a done step into a retry.
            config.onReportError?.(error);
          }
        };

        let output: ToolResult;
        try {
          output = await options.execute(args, grant, extra);
        } catch (error) {
          await report("downstream_error");
          throw error;
        }
        await report(output.isError ? "downstream_error" : "executed");
        return {
          ...output,
          _meta: {
            ...output._meta,
            [GUARD_META_KEY]: { status: "executed", decisionId: grant.decisionId },
          },
        };
      };
    },
  };
}
