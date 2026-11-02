/**
 * The three ACR operations the guard needs, over the public v1 gateway:
 * decideAction, getApprovalStatus and reportExecutionOutcome. Any non-2xx
 * answer is an error; the guard turns errors into "the tool did not run".
 */

export type AcrDecision = {
  decisionId?: string;
  effect?: "grant" | "reject" | "pending" | string;
  rationale?: string;
  expiresAt?: string;
  approvalId?: string;
  grantJwt?: string;
  error?: string;
  lineage?: { parentDecisionId: string; rootDecisionId: string; depth: number } | null;
  [key: string]: unknown;
};

export type AcrApproval = {
  approvalId?: string;
  status?: "pending" | "granted" | "refused" | "expired" | "consumed" | string;
  reason?: string | null;
  expiresAt?: string | null;
  [key: string]: unknown;
};

export class AcrRequestError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly code: string | null,
  ) {
    super(message);
  }
}

export type AcrClient = {
  decideAction: (
    parameters: Record<string, unknown>,
    idempotencyKey: string,
  ) => Promise<AcrDecision>;
  getApprovalStatus: (approvalId: string) => Promise<AcrApproval>;
  reportExecutionOutcome: (parameters: Record<string, unknown>) => Promise<void>;
};

export function createAcrClient(options: {
  workspaceUrl: string;
  apiKey: string;
  fetch: typeof fetch;
  retries: number;
}): AcrClient {
  const endpoint = `${options.workspaceUrl}/api/public/v1/gateway`;

  async function call(operation: string, parameters: object, idempotencyKey?: string, retries = 0) {
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await options.fetch(endpoint, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-api-key": options.apiKey,
            ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
          },
          body: JSON.stringify({ operation, parameters }),
        });
      } catch (error) {
        if (attempt < retries) continue;
        throw new AcrRequestError(`Agent Control Room unreachable: ${String(error)}`, null, null);
      }
      if (res.status >= 500 && attempt < retries) continue;
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (!res.ok) {
        const err = (body["error"] ?? {}) as { code?: string; message?: string };
        throw new AcrRequestError(
          `Agent Control Room answered ${res.status}${err.message ? `: ${err.message}` : ""}`,
          res.status,
          err.code ?? null,
        );
      }
      return body;
    }
  }

  return {
    async decideAction(parameters, idempotencyKey) {
      // Retrying is safe only because the Idempotency-Key makes a repeat return the same answer.
      const body = await call("decideAction", parameters, idempotencyKey, options.retries);
      return (body["decision"] ?? {}) as AcrDecision;
    },
    async getApprovalStatus(approvalId) {
      const body = await call("getApprovalStatus", { approvalId }, undefined, options.retries);
      return (body["approval"] ?? {}) as AcrApproval;
    },
    async reportExecutionOutcome(parameters) {
      await call("reportExecutionOutcome", parameters);
    },
  };
}
