/**
 * Fetches and caches ACR's public JWK Set. A failed fetch never falls back to
 * stale or missing keys silently: the caller gets no key and fails closed.
 */

export type Jwk = {
  kty?: string;
  crv?: string;
  x?: string;
  kid?: string;
  alg?: string;
  use?: string;
};

export type JwksCache = {
  /** The Ed25519 key with this kid, refetching once (at most every minRefreshMs) when it is unknown. */
  getKey: (kid: string) => Promise<Jwk | null>;
};

export function createJwksCache(options: {
  url: string;
  ttlMs: number;
  fetch: typeof fetch;
  now: () => number;
  minRefreshMs?: number;
}): JwksCache {
  const minRefreshMs = options.minRefreshMs ?? 10_000;
  let keys: Jwk[] | null = null;
  let fetchedAt = 0;
  let inflight: Promise<Jwk[]> | null = null;

  const load = async (): Promise<Jwk[]> => {
    inflight ??= (async () => {
      try {
        const res = await options.fetch(options.url, { headers: { accept: "application/json" } });
        if (!res.ok) throw new Error(`JWK Set answered ${res.status}`);
        const body = (await res.json()) as { keys?: unknown };
        if (!Array.isArray(body.keys)) throw new Error("JWK Set has no keys array");
        keys = body.keys as Jwk[];
        fetchedAt = options.now();
        return keys;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  };

  const find = (list: Jwk[], kid: string) =>
    list.find(
      (k) => k.kid === kid && k.kty === "OKP" && k.crv === "Ed25519" && typeof k.x === "string",
    ) ?? null;

  return {
    async getKey(kid) {
      const fresh = keys !== null && options.now() - fetchedAt < options.ttlMs;
      const list = fresh ? keys! : await load();
      const hit = find(list, kid);
      if (hit) return hit;
      // Unknown kid: a key may just have been promoted. Refetch once, but not on every call.
      if (!fresh || options.now() - fetchedAt < minRefreshMs) return null;
      return find(await load(), kid);
    },
  };
}
