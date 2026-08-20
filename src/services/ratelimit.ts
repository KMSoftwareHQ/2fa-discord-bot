/**
 * In-memory sliding-window rate limiting.
 *
 * Two limits matter here, and the ORDER they are consumed in is a security
 * property rather than a preference — see resolveCodeRequest in vault.ts.
 */

interface RateLimitEntry {
  timestamps: number[];
  /**
   * Carried on the entry rather than re-derived from the map key. Bucket names
   * contain colons ("2fa:get:secret") and so do composed keys, so splitting the
   * key back apart is ambiguous — and would silently sweep with the wrong
   * window.
   */
  windowMs: number;
}

interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

export const LIMITS: Record<string, RateLimitConfig> = {
  /** Per user, across every secret. The anti-enumeration limiter. */
  "2fa:get": { maxRequests: 10, windowMs: 300_000 },
  /** Per user AND secret. Bounds repeated pulls of one credential. */
  "2fa:get:secret": { maxRequests: 5, windowMs: 300_000 },
  "2fa:list": { maxRequests: 10, windowMs: 60_000 },
  /** Fires per keystroke, so it is deliberately loose. */
  "2fa:autocomplete": { maxRequests: 60, windowMs: 60_000 },
};

const entries = new Map<string, RateLimitEntry>();

export type RateLimitResult =
  | { allowed: true }
  | { allowed: false; retryAfterSeconds: number; rule: string };

function prune(entry: RateLimitEntry, windowMs: number, now: number): void {
  const cutoff = now - windowMs;
  entry.timestamps = entry.timestamps.filter((t) => t > cutoff);
}

/**
 * Consume one request from `bucket` for `key`.
 *
 * `key` is composed by the caller — a user id for the per-user buckets, or
 * `${userId}:${name}` for the per-secret one.
 */
export function checkRateLimit(
  bucket: string,
  key: string,
  now: number = Date.now(),
): RateLimitResult {
  const cfg = LIMITS[bucket];
  if (!cfg) return { allowed: true };

  const mapKey = `${bucket}:${key}`;
  const entry = entries.get(mapKey) ?? { timestamps: [], windowMs: cfg.windowMs };
  prune(entry, cfg.windowMs, now);

  if (entry.timestamps.length >= cfg.maxRequests) {
    entries.set(mapKey, entry);
    const oldest = entry.timestamps[0] ?? now;
    const retryAfterMs = oldest + cfg.windowMs - now;
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)),
      rule: getRateLimitRuleDescription(bucket) ?? bucket,
    };
  }

  entry.timestamps.push(now);
  entries.set(mapKey, entry);
  return { allowed: true };
}

/** Human-readable window, e.g. "minute", "5 minutes", "hour". */
export function formatRateLimitWindow(windowMs: number): string {
  if (windowMs >= 3_600_000 && windowMs % 3_600_000 === 0) {
    const h = windowMs / 3_600_000;
    return h === 1 ? "hour" : `${h} hours`;
  }
  if (windowMs >= 60_000 && windowMs % 60_000 === 0) {
    const m = windowMs / 60_000;
    return m === 1 ? "minute" : `${m} minutes`;
  }
  return `${Math.round(windowMs / 1000)} seconds`;
}

/** e.g. "10 per 5 minutes", for use in messages and help. */
export function getRateLimitRuleDescription(bucket: string): string | null {
  const cfg = LIMITS[bucket];
  if (!cfg) return null;
  return `${cfg.maxRequests} per ${formatRateLimitWindow(cfg.windowMs)}`;
}

/**
 * Drop entries with nothing left in window.
 *
 * A limiter that never evicts is fine when the user set is small and known.
 * Here any member of the guild can invoke the command — including people with
 * no grants at all — so the Map would otherwise grow without bound across a
 * process expected to run for months.
 */
export function sweep(now: number = Date.now()): number {
  let removed = 0;
  for (const [mapKey, entry] of entries) {
    prune(entry, entry.windowMs, now);
    if (entry.timestamps.length === 0) {
      entries.delete(mapKey);
      removed += 1;
    }
  }
  return removed;
}

/** Test seam. */
export function resetRateLimits(): void {
  entries.clear();
}

export function rateLimitEntryCount(): number {
  return entries.size;
}
