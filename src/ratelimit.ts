/**
 * Rate limiting on /sign and on address creation.
 *
 * SD-09: "Rate limiting — there is none." That is the whole of the context. forge-keyvault will
 * answer signing requests as fast as a caller can make them, which means a leaked credential is
 * bounded only by network throughput: the difference between one compromised token and every
 * customer's deposit swept is measured in seconds rather than in anything an operator could
 * interrupt.
 *
 * TWO DESIGN DECISIONS, BOTH OF WHICH ARE THE POINT.
 *
 * 1. **The counter is the audit table.** There is no `rate_limit_counters` table and no in-memory
 *    map. `signAttemptsSince` counts `signing_audit` rows for the actor in the window, and
 *    `addressesCreatedSince` counts `custody_keys`. A separate counter is a second thing to keep
 *    correct and it drifts the moment a path writes one and not the other; counting the durable
 *    record means the limit survives a restart, is queryable by an operator mid-incident, and — since
 *    REFUSALS are audited too — bites hardest on a caller probing gates in a loop. The cost is one
 *    indexed count per request, which is the cheapest query this service makes.
 *
 * 2. **It is per ACTOR, not per address or per user.** The thing being bounded is a credential, not
 *    a customer: an attacker holding one token spreads across thousands of addresses and thousands
 *    of user ids, and a per-address limit would never fire once. `actor` is `service:<name>` or
 *    `user:<id>` — exactly the identity SD-05 introduced so that "which caller" is answerable.
 *
 * WHAT THIS IS NOT. It is not a defence against a compromised credential; it is a delay, and a
 * delay is what turns "every key is gone" into "an alert fired and someone revoked a token". The
 * real control is scope minimisation and the 10-minute TTL (SD-05).
 */

export interface RateLimitDecision {
  readonly allowed: boolean
  readonly limit: number
  readonly used: number
  /** Seconds until the window rolls. Sent as `Retry-After`. */
  readonly retryAfterSeconds: number
}

export interface RateLimitRule {
  readonly limit: number
  readonly windowMs: number
}

export const SIGN_WINDOW_MS = 60_000
export const ADDRESS_WINDOW_MS = 3_600_000

/**
 * A fixed window, deliberately, rather than a sliding one or a token bucket.
 *
 * A fixed window admits up to 2× the limit across a boundary and that is understood and accepted:
 * the alternative needs either per-request state or a scan of individual timestamps, and neither
 * buys anything against the threat being bounded here, which is a sustained loop rather than a
 * precisely-timed burst. Stating the weakness is better than implying a precision this does not
 * have.
 */
export function decide(rule: RateLimitRule, used: number, now: number): RateLimitDecision {
  const elapsed = now % rule.windowMs
  const retryAfterSeconds = Math.max(1, Math.ceil((rule.windowMs - elapsed) / 1_000))
  return {
    allowed: used < rule.limit,
    limit: rule.limit,
    used,
    retryAfterSeconds,
  }
}

/** The start of the window a count must cover. */
export function windowStart(rule: RateLimitRule, now: number): Date {
  return new Date(now - (now % rule.windowMs))
}
