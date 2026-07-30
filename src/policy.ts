/**
 * The policy client. **The only outbound call this service makes.**
 *
 * 03 §3: "`custody` must never make an outbound call to anything but `policy`. No RPC providers, no
 * price feeds, no product services. Its network reachability is the whole security model." A service
 * that calls nothing cannot be pivoted through, which is why the indexer exists as a separate
 * service rather than custody talking to twelve RPC providers (AD-07, SD-13).
 *
 * WHAT POLICY IS AND IS NOT. AD-09: it DECIDES, callers ENFORCE. It is an ADDITIONAL gate, never a
 * replacement for the signing policy — a signing rule enforced by a remote call is a signing rule an
 * attacker bypasses by reaching the signer directly, or by making policy unavailable and hoping for
 * fail-open. So `signing.ts` never consults this file, and this file is reachable from exactly one
 * action: `custody.key.export`.
 *
 * FAIL-CLOSED, AND HERE THAT IS UNAMBIGUOUS. SD-10 splits actions into fail-closed and fail-open;
 * key export is named in AD-09's narrow fail-closed set. So a timeout, a 500, an open circuit or a
 * body this file cannot parse all produce `deny`. The cost of being wrong in that direction is a
 * user who must ask again tomorrow. The cost of the other direction is a private key handed out
 * during the one minute the risk engine was down.
 */

import { HttpClient } from '@cloudsforge/http'
import type { Logger } from '@cloudsforge/telemetry'

export type Effect = 'allow' | 'deny' | 'challenge' | 'review'

export interface PolicyRequest {
  readonly subject: string
  readonly action: string
  readonly resource: string
  readonly context: Record<string, unknown>
}

export interface PolicyDecision {
  readonly effect: Effect
  readonly reasons: readonly string[]
}

export interface PolicyClient {
  decide(request: PolicyRequest, options?: { requestId?: string }): Promise<PolicyDecision>
}

const EFFECTS = new Set<string>(['allow', 'deny', 'challenge', 'review'])

/** The decision returned when policy could not be asked. Named, so it is greppable in an audit. */
export function failClosed(reason: string): PolicyDecision {
  return { effect: 'deny', reasons: [`policy_unavailable:${reason}`] }
}

export function createPolicyClient(options: {
  baseUrl: string
  logger: Logger
  token?: () => Promise<string | undefined> | string | undefined
  fetch?: typeof globalThis.fetch
}): PolicyClient {
  const client = new HttpClient({
    baseUrl: options.baseUrl,
    name: 'policy',
    // Short. A decision that takes three seconds has already cost the user more than re-asking
    // tomorrow would, and a long deadline is how one slow upstream pins every worker in a process.
    defaultDeadlineMs: 2_000,
    defaultRetries: 1,
    ...(options.token ? { token: options.token } : {}),
    ...(options.fetch ? { fetch: options.fetch } : {}),
  })

  return {
    async decide(request, opts) {
      try {
        const body = await client.request<unknown>('/v1/decisions', {
          method: 'POST',
          body: request,
          // A decision is not a state change, so retrying one is safe — but `request` only retries
          // a POST when it is given an idempotency key, and the key must be stable across the
          // retries of ONE decision and different across two. The request id is exactly that.
          ...(opts?.requestId ? { idempotencyKey: opts.requestId, requestId: opts.requestId } : {}),
        })
        const parsed = parseDecision(body)
        if (!parsed) {
          options.logger.error('policy returned an undecodable body', { action: request.action })
          return failClosed('undecodable_body')
        }
        return parsed
      } catch (err) {
        // Logged at error, not warn: a custody decision that could not be made is an availability
        // incident on a control, and SDR-10 says that trade is accepted rather than invisible.
        options.logger.error('policy decision failed; failing closed', {
          action: request.action,
          err: err instanceof Error ? err.message : String(err),
        })
        return failClosed('unreachable')
      }
    },
  }
}

function parseDecision(body: unknown): PolicyDecision | null {
  if (typeof body !== 'object' || body === null) return null
  const record = body as Record<string, unknown>
  const effect = record['effect']
  if (typeof effect !== 'string' || !EFFECTS.has(effect)) return null
  const rawReasons = record['reasons']
  const reasons = Array.isArray(rawReasons) ? rawReasons.filter((r): r is string => typeof r === 'string') : []
  return { effect: effect as Effect, reasons }
}
