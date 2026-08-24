/**
 * The HTTP surface.
 *
 * Plain `node:http`, following the service template. The parts that matter — request ids, RED
 * metrics, the child logger, the error shape, the auth-fault mapping — are framework-independent,
 * and custody is not the service in which to introduce a framework's opinions about body parsing.
 *
 * **THE SMALLEST ROUTE SURFACE IN THE ESTATE, ON PURPOSE.** SD-06 names it as one of the three
 * compensating controls for custody's residual risks. Every route below had to justify existing,
 * and one that used to exist does not:
 *
 *   `POST /admin/keys/:address/reveal` IS DELETED (SD-08). It returned any private key in plaintext
 *   to any holder of an administrator JWT, in a system with no MFA on administrator accounts. A loop
 *   over `GET /admin/keys` followed by it exfiltrated the entire custody estate, and its only
 *   mitigation was an audit row — which tells you afterwards that every key is gone. It is not
 *   registered here, it answers 404 like any other unknown path, and `server.test.ts` asserts that
 *   rather than trusting it. The genuine break-glass cases are met by a two-operator offline
 *   procedure against a database backup, which needs no network-reachable endpoint at all.
 *
 * **EXACTLY ONE ROUTE IN THIS FILE CAN RETURN KEY MATERIAL**: `POST /v1/exports/:id/redeem`, the
 * last gate of the SD-07 ceremony, reachable only by the key's own owner, only after a 24-hour hold
 * and a second MFA challenge, and only once. `bodyscan.test.ts` drives every other route and proves
 * none of them can — SD-16's response-body scan, as a test rather than as a claim.
 *
 * A bad token is 401. A verifier that could not reach the JWKS is **503**, never 401 — answering 401
 * there signs every user in the estate out because identity is having a bad minute.
 */

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import {
  ForbiddenError,
  TokenError,
  bearerFrom,
  isAdmin,
  requireAdmin,
  requireScope,
  statusFor,
  type Principal,
} from '@cloudsforge/auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { familyForChain, isKnownChain, type KeyNetwork } from './chains.ts'
import { signScopeFor } from './gates.ts'
import { provisionAddress, signForAddress, type KeyDeps } from './keys.ts'
import {
  EXPORT_FORMATS,
  cancelExport,
  challengeExport,
  listExportsForUser,
  redeemExport,
  requestExport,
  toExportRecord,
  getExport,
  type ExportDeps,
  type ExportFormat,
} from './exports.ts'
import { ADDRESS_WINDOW_MS, SIGN_WINDOW_MS, decide, windowStart } from './ratelimit.ts'
import { remainingCount } from './reencrypt.ts'
import {
  addressesCreatedSince,
  getKey,
  listKeys,
  listKeysForUser,
  listSigningAudit,
  listTokenContracts,
  listTreasuryPins,
  outstandingPoolPayout,
  outstandingTreasuryCandidate,
  pinTreasury,
  poolPayoutBinding,
  signAttemptsSince,
  toKeyAdminRecord,
  toKeyRecord,
  treasuryBinding,
  type PinRefusal,
  type Purpose,
  type Scheme,
} from './store.ts'

/**
 * The verifier as this file needs it. `verify` as well as `principal`, because the export ceremony
 * has to read `amr` and `auth_time` — the claims that carry "this person proved a password" and
 * "this person completed a factor, just now". `Principal` deliberately does not expose them, since
 * no other service has any business branching on them.
 */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
  verify(token: string): Promise<Record<string, unknown>>
}

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  readonly keys: KeyDeps
  readonly exports: ExportDeps
  readonly limits: { readonly signPerMinute: number; readonly addressPerHour: number }
  readonly now?: () => number
  readonly beforeScrape?: () => Promise<void>
}

/**
 * The scopes. SD-05 names the three signing ones; the other two are custody's own, and they are
 * separate because minting an address and reading a treasury pin are different authorities from
 * signing and are held by different callers.
 */
export const ADDRESS_CREATE_SCOPE = 'custody:address:create'
export const TREASURY_READ_SCOPE = 'custody:treasury:read'

const MAX_BODY_BYTES = 256 * 1024
/** Kept equal to migration 6's `custody_keys_idempotency_ck`, so the two cannot disagree. */
const MAX_IDEMPOTENCY_KEY_LENGTH = 255
const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/
const NETWORKS = new Set(['mainnet', 'testnet'])
/**
 * The purposes the mint route accepts. Kept equal to `custody_keys_purpose_ck` (migrations 4 and 8),
 * so a value this set admits is a value the database will store rather than a 500 in the shape of a
 * check violation.
 *
 * `pool` is here so micro-pool's coinbase payout address can be a custody key — see migration 8 for
 * why it is a purpose of its own and, in particular, why it is not `treasury`. Accepting it here
 * grants nothing beyond minting: `gates.SIGNABLE_PURPOSES` does not contain it, so /sign refuses a
 * `pool` address at gate 1, and no `custody:sign:pool` scope is issued by anything in the estate.
 */
const PURPOSES = new Set<Purpose>(['deposit', 'treasury', 'deployer', 'user', 'pool'])
const SCHEMES = new Set<Scheme>(['flat_random', 'hd_bip44'])

/** Domain metrics, declared rather than inferred from a log line — AD-20. */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'custody_signatures_total',
      help: 'Signing requests, by network, purpose and outcome. A refusal is a signature that did not happen.',
      kind: 'counter',
      // `network` because ONE custody now serves both estates (micro-deploy
      // `docs/network-consolidation.md`). Without it a testnet signing refusal and a mainnet one
      // are the same series — and on this service that is the difference between "somebody is
      // probing our key material" and "the testnet faucet is misconfigured again".
      labels: ['network', 'purpose', 'outcome'],
    })
    .register({
      name: 'custody_sign_refusals_total',
      help: 'Signing refusals by network and by the gate that refused them. A shift between gates is a caller changing shape.',
      kind: 'counter',
      labels: ['network', 'gate'],
    })
    .register({
      name: 'custody_addresses_created_total',
      help: 'Addresses minted, by network and scheme. `flat_random` must never increase for XRP.',
      kind: 'counter',
      labels: ['network', 'scheme', 'purpose'],
    })
    .register({
      name: 'custody_addresses_replayed_total',
      help:
        'Provisioning requests answered with an address that already existed. Counted separately ' +
        'because a replay is not a mint: this rising while `created_total` does not is a caller ' +
        'retrying, and both rising together is a caller minting.',
      kind: 'counter',
      labels: ['network', 'purpose'],
    })
    .register({
      name: 'custody_rate_limited_total',
      help: 'Requests refused by the rate limiter, by surface.',
      kind: 'counter',
      labels: ['surface'],
    })
    .register({
      name: 'custody_key_version_backlog',
      help: 'Blobs still on an envelope version below the write version. A rotation is finished at 0.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'custody_exports_total',
      help: 'Export ceremony transitions, by stage.',
      kind: 'counter',
      labels: ['stage'],
    })
}

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
  readonly headers?: Record<string, string>
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
}

interface Route {
  readonly method: string
  /** `:name` segments become `ctx.params.name`. */
  readonly path: string
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const matched = matchRoute(routes, req.method ?? 'GET', url.pathname)
    // Unmatched paths collapse to one label. Using the raw path would let any caller mint unbounded
    // time series and take the scrape target down with cardinality.
    const routeLabel = matched ? matched.route.path : 'unmatched'
    const log = deps.logger.child({ requestId, method: req.method ?? 'GET', route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method: req.method ?? 'GET',
        route: routeLabel,
        status: String(status),
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, { method: req.method ?? 'GET', route: routeLabel })
    }

    void handle(matched, { req, url, requestId, log, params: matched?.params ?? {} }, deps)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status)
      })
      .catch((err: unknown) => {
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500)
      })
  })
}

function matchRoute(
  routes: readonly Route[],
  method: string,
  pathname: string,
): { route: Route; params: Record<string, string> } | undefined {
  const parts = pathname.split('/').filter((p) => p.length > 0)
  for (const route of routes) {
    if (route.method !== method) continue
    const pattern = route.path.split('/').filter((p) => p.length > 0)
    if (pattern.length !== parts.length) continue
    const params: Record<string, string> = {}
    let ok = true
    for (const [i, segment] of pattern.entries()) {
      const actual = parts[i]!
      if (segment.startsWith(':')) params[segment.slice(1)] = decodeURIComponent(actual)
      else if (segment !== actual) {
        ok = false
        break
      }
    }
    if (ok) return { route, params }
  }
  return undefined
}

async function handle(
  matched: { route: Route; params: Record<string, string> } | undefined,
  ctx: RequestContext,
  deps: ServerDeps,
): Promise<Reply> {
  if (!matched) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    return await matched.route.handle(ctx, deps)
  } catch (err) {
    const authStatus = statusFor(err)
    if (authStatus === 401) {
      // The reason is logged, never returned — "signature verification failed" versus "expired"
      // tells an attacker which half of a forged token to fix.
      ctx.log.info('unauthenticated request', { err })
      return errorReply(401, 'unauthenticated', 'a valid bearer token is required', ctx.requestId)
    }
    if (authStatus === 403) {
      const required = err instanceof ForbiddenError ? err.required : 'unknown'
      ctx.log.info('forbidden request', { required })
      return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
    }
    if (authStatus === 503) {
      ctx.log.error('token verifier unavailable', { err })
      return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    if (err instanceof BadRequestError) return errorReply(400, 'bad_request', err.message, ctx.requestId)
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

/**
 * The route table as data: every route this server will match, in declaration order.
 *
 * **This exists so that `bodyscan.test.ts` cannot be wrong about the surface it covers.** SD-16's
 * response-body scan claims to drive every route; it used to claim that against a list typed out by
 * hand, which meant a route added here was a route the scan silently stopped covering — and two of
 * them were, for as long as it took someone to read the two files side by side. The scan now
 * reconciles its samples against this function and fails naming any route it cannot drive.
 *
 * Derived from `buildRoutes()` rather than written beside it, so the two cannot disagree. Only the
 * method and path are published: a handler is not something a test has any business calling
 * directly, since half of what the scan asserts is a property of the transport.
 */
export function routeTable(): ReadonlyArray<{ readonly method: string; readonly path: string }> {
  return buildRoutes().map((route) => ({ method: route.method, path: route.path }))
}

function buildRoutes(): Route[] {
  return [
    {
      method: 'GET',
      path: '/livez',
      // Static, deliberately. A liveness probe that consults a dependency restarts a healthy process
      // every time the database blinks. Readiness is where dependencies belong.
      handle: async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() }),
    },
    {
      method: 'GET',
      path: '/readyz',
      handle: async (_ctx, deps) => {
        const report = await deps.lifecycle.readyz()
        return { status: report.ready ? 200 : 503, body: report }
      },
    },
    {
      method: 'GET',
      path: '/metrics',
      handle: async (ctx, deps) => {
        try {
          await deps.beforeScrape?.()
        } catch (err) {
          ctx.log.warn('gauge refresh failed; serving the previous values', { err })
        }
        return { status: 200, text: deps.metrics.render(), contentType: 'text/plain; version=0.0.4; charset=utf-8' }
      },
    },

    /* ---------------------------------------------------------------- provisioning */
    {
      method: 'POST',
      path: '/v1/addresses',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireScope(principal, ADDRESS_CREATE_SCOPE)
        const actor = actorOf(principal)

        const limited = await limitAddresses(deps, actor)
        if (limited) return limited

        const body = await readJson(ctx.req)
        const chain = stringField(body, 'chain')
        const userId = stringField(body, 'userId')
        const orderId = stringField(body, 'orderId')
        const network = enumField(body, 'network', NETWORKS, 'testnet') as KeyNetwork
        const purpose = enumField(body, 'purpose', PURPOSES as ReadonlySet<string>, 'deposit') as Purpose
        const scheme = enumField(body, 'scheme', SCHEMES as ReadonlySet<string>, 'hd_bip44') as Scheme
        // A HEADER, not a body field, because that is where both callers put it: `@cloudsforge/http`
        // sets `idempotency-key` from `request.idempotencyKey`, and it also RETRIES a POST that
        // carries one. Reading it here is what makes that retry safe instead of what makes it mint.
        const idempotencyKey = idempotencyKeyOf(ctx.req)

        const done = deps.lifecycle.track()
        try {
          const result = await provisionAddress(deps.keys, {
            chain,
            network,
            purpose,
            userId,
            orderId,
            scheme,
            createdBy: actor,
            correlationId: ctx.requestId,
            ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
          })
          if (!result.ok) return errorReply(result.status, result.code, result.error, ctx.requestId)
          if (result.reused) {
            // 200 AND `reused`, the vocabulary the treasury mint route below already speaks. A 201
            // here would tell a caller — and every log, metric and dashboard reading the status —
            // that an address was created, which is the one thing that did not happen.
            deps.metrics.increment('custody_addresses_replayed_total', { network, purpose })
            return { status: 200, body: { key: result.key, reused: true } }
          }
          deps.metrics.increment('custody_addresses_created_total', { network, scheme, purpose })
          // NEVER the private key. The response is the secret-free projection and nothing else.
          return { status: 201, body: { key: result.key } }
        } finally {
          done()
        }
      },
    },
    {
      method: 'GET',
      path: '/v1/addresses/:address',
      /*
       * Existence and placement. NOT `userId`, NOT `orderId`.
       *
       * This route used to publish both in forge-keyvault, which made the /sign binding check
       * circular: everything a caller had to "prove" it knew was served, under the same credential,
       * from a read. The binding's entropy is entirely in those two fields — chain, network, family
       * and purpose have about twenty possible values between them — so they are what stopped being
       * published. `GET /v1/admin/keys/:address` serves them to an operator, which is a different
       * credential with a different audience.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, ADDRESS_CREATE_SCOPE)
        const row = await getKey(deps.keys.sql, ctx.params.address!)
        if (!row) return errorReply(404, 'not_found', 'address not found', ctx.requestId)
        if (principal.kind === 'user' && !isAdmin(principal) && row.user_id !== principal.userId) {
          // Not 403: a 403 confirms the address exists, which is the fact a user who does not own it
          // has no business learning.
          return errorReply(404, 'not_found', 'address not found', ctx.requestId)
        }
        return { status: 200, body: { key: toKeyRecord(row) } }
      },
    },
    {
      method: 'GET',
      path: '/v1/keys',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind !== 'user') throw new ForbiddenError('user token')
        const rows = await listKeysForUser(deps.keys.sql, principal.userId, 200)
        return { status: 200, body: { keys: rows.map(toKeyRecord) } }
      },
    },

    /* ---------------------------------------------------------------- treasury pin (read) */
    {
      method: 'GET',
      path: '/v1/treasuries/:chain/:network',
      /*
       * READ the pin, and only read. There is deliberately NO write route on this surface: a signing
       * credential can read the pin and can never set, rotate or influence it. If that stopped being
       * true the sweep shape would become a total-loss vulnerability rather than a containment —
       * anyone who can mint a `treasury` address would pin their own and sweep every deposit to it.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, TREASURY_READ_SCOPE)
        const { chain, network } = ctx.params as { chain: string; network: string }
        if (!NETWORKS.has(network)) return errorReply(400, 'bad_request', 'network must be mainnet or testnet', ctx.requestId)
        const pins = await listTreasuryPins(deps.keys.sql)
        const pin = pins.find((p) => p.chain === chain && p.network === network)
        if (!pin) {
          return errorReply(404, 'no_treasury_pinned', `no treasury is pinned for '${chain}' ${network}`, ctx.requestId)
        }
        // The operator's `sub` and the timestamp stay on the admin surface; a peer service needs the
        // address and nothing else.
        return { status: 200, body: { chain, network, address: pin.address } }
      },
    },

    /* ---------------------------------------------------------------- token allowlist (read) */
    {
      method: 'GET',
      path: '/v1/token-contracts',
      /*
       * THE ALLOWLIST, READ BY THE SERVICE THAT MUST NOT DISAGREE WITH IT.
       *
       * `assertTokenSweep` refuses a token sweep whose `to` is not in `custody_token_contracts` for
       * the row's own (chain, network). `micro-settlement` is the caller that builds those sweeps,
       * and if it holds its own copy of the list — a config file, an env var, a table of its own —
       * then the day the two disagree is a sweep built, committed, and 403'd AFTER the chain's
       * single outbound slot has been claimed, with a `shape_refused` that says nothing about which
       * side is stale. So there is one list and this is how the other side reads it.
       *
       * **READ, AND ONLY READ**, for the treasury pin's reason stated one route above. Registering
       * a token is `PUT /v1/admin/token-contracts` under an operator's token: a signing credential
       * that could add to this allowlist could register a contract of its own and make a customer's
       * deposit key execute it, which is the precise capability the allowlist exists to bound.
       *
       * `custody:treasury:read` rather than a scope of its own. The two answer the same question —
       * "what has an operator configured this vault to permit" — they are read by the same caller
       * for the same purpose in the same pass, and a new scope would have to be registered,
       * granted and deployed before a single token could be swept. Reusing it widens nothing: every
       * holder of it can already read the pin, which is the more sensitive of the two.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        if (principal.kind === 'service') requireScope(principal, TREASURY_READ_SCOPE)
        const rows = await listTokenContracts(deps.keys.sql)
        // `set_by` and `set_at` stay on the admin surface. A peer needs what to call and what it is
        // denominated in; who registered it is an operator's audit question.
        return {
          status: 200,
          body: {
            tokens: rows.map((row) => ({
              chain: row.chain,
              network: row.network,
              contract: row.contract,
              symbol: row.symbol,
              decimals: row.decimals,
            })),
          },
        }
      },
    },

    /* ---------------------------------------------------------------- signing */
    {
      method: 'POST',
      path: '/v1/sign',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        const body = await readJson(ctx.req)
        const claimedPurpose = stringField(body, 'purpose')
        if (!PURPOSES.has(claimedPurpose as Purpose)) throw new BadRequestError('purpose is not one this service knows')
        // The scope is checked against the CLAIMED purpose, before the row is loaded, so an
        // unscoped caller cannot use this route to probe which addresses exist. If the claim
        // disagrees with the row the binding check refuses it a moment later anyway.
        requireScope(principal, signScopeFor(claimedPurpose))
        const actor = actorOf(principal)

        const limited = await limitSigning(deps, actor)
        if (limited) return limited

        const request = {
          address: stringField(body, 'address'),
          chain: stringField(body, 'chain'),
          network: stringField(body, 'network'),
          family: stringField(body, 'family'),
          purpose: claimedPurpose,
          userId: stringField(body, 'userId'),
          orderId: stringField(body, 'orderId'),
          payload: body['payload'],
          actor,
          correlationId: ctx.requestId,
        }
        if (request.payload === undefined) throw new BadRequestError('payload is required')

        // ══════════════════════════════════════════════════════════════════════════════════════
        // THE LABEL MUST BE BOUNDED, AND `request.network` IS RAW CALLER INPUT.
        // ══════════════════════════════════════════════════════════════════════════════════════
        //
        // `stringField(body, 'network')` is whatever the caller sent. `signForAddress` refuses an
        // unknown one at its binding check — but the counters below are incremented on the REFUSAL
        // path too, so labelling them with the raw value hands any caller two things:
        //
        //   1. unbounded cardinality. A loop posting a fresh uuid as `network` mints a new time
        //      series per request; 13-operational-model §13 budgets 500k active series for the
        //      whole estate, and this route would spend them. The same reasoning is written on
        //      beacon's `probes.target`: a metric label must be bounded by something the SERVICE
        //      controls, never by something a caller does.
        //
        //   2. attribution they do not own. A caller could book its own refusals against whichever
        //      estate it liked, which is the opposite of what this label was added for.
        //
        // `invalid` rather than dropping the label: it keeps the series bounded at three AND says
        // something true and useful — "somebody is sending nonsense here" is a different alert
        // from "testnet signing is failing", and collapsing them would hide the first.
        const networkLabel = NETWORKS.has(request.network) ? request.network : 'invalid'

        const done = deps.lifecycle.track()
        try {
          const outcome = await signForAddress(deps.keys, request)
          if (!outcome.ok) {
            deps.metrics.increment('custody_signatures_total', {
              network: networkLabel,
              purpose: claimedPurpose,
              outcome: 'refused',
            })
            deps.metrics.increment('custody_sign_refusals_total', { network: networkLabel, gate: outcome.gate })
            return errorReply(outcome.status, outcome.code, outcome.error, ctx.requestId)
          }
          deps.metrics.increment('custody_signatures_total', {
            network: networkLabel,
            purpose: claimedPurpose,
            outcome: 'signed',
          })
          // The signature, and the id of the audit row committed with it. Nothing else — and in
          // particular not the key, not the payload and not the address's binding.
          return { status: 200, body: { signedTx: outcome.signedTx, auditId: outcome.auditId } }
        } finally {
          done()
        }
      },
    },

    /* ---------------------------------------------------------------- the export ceremony */
    {
      method: 'POST',
      path: '/v1/exports',
      handle: async (ctx, deps) => {
        const { principal, claims } = await authenticateUser(ctx, deps)
        const body = await readJson(ctx.req)
        const address = stringField(body, 'address')
        const format = enumField(body, 'format', new Set(EXPORT_FORMATS), 'keystore') as ExportFormat

        const result = await requestExport(deps.exports, {
          address,
          userId: principal.userId,
          format,
          actor: `user:${principal.userId}`,
          correlationId: ctx.requestId,
          amr: amrOf(claims),
          context: { ip: ctx.req.socket.remoteAddress ?? null },
        })
        if (!result.ok) return errorReply(result.status, result.code, result.error, ctx.requestId)
        deps.metrics.increment('custody_exports_total', { stage: result.value.status })
        return { status: 201, body: { export: result.value } }
      },
    },
    {
      method: 'GET',
      path: '/v1/exports',
      handle: async (ctx, deps) => {
        const { principal } = await authenticateUser(ctx, deps)
        const rows = await listExportsForUser(deps.exports.sql, principal.userId, 100)
        return { status: 200, body: { exports: rows.map(toExportRecord) } }
      },
    },
    {
      method: 'GET',
      path: '/v1/exports/:id',
      handle: async (ctx, deps) => {
        const { principal } = await authenticateUser(ctx, deps)
        const row = await getExport(deps.exports.sql, ctx.params.id!)
        if (!row || row.user_id !== principal.userId) {
          return errorReply(404, 'not_found', 'export request not found', ctx.requestId)
        }
        return { status: 200, body: { export: toExportRecord(row) } }
      },
    },
    {
      method: 'POST',
      path: '/v1/exports/:id/cancel',
      handle: async (ctx, deps) => {
        const { principal } = await authenticateUser(ctx, deps)
        const result = await cancelExport(deps.exports, {
          id: ctx.params.id!,
          userId: principal.userId,
          actor: `user:${principal.userId}`,
          correlationId: ctx.requestId,
        })
        if (!result.ok) return errorReply(result.status, result.code, result.error, ctx.requestId)
        deps.metrics.increment('custody_exports_total', { stage: 'cancelled' })
        return { status: 200, body: { export: result.value } }
      },
    },
    {
      method: 'POST',
      path: '/v1/exports/:id/challenge',
      handle: async (ctx, deps) => {
        const { principal, claims } = await authenticateUser(ctx, deps)
        const result = await challengeExport(deps.exports, {
          id: ctx.params.id!,
          userId: principal.userId,
          amr: amrOf(claims),
          authTimeSeconds: typeof claims['auth_time'] === 'number' ? claims['auth_time'] : null,
          correlationId: ctx.requestId,
        })
        if (!result.ok) return errorReply(result.status, result.code, result.error, ctx.requestId)
        deps.metrics.increment('custody_exports_total', { stage: 'challenged' })
        // The reveal token, once. `no-store` is set on every response this server sends, which is
        // SD-07 gate 8's "never in a cacheable response" — and it is set centrally rather than here
        // so a new route cannot forget it.
        return { status: 200, body: { export: result.value.export, revealToken: result.value.revealToken } }
      },
    },
    {
      method: 'POST',
      path: '/v1/exports/:id/redeem',
      /*
       * THE ONE ROUTE IN THIS SERVICE THAT RETURNS KEY MATERIAL.
       *
       * Reachable only by the key's owner, only after policy allowed it, only after the 24-hour
       * cooling-off, only with a fresh second factor, only with the single-use token minted by the
       * challenge, and only once — the redemption transitions the wallet to `exported` in the same
       * transaction that spends the token, so a replay updates no row and returns nothing.
       */
      handle: async (ctx, deps) => {
        const { principal } = await authenticateUser(ctx, deps)
        const body = await readJson(ctx.req)
        const revealToken = stringField(body, 'revealToken')
        const passphrase = typeof body['passphrase'] === 'string' ? body['passphrase'] : undefined
        const result = await redeemExport(deps.exports, {
          id: ctx.params.id!,
          userId: principal.userId,
          revealToken,
          ...(passphrase === undefined ? {} : { passphrase }),
          correlationId: ctx.requestId,
        })
        if (!result.ok) return errorReply(result.status, result.code, result.error, ctx.requestId)
        deps.metrics.increment('custody_exports_total', { stage: 'redeemed' })
        return { status: 200, body: { export: result.value } }
      },
    },

    /* ---------------------------------------------------------------- operator surface */
    {
      method: 'GET',
      path: '/v1/admin/keys',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const rows = await listKeys(deps.keys.sql, 500)
        return { status: 200, body: { keys: rows.map(toKeyAdminRecord) } }
      },
    },
    {
      method: 'GET',
      path: '/v1/admin/keys/:address',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const row = await getKey(deps.keys.sql, ctx.params.address!)
        if (!row) return errorReply(404, 'not_found', 'address not found', ctx.requestId)
        return { status: 200, body: { key: toKeyAdminRecord(row) } }
      },
    },
    {
      method: 'GET',
      path: '/v1/admin/keys/:address/audit',
      /*
       * What replaces `reveal` on the operator surface: the signing history of an address, which is
       * what an investigation actually needs. The rows carry digests rather than payloads or
       * signatures — a signed transaction in a response is a submittable transaction.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const rows = await listSigningAudit(deps.keys.sql, ctx.params.address!, 200)
        return { status: 200, body: { audit: rows } }
      },
    },
    {
      method: 'GET',
      path: '/v1/admin/treasuries',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        return { status: 200, body: { treasuries: await listTreasuryPins(deps.keys.sql) } }
      },
    },
    {
      method: 'POST',
      path: '/v1/admin/treasuries/:chain/:network/mint',
      /*
       * Mint a ROTATION CANDIDATE, and deliberately do NOT pin it.
       *
       * Without this route the pin can rotate and nothing can ever give it somewhere to rotate to:
       * `pinTreasury` refuses anything that is not a second `treasury`-purpose address on the same
       * chain and network, and the only other minting route is on the signing surface, which an
       * operator does not hold and a browser cannot reach.
       *
       * Pinning here would point every future sweep at an address holding nothing, in the same
       * request that created it, while the withdrawer still pays out of the old one. Rotation stays
       * three deliberate steps — mint, move the balance, then pin — and this is only the first.
       *
       * It does not mint twice: everything it writes is derived from the path, so two calls a minute
       * apart are the SAME request. A call that finds an outstanding candidate returns THAT one with
       * 200 and `reused: true`, and creates nothing.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const { chain, network } = ctx.params as { chain: string; network: string }
        if (!NETWORKS.has(network)) return errorReply(400, 'bad_request', 'network must be mainnet or testnet', ctx.requestId)
        if (!isKnownChain(chain) || !familyForChain(chain)) {
          return errorReply(400, 'unknown_chain', `'${chain}' is not a chain this service holds keys for`, ctx.requestId)
        }

        const outstanding = await outstandingTreasuryCandidate(deps.keys.sql, chain, network)
        if (outstanding) {
          ctx.log.info('treasury mint reused an outstanding candidate', {
            audit: 'treasury_mint_reused',
            chain,
            network,
            address: outstanding.address,
          })
          return { status: 200, body: { key: toKeyAdminRecord(outstanding), pinned: false, reused: true } }
        }

        const binding = treasuryBinding(chain, network as KeyNetwork)
        const result = await provisionAddress(deps.keys, {
          chain,
          network: network as KeyNetwork,
          purpose: 'treasury',
          userId: binding.userId,
          orderId: binding.orderId,
          // A treasury belongs to the platform, not to a user, so there is no per-user seed for it
          // to hang off and HD derivation would have to invent one. Flat random is the honest
          // answer, and a treasury has no recovery phrase to offer anybody anyway.
          scheme: 'flat_random',
          createdBy: actorOf(principal),
          correlationId: ctx.requestId,
        })
        if (!result.ok) return errorReply(result.status, result.code, result.error, ctx.requestId)

        ctx.log.warn('treasury candidate minted', {
          audit: 'treasury_minted',
          chain,
          network,
          address: result.key.address,
          msg: 'it is NOT pinned and nothing sweeps to it yet — move the balance off the current treasury, then pin',
        })
        return { status: 201, body: { key: result.key, pinned: false, reused: false } }
      },
    },
    {
      method: 'POST',
      path: '/v1/admin/pool-payouts/:chain/:network/mint',
      /*
       * Mint the MINING POOL'S PAYOUT ADDRESS, and deliberately tell nobody about it.
       *
       * The route above states the general form of the problem and this route is the second
       * instance of it: `POST /v1/addresses` is the only route that mints a purpose the caller
       * names, `hasScope` opens with `if (principal.kind !== 'service') return false`, and so an
       * operator bearer can never pass its gate however many roles it carries. Nor can any service
       * pass it FOR THIS PURPOSE: the three grants holding `custody:address:create` are foresight,
       * mint and wallet, each derived from an outbound call it actually makes, and micro-pool makes
       * none — it reads one string out of `POOL_<CHAIN>_PAYOUT_ADDRESS` and refuses to boot without
       * it. So minting the pool's payout address without this route means borrowing wallet's
       * credential, and `custody_keys.created_by` then records `service:wallet` for ever as the
       * creator of the address every block reward on the platform pays into. The one column that
       * answers "who made this" would name a service that has never heard of the pool.
       *
       * `requireAdmin`, therefore, and NOT the address scope — a human, named in `created_by` as a
       * human. That is also why this is not a second entry point onto the signing surface's gate:
       * a holder of `custody:address:create` is refused here, which `server.test.ts` asserts rather
       * than assumes.
       *
       * `flat_random`, for the treasury route's reason. A pool payout address belongs to the
       * platform rather than to a user, so there is no per-user seed for it to hang off and HD
       * derivation would have to invent one; and there is no recovery phrase to offer anybody
       * either, since nobody outside this service is ever entitled to this key. (The estate does
       * hold HD `pool` keys minted by hand through `POST /v1/addresses` under a platform user id —
       * they are legitimate and this route hands them back untouched. What it will not do is mint a
       * NEW one that way.)
       *
       * ── IT PINS NOTHING, AND IT CONFIGURES NOTHING ───────────────────────────────────────────
       *
       * Nothing here touches `custody_treasuries`, and nothing may: migration 8's argument is that
       * a `pool` row must never appear in that table, because `outstandingTreasuryCandidate` hands
       * the newest unpinned treasury back as the next rotation candidate and micro-pool mines a
       * chain settlement pins. `pool` is a purpose of its own precisely so that cannot happen, and
       * this route is not the place it quietly starts happening.
       *
       * Telling micro-pool is likewise the operator's separate, deliberate step:
       * `POOL_<CHAIN>_PAYOUT_ADDRESS` names the address, and until it does the address is inert —
       * no coinbase is paid to it and nothing watches it. The response says so with
       * `configured: false`, which is always false for the same reason the treasury mint's
       * `pinned: false` always is. Note also that this service could not synthesise that variable's
       * name even if it wanted to: micro-pool keys its chains as `btc` and `ltc` (`pool/src/env.ts`)
       * where custody names them `bitcoin` and `litecoin`, so the variable for a litecoin address is
       * `POOL_LTC_PAYOUT_ADDRESS`. Guessing across that mapping is how an operator is handed a
       * variable name that does not exist.
       *
       * ── IT DOES NOT MINT TWICE, AND THE DATABASE IS NOT WHAT SAYS SO ─────────────────────────
       *
       * Everything written is derived from the path — `poolPayoutBinding` — so two calls a minute
       * apart are the SAME request, and the second returns the first address with 200 and
       * `reused: true`, creating nothing. That rule is `outstandingPoolPayout` and it is a QUERY on
       * purpose: migration 8 refused `unique (chain, network) where purpose = 'pool'` in writing,
       * because a pool payout key accumulates every block the pool ever finds and is therefore
       * exactly the key an operator must be able to abandon and replace. Under that index the
       * replacement mint is a 23505 no operator can act on. So the idempotency lives here, and this
       * route must not become the thing that makes rotation impossible either: the reuse is filtered
       * on `status = 'active'`, so retiring the row it hands back makes the next call a 201 and the
       * abandoned row stays in `custody_keys` still saying who holds the coin at it.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const { chain, network } = ctx.params as { chain: string; network: string }
        if (!NETWORKS.has(network)) return errorReply(400, 'bad_request', 'network must be mainnet or testnet', ctx.requestId)
        if (!isKnownChain(chain) || !familyForChain(chain)) {
          return errorReply(400, 'unknown_chain', `'${chain}' is not a chain this service holds keys for`, ctx.requestId)
        }

        const outstanding = await outstandingPoolPayout(deps.keys.sql, chain, network)
        if (outstanding) {
          ctx.log.info('pool payout mint reused the live payout address', {
            audit: 'pool_payout_mint_reused',
            chain,
            network,
            address: outstanding.address,
          })
          return { status: 200, body: { key: toKeyAdminRecord(outstanding), configured: false, reused: true } }
        }

        const binding = poolPayoutBinding(chain, network as KeyNetwork)
        const result = await provisionAddress(deps.keys, {
          chain,
          network: network as KeyNetwork,
          purpose: 'pool',
          userId: binding.userId,
          orderId: binding.orderId,
          scheme: 'flat_random',
          createdBy: actorOf(principal),
          correlationId: ctx.requestId,
        })
        if (!result.ok) return errorReply(result.status, result.code, result.error, ctx.requestId)

        ctx.log.warn('pool payout address minted', {
          audit: 'pool_payout_minted',
          chain,
          network,
          address: result.key.address,
          msg:
            'it is NOT configured anywhere and the pool will not use it until POOL_<CHAIN>_PAYOUT_ADDRESS ' +
            'names it — set that, then restart micro-pool',
        })
        // Re-read rather than publish `provisionAddress`'s own return value, which is the PUBLIC
        // projection: `toKeyAdminRecord` is what an operator surface serves, it is what the reuse
        // branch above serves, and a route whose two branches answer with different field sets is a
        // route every caller has to parse twice. What the admin projection adds is the binding, and
        // the binding is the fact an operator investigating a platform-owned address needs most.
        // Still never the key itself — this route creates key material and returns none.
        const row = await getKey(deps.keys.sql, result.key.address)
        if (!row) throw new Error('the pool payout address was not readable immediately after its own insert')
        return { status: 201, body: { key: toKeyAdminRecord(row), configured: false, reused: false } }
      },
    },
    {
      method: 'PUT',
      path: '/v1/admin/treasuries/:chain/:network',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const { chain, network } = ctx.params as { chain: string; network: string }
        if (!NETWORKS.has(network)) return errorReply(400, 'bad_request', 'network must be mainnet or testnet', ctx.requestId)
        const body = await readJson(ctx.req)
        const address = stringField(body, 'address')

        const result = await pinTreasury(deps.keys.sql, {
          chain,
          network,
          address,
          setBy: actorOf(principal),
        })
        if ('refusal' in result) {
          return errorReply(400, result.refusal, PIN_REFUSAL_REASON[result.refusal], ctx.requestId)
        }
        const superseded =
          result.previous && result.previous.address !== result.current.address ? result.previous.address : null
        if (superseded) {
          // ROTATION, AND IT IS LOUD ON PURPOSE. The superseded row is deliberately not touched, so
          // its balance stays spendable — but nothing MOVES by itself, and the withdrawer pays from
          // the pinned address only. An un-drained old treasury presents as "deposits are
          // consolidating and withdrawals are starving", with no error anywhere unless this fires.
          ctx.log.warn('treasury rotated', {
            audit: 'treasury_rotated',
            chain,
            network,
            supersededAddress: superseded,
            address: result.current.address,
          })
        } else {
          ctx.log.warn('treasury pinned', { audit: 'treasury_pinned', chain, network, address: result.current.address })
        }
        return { status: 200, body: { ...result.current, supersededAddress: superseded } }
      },
    },
    {
      method: 'GET',
      path: '/v1/admin/rotation',
      /*
       * The master-secret rotation's progress. An operator needs a number to watch to zero before
       * removing the old `CUSTODY_MASTER_SECRET_V<n>` — see `reencrypt.ts`. Removing it early is the
       * one way this rotation loses a key.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const target = deps.keys.keyring.writeVersion
        return {
          status: 200,
          body: {
            writeVersion: target,
            readableVersions: deps.keys.keyring.readableVersions,
            remaining: await remainingCount(deps.keys.sql, target),
          },
        }
      },
    },
  ]
}

/** What an operator can act on when a pin is refused. */
const PIN_REFUSAL_REASON: Record<PinRefusal, string> = {
  address_unknown:
    'no such address in this service — a treasury pin may only name an address it minted and holds the key to',
  address_not_treasury:
    "that address is not purpose 'treasury' — mint one with POST /v1/admin/treasuries/:chain/:network/mint first",
  address_wrong_chain: 'that address belongs to a different chain',
  address_wrong_network: 'that address belongs to a different network',
  address_not_active: 'that address has been exported or retired and may not be pinned',
  address_not_platform_treasury:
    "that address is purpose 'treasury' but is not bound to this chain's platform treasury — it " +
    'belongs to another service and pinning it would sweep every deposit into that service\'s ' +
    'float. Mint the platform treasury with POST /v1/admin/treasuries/:chain/:network/mint.',
}

/* ------------------------------------------------------------------ helpers */

async function authenticate(ctx: RequestContext, deps: ServerDeps): Promise<Principal> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  // A missing token is a token fault, so it takes the same 401 path as a bad one rather than being
  // a separate branch that can drift away from it.
  if (!token) throw new TokenError('no bearer token presented', 'missing')
  return deps.verifier.principal(token)
}

/**
 * The export ceremony is a USER right and no service token may complete any step of it.
 *
 * That is the control against SD-07's malicious-insider case, and it is stated here as one function
 * rather than as a condition repeated in six routes, because a route that forgot it would be the
 * deleted reveal endpoint reintroduced.
 */
async function authenticateUser(
  ctx: RequestContext,
  deps: ServerDeps,
): Promise<{ principal: Extract<Principal, { kind: 'user' }>; claims: Record<string, unknown> }> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  if (!token) throw new TokenError('no bearer token presented', 'missing')
  const principal = await deps.verifier.principal(token)
  if (principal.kind !== 'user') throw new ForbiddenError('a user token — the export ceremony has no service path')
  return { principal, claims: await deps.verifier.verify(token) }
}

function amrOf(claims: Record<string, unknown>): string[] {
  const amr = claims['amr']
  return Array.isArray(amr) ? amr.filter((v): v is string => typeof v === 'string') : []
}

function actorOf(principal: Principal): string {
  return principal.kind === 'user' ? `user:${principal.userId}` : `service:${principal.service}`
}

async function limitSigning(deps: ServerDeps, actor: string): Promise<Reply | null> {
  const rule = { limit: deps.limits.signPerMinute, windowMs: SIGN_WINDOW_MS }
  const now = (deps.now ?? Date.now)()
  const used = await signAttemptsSince(deps.keys.sql, actor, windowStart(rule, now))
  const verdict = decide(rule, used, now)
  if (verdict.allowed) return null
  deps.metrics.increment('custody_rate_limited_total', { surface: 'sign' })
  deps.logger.warn('sign rate limit reached', { actor, used: verdict.used, limit: verdict.limit })
  return rateLimited(verdict.retryAfterSeconds, 'too many signing requests')
}

async function limitAddresses(deps: ServerDeps, actor: string): Promise<Reply | null> {
  const rule = { limit: deps.limits.addressPerHour, windowMs: ADDRESS_WINDOW_MS }
  const now = (deps.now ?? Date.now)()
  const used = await addressesCreatedSince(deps.keys.sql, actor, windowStart(rule, now))
  const verdict = decide(rule, used, now)
  if (verdict.allowed) return null
  deps.metrics.increment('custody_rate_limited_total', { surface: 'addresses' })
  deps.logger.warn('address creation rate limit reached', { actor, used: verdict.used, limit: verdict.limit })
  return rateLimited(verdict.retryAfterSeconds, 'too many address creations')
}

function rateLimited(retryAfterSeconds: number, message: string): Reply {
  return {
    status: 429,
    headers: { 'retry-after': String(retryAfterSeconds) },
    body: { error: { code: 'rate_limited', message, retryAfterSeconds } },
  }
}

function stringField(body: Record<string, unknown>, name: string): string {
  const value = body[name]
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > 512) {
    throw new BadRequestError(`${name} must be a non-empty string`)
  }
  return value.trim()
}

function enumField(
  body: Record<string, unknown>,
  name: string,
  allowed: ReadonlySet<string>,
  fallback: string,
): string {
  const value = body[name]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'string' || !allowed.has(value)) {
    throw new BadRequestError(`${name} must be one of ${[...allowed].join(', ')}`)
  }
  return value
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    // Capped before buffering, not after: an unbounded body is a memory-exhaustion primitive any
    // caller can reach. The cap is larger than the template's because a PSBT is a real payload.
    if (size > MAX_BODY_BYTES) throw new BadRequestError('request body too large')
    chunks.push(buffer)
  }
  if (size === 0) return {}
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new BadRequestError('request body must be a JSON object')
    }
    return parsed as Record<string, unknown>
  } catch (err) {
    if (err instanceof BadRequestError) throw err
    throw new BadRequestError('request body is not valid JSON')
  }
}

function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  if (res.writableEnded) return
  const payload = reply.text ?? `${JSON.stringify(reply.body ?? {})}\n`
  res.writeHead(reply.status, {
    ...(reply.headers ?? {}),
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    // `no-store` on EVERY response, centrally. SD-07 gate 8 requires it for the one route that
    // returns key material; setting it here rather than there means a new route cannot forget it,
    // and a cached 200 from a replica that has since gone unready is a lie besides.
    'cache-control': 'no-store',
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}

/**
 * The caller's name for this request, or nothing.
 *
 * An absent header and an empty one mean the same thing — no key — because a header a caller sent
 * with nothing in it is not an identity, and treating `''` as one would make every such request
 * "the same request" and every mint after the first a replay of the wrong address. The length cap
 * matches migration 6's CHECK, so a key that would be refused by the database is refused here with
 * a sentence instead of a 500.
 */
function idempotencyKeyOf(req: IncomingMessage): string | undefined {
  const raw = headerOf(req, 'idempotency-key')
  if (raw === undefined) return undefined
  const value = raw.trim()
  if (value.length === 0) return undefined
  if (value.length > MAX_IDEMPOTENCY_KEY_LENGTH) {
    throw new BadRequestError(`idempotency-key must be at most ${MAX_IDEMPOTENCY_KEY_LENGTH} characters`)
  }
  return value
}
