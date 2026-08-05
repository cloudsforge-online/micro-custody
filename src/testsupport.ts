/**
 * Shared setup for the database tests.
 *
 * **A database test runs only against a database whose name says it is a test database.** That is
 * not a convenience: `resetCustody` truncates every table custody owns, and requiring "test" in the
 * name is the difference between a red build and an emptied key store. Custody is the one service in
 * the estate where pointing a suite at the wrong database would destroy the record of which key is
 * whose — and the blobs on disk would then be ciphertext nothing knows the owner of.
 *
 * Not a test file itself — it is excluded from the build and contains no `test()` call.
 */

import { mkdtemp, rm } from 'node:fs/promises'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import postgres from 'postgres'
import { migrate, type Sql as DbSql } from '@cloudsforge/db'
import { TokenError, type Principal, type Role } from '@cloudsforge/auth'
import { Lifecycle } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics } from '@cloudsforge/telemetry'
import { Keyring } from './crypto.ts'
import { MIGRATIONS } from './migrations.ts'
import { createServer, registerServiceMetrics, type PrincipalVerifier, type ServerDeps } from './server.ts'
import { MemoryVault, type Vault } from './vault.ts'
import type { KeyDeps } from './keys.ts'
import type { ExportDeps } from './exports.ts'
import type { PolicyClient, PolicyDecision } from './policy.ts'

const url = process.env['CUSTODY_TEST_DATABASE_URL']

/** Both halves are required: a URL, and a URL that names a test database. */
export const enabled = Boolean(url && /test/i.test(url))
export const skip = enabled ? false : 'set CUSTODY_TEST_DATABASE_URL (name must contain "test")'

/**
 * Every table custody owns. CASCADE, so the order does not matter.
 *
 * **A TABLE MISSING FROM THIS LIST IS A TEST THAT PASSES ONCE.** `custody_token_contracts` was
 * added by migration 7 and never added here, so the two migration tests that insert into it — the
 * one-spelling check and the two-networks check — passed on a virgin database and failed with a
 * 23505 on every run afterwards. That is worse than a plain failure: on a developer's machine it
 * looks like flakiness, and on CI, which always starts clean, it looks like nothing at all.
 */
const ALL_TABLES = [
  'key_exports',
  'signing_audit',
  'custody_token_contracts',
  'custody_treasuries',
  'custody_keys',
  'custody_seeds',
  'outbox_deliveries',
  'event_subscriptions',
  'outbox',
  'inbox',
  'jobs',
].join(', ')

export function openDb(max = 8): postgres.Sql {
  if (!enabled) throw new Error('database tests are disabled')
  return postgres(url!, { max, onnotice: () => {} })
}

/**
 * Bring the schema up. Idempotent, so every test file may call it and only the first does work.
 *
 * Deliberately runs the real `MIGRATIONS` rather than a hand-written fixture schema. A fixture would
 * let the CHECK constraints drift out of the tests that are supposed to prove they fire — and for
 * this service the scheme constraint is what stops a `flat_random` row claiming a derivation path.
 */
export async function migrateTestDb(sql: postgres.Sql): Promise<void> {
  await migrate(sql as unknown as DbSql, MIGRATIONS, { service: 'custody-test' })
}

export async function resetCustody(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`truncate ${ALL_TABLES} restart identity cascade`)
}

/* ------------------------------------------------------------------ fixtures */

/** Long enough to pass the entropy floor, and obviously a test value. */
export const SECRET_V1 = 'v1-master-secret-for-the-custody-suite-0123456789'
export const SECRET_V2 = 'v2-master-secret-for-the-custody-suite-9876543210'
export const SECRET_V3 = 'v3-master-secret-for-the-custody-suite-abcdefabcd'

export function keyringFor(versions: Record<number, string>, writeVersion: number): Keyring {
  return new Keyring(new Map(Object.entries(versions).map(([v, s]) => [Number(v), s])), writeVersion)
}

export const ALICE = '11111111-1111-4111-8111-111111111111'
export const BOB = '22222222-2222-4222-8222-222222222222'

export const silentLogger = new Logger({ service: 'custody-test', level: 'error', version: 'test', env: 'test' })

/**
 * A logger that keeps the `audit` tag of everything written through it, and prints nothing.
 *
 * It exists for one assertion and it is worth the plumbing: the concurrency cases need to prove
 * that the UNIQUE INDEX refused the second insert, not that the lookup happened to run first. Those
 * two are indistinguishable from the outside — both end with one address — and a test that cannot
 * tell them apart would pass just as happily against a service with no constraint at all.
 *
 * Subclassed rather than faked because `Logger` carries a private field, so a structural stand-in
 * is not assignable to it — which is the type system doing its job.
 */
export class CapturingLogger extends Logger {
  readonly audits: string[] = []
  override info(message: string, fields?: Record<string, unknown>): void {
    const audit = fields?.['audit']
    if (typeof audit === 'string') this.audits.push(audit)
  }
  count(audit: string): number {
    return this.audits.filter((a) => a === audit).length
  }
}

export function capturingLogger(): CapturingLogger {
  return new CapturingLogger({ service: 'custody-test', level: 'error', version: 'test', env: 'test' })
}

/** A policy that always answers the same thing. The real one is the only outbound call custody has. */
export function fixedPolicy(decision: PolicyDecision): PolicyClient {
  return { decide: async () => decision }
}

export interface Harness {
  readonly sql: postgres.Sql
  readonly vault: Vault
  readonly keys: KeyDeps
  readonly exports: ExportDeps
  clock(): number
  setClock(ms: number): void
  cleanup(): Promise<void>
}

/**
 * A whole service's worth of dependencies against the test database, with a movable clock.
 *
 * The clock is injected rather than faked globally because the export ceremony's central control is
 * a 24-hour hold, and a suite that could not advance time would either not test it or would test it
 * by waiting a day.
 */
export async function harness(options: {
  sql: postgres.Sql
  keyring?: Keyring
  policy?: PolicyClient
  coolingOffMs?: number
  tokenTtlMs?: number
  requestTtlMs?: number
  vault?: Vault
  logger?: Logger
}): Promise<Harness> {
  const keyring = options.keyring ?? keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2)
  const vault = options.vault ?? new MemoryVault()
  const logger = options.logger ?? silentLogger
  let clock = Date.UTC(2026, 0, 1, 12, 0, 0)

  const keys: KeyDeps = { sql: options.sql, vault, keyring, logger, producer: 'custody' }
  const exportDeps: ExportDeps = {
    sql: options.sql,
    vault,
    keyring,
    policy: options.policy ?? fixedPolicy({ effect: 'allow', reasons: [] }),
    logger: silentLogger,
    producer: 'custody',
    coolingOffMs: options.coolingOffMs ?? 24 * 3_600_000,
    tokenTtlMs: options.tokenTtlMs ?? 300_000,
    requestTtlMs: options.requestTtlMs ?? 168 * 3_600_000,
    now: () => clock,
  }

  return {
    sql: options.sql,
    vault,
    keys,
    exports: exportDeps,
    clock: () => clock,
    setClock: (ms) => {
      clock = ms
    },
    cleanup: async () => {},
  }
}

/** A real on-disk vault in a temporary directory, for the tests that care about file modes. */
export async function tempFileVaultDir(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'custody-test-'))
  return { dir, cleanup: async () => rm(dir, { recursive: true, force: true }) }
}

/* ------------------------------------------------------------------ the HTTP surface */

export interface TestToken {
  readonly principal: Principal
  readonly claims?: Record<string, unknown>
}

/**
 * A verifier over a fixed token table.
 *
 * The routes are driven over REAL HTTP against a REAL server, because half of what is being asserted
 * — the 404 for the deleted reveal route, `cache-control: no-store`, the response body of every
 * route — is a property of the transport rather than of a handler function. Only the JWKS is faked,
 * and `@cloudsforge/auth` has its own tests for that.
 */
export function stubVerifier(tokens: Record<string, TestToken>): PrincipalVerifier {
  return {
    async principal(token) {
      const entry = tokens[token]
      if (!entry) throw new TokenError('unknown test token', 'invalid')
      return entry.principal
    },
    async verify(token) {
      const entry = tokens[token]
      if (!entry) throw new TokenError('unknown test token', 'invalid')
      return entry.claims ?? {}
    },
  }
}

export function serviceToken(name: string, scopes: readonly string[]): TestToken {
  return { principal: { kind: 'service', service: name, scopes } }
}

export function userToken(userId: string, options: { roles?: Role[]; amr?: string[]; authTimeMs?: number } = {}): TestToken {
  return {
    principal: { kind: 'user', userId, handle: userId.slice(0, 8), roles: options.roles ?? ['player'] },
    claims: {
      amr: options.amr ?? ['pwd', 'mfa'],
      ...(options.authTimeMs === undefined ? {} : { auth_time: Math.floor(options.authTimeMs / 1_000) }),
    },
  }
}

export interface RunningServer {
  readonly url: string
  request(
    path: string,
    options?: { method?: string; token?: string; body?: unknown; headers?: Record<string, string> },
  ): Promise<{
    status: number
    headers: Headers
    body: Record<string, unknown>
    text: string
  }>
  close(): Promise<void>
}

/** Start the real server on an ephemeral port. */
export async function startServer(deps: ServerDeps): Promise<RunningServer> {
  const server = createServer(deps)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const address = server.address() as AddressInfo
  const url = `http://127.0.0.1:${address.port}`

  return {
    url,
    async request(path, options = {}) {
      const response = await fetch(`${url}${path}`, {
        method: options.method ?? 'GET',
        headers: {
          'content-type': 'application/json',
          ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
          // Last, so a case can drive a header the helper also sets — `idempotency-key` is not one
          // the helper sets at all, and it is the reason this parameter exists: the key travels as
          // a HEADER (`@cloudsforge/http` sets it from `request.idempotencyKey`), so a suite that
          // could only send a body could not exercise the route the callers actually reach.
          ...(options.headers ?? {}),
        },
        ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      })
      const text = await response.text()
      let body: Record<string, unknown> = {}
      try {
        body = JSON.parse(text) as Record<string, unknown>
      } catch {
        body = {}
      }
      return { status: response.status, headers: response.headers, body, text }
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeIdleConnections()
        server.close(() => resolve())
      }),
  }
}

/** A Lifecycle that is always ready, so a route test does not need probes. */
export function testLifecycle(): Lifecycle {
  const lifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 100 })
  lifecycle.markReady()
  return lifecycle
}

export function testMetrics(): Metrics {
  return registerServiceMetrics(registerHttpMetrics(new Metrics()))
}
