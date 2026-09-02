/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this file.
 *
 * What it deliberately does NOT do: run migrations. That is `src/migrator.ts`, a separate one-shot
 * process (AD-17, rule 7).
 *
 * WHAT IS ABSENT FROM THIS FILE IS AS MUCH THE DESIGN AS WHAT IS IN IT. There is no RPC client, no
 * price feed, no product-service client. The only `HttpClient` constructed anywhere in this
 * repository points at `policy` (SD-13, 03 §3), and a second one would be visible here in one line.
 */

import { hostname } from 'node:os'
import postgres from 'postgres'
import { assertSchemaAtLeast, type Sql as DbSql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Verifier } from '@cloudsforge/auth'
import { Lifecycle, httpProbe, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { Keyring } from './crypto.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, registerServiceMetrics, type PrincipalVerifier } from './server.ts'
import { registerHandlers, rescheduleRecurring, seedRecurring } from './jobs.ts'
import { createPolicyClient } from './policy.ts'
import { FileVault } from './vault.ts'
import { remainingCount } from './reencrypt.ts'
import type { KeyDeps } from './keys.ts'
import type { ExportDeps } from './exports.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing variable, a placeholder secret or a
//    write version with no master secret behind it has already exited with a structured line naming
//    the variable.

// 2. Telemetry, before anything that can fail, so the pool's failure is a structured, searchable,
//    redacted line rather than a bare V8 stack the collector drops.
const logger = new Logger({ service: SERVICE, level: env.logLevel, version: env.version, env: env.env })
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
logger.info('starting', {
  version: env.version,
  schemaVersion: SCHEMA_VERSION,
  keyVersion: env.keyVersion,
  // Which VERSIONS are readable, never the secrets. An operator mid-rotation needs to know whether
  // the old secret is still loaded, and that fact is not itself a secret.
  readableKeyVersions: [...env.masterSecrets.keys()].sort((a, b) => a - b),
})

// 3. The keyring, before the pool, because a service that cannot decrypt is a service that must not
//    accept traffic — and this constructor is what refuses a write version with no secret behind it.
const keyring = new Keyring(env.masterSecrets, env.keyVersion)
const vault = new FileVault(env.dataDir)

// 4. The database pool. Opened before the schema assertion for the obvious reason that the assertion
//    is a query, and before the Lifecycle because the readiness probe closes over it.
const sql = postgres(env.databaseUrl, {
  max: env.databasePoolMax,
  // postgres.js writes notices to stderr as unstructured text by default, which is how a connection
  // string ends up in a log the collector cannot parse.
  onnotice: () => {},
})

// 5. Assert the schema. This does NOT migrate. Failing here rather than serving is the point: a
//    replica of the new code answering requests against the old schema corrupts data quietly.
try {
  await assertSchemaAtLeast(sql as unknown as DbSql, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 6. The Lifecycle and its probes, before the routes, because `/readyz` is a route and it needs
//    something to report.
const lifecycle = new Lifecycle({
  // Must exceed one load-balancer probe interval, or the balancer is still sending traffic when the
  // process stops accepting it.
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})

lifecycle
  .addProbe(
    postgresProbe('postgres', (signal) =>
      // Racing the signal is what turns "the database is not answering" into a fail rather than a
      // hung readiness endpoint.
      Promise.race([
        sql`select 1`,
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
        }),
      ]),
    ),
  )
  // Soft. If identity is down this service still serves everything that does not need a fresh key,
  // and marking it hard means one identity blip removes every service in the estate from its
  // balancer at once — a cascade, not a safety measure.
  .addProbe(httpProbe('identity-jwks', env.identityJwksUrl, { kind: 'soft' }))

// 7. The domain. The policy client is the ONLY outbound dependency this service has.
const policy = createPolicyClient({ baseUrl: env.policyBaseUrl, logger: logger.child({ upstream: 'policy' }) })

const keys: KeyDeps = { sql, vault, keyring, logger, producer: SERVICE }
const exports: ExportDeps = {
  sql,
  vault,
  keyring,
  policy,
  logger,
  producer: SERVICE,
  coolingOffMs: env.exportCoolingOffHours * 3_600_000,
  tokenTtlMs: env.exportTokenTtlSeconds * 1_000,
  requestTtlMs: env.exportRequestTtlHours * 3_600_000,
}

const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })
const server = createServer({
  lifecycle,
  logger,
  metrics,
  verifier: verifier as unknown as PrincipalVerifier,
  keys,
  exports,
  limits: { signPerMinute: env.signRatePerMinute, addressPerHour: env.addressRatePerHour },
  // The same key the relay below signs WITH. `POST /v1/events` verifies inbound deliveries with it
  // — micro-org#534.
  eventSigningSecret: env.outboxSigningSecret,
  // Sampled at scrape time rather than on a timer. There is no `setInterval` in this repository and
  // CI greps for one — rule 8.
  beforeScrape: async () => {
    const stats = await queue.stats()
    metrics.set('jobs_pending', stats.pending)
    metrics.set('jobs_overdue', stats.overdue)
    metrics.set('custody_key_version_backlog', await remainingCount(sql, keyring.writeVersion))
  },
})

// 8. The job runner, started before `listen()`. Background work is claimed under a lease, so a
//    replica that is draining stops claiming before it stops serving.
const queue = new JobQueue(sql as unknown as JobsSql, { owner: env.instanceId })
const reschedule = rescheduleRecurring(queue, logger)
const runner = new JobRunner({
  queue,
  concurrency: 2,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    if (event.kind) {
      if (event.type === 'claimed') metrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') metrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') metrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') metrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) metrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
    }
    if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
      logger.error('job failure', { ...event })
    }
    reschedule(event)
  },
})

registerHandlers(runner, {
  sql,
  logger,
  signingSecret: env.outboxSigningSecret,
  reencrypt: { sql, vault, keyring, logger },
  exports,
  onBacklog: (remaining) => metrics.set('custody_key_version_backlog', remaining),
})
await seedRecurring(queue)
runner.start()

// 9. Listen. Last of the construction steps, because a socket that accepts before its dependencies
//    exist is a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port, instance: env.instanceId || hostname() })

// 10. Ready. Only now does `/readyz` start answering 200. Flipping this before `listen()` would
//     advertise a replica that has no socket.
lifecycle.markReady()

// 11. Signal handlers, last of all. Installing them earlier means a SIGTERM arriving mid-boot drains
//     a service that was never ready. Hooks run in reverse registration order, so the server closes
//     first, then the runner stops claiming and drains, then the pool closes with nothing left to
//     use it.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      // Idle keep-alive sockets hold the server open past the drain budget.
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
