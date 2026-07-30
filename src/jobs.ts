/**
 * Background work.
 *
 * Rule 8 of docs/ecosystem/03 §2: every background timer is a leased job. There is no `setInterval`
 * in this repository doing domain work — the old estate runs eight of them, each guarded only by a
 * module-local boolean, which is a variable that by construction cannot be seen by a second process.
 *
 * **The lease key names the contended resource, not the row.** Ask: what would break if two of these
 * ran at once? Whatever the answer names is the key.
 *
 *   | Work              | Key      | Why                                                              |
 *   |-------------------|----------|------------------------------------------------------------------|
 *   | outbox.relay      | `stream` | The outbox stream. Keying on the event id lets two relays deliver |
 *   |                   |          | the same batch to the same subscriber.                            |
 *   | custody.reencrypt | `vault`  | The blob store. Two passes rewriting one address race on the file |
 *   |                   |          | and on `key_version`; the atomic rename makes that survivable and |
 *   |                   |          | the lease makes it not happen.                                    |
 *   | custody.exports   | `timers` | The ceremony clock. Two expiry passes are harmless and pointless; |
 *   |                   |          | one key keeps the work at one replica's worth.                    |
 */

import { JobRunner, type JobQueue, type RunnerEvent } from '@cloudsforge/jobs'
import type { Logger } from '@cloudsforge/telemetry'
import { createRelay, type Db, type RelayDeps } from './outbox.ts'
import { expireExports, type ExportDeps } from './exports.ts'
import { reencryptOnce, type ReencryptDeps } from './reencrypt.ts'

export const RELAY_KIND = 'outbox.relay'
export const REENCRYPT_KIND = 'custody.reencrypt'
export const EXPORT_TIMERS_KIND = 'custody.exports'

/**
 * Jobs that must exist whether or not anything enqueued them.
 *
 * A recurring job is a producer plus a leased job, never a timer: the interval survives a restart,
 * is visible in a table an operator can query, and is claimed by exactly one replica.
 *
 * The re-encryption pass runs every thirty seconds and does nothing at all when there is no
 * backlog — one indexed query against a partial index. Making it a rotation-time manual command
 * instead would mean a rotation depends on somebody remembering to finish it, and an unfinished
 * rotation is a compromised secret still in service.
 */
export const RECURRING: ReadonlyArray<{ kind: string; key: string; everyMs: number }> = [
  { kind: RELAY_KIND, key: 'stream', everyMs: 1_000 },
  { kind: REENCRYPT_KIND, key: 'vault', everyMs: 30_000 },
  { kind: EXPORT_TIMERS_KIND, key: 'timers', everyMs: 60_000 },
]

export async function seedRecurring(queue: JobQueue): Promise<void> {
  for (const job of RECURRING) {
    await queue.enqueue({ kind: job.kind, key: job.key, onConflict: 'keep' })
  }
}

/**
 * Re-arm a recurring job once it has finished.
 *
 * It cannot re-arm itself from inside its own handler: the runner deletes the row on success AFTER
 * the handler returns, so a self-enqueue would be deleted a moment later and the schedule would
 * stop. A dead-lettered recurring job is deliberately NOT re-armed — the row stays, `jobs_dead_total`
 * increments and `jobs_overdue` climbs, which is how an operator finds out.
 */
export function rescheduleRecurring(queue: JobQueue, logger: Logger): (event: RunnerEvent) => void {
  const byKind = new Map(RECURRING.map((r) => [r.kind, r]))
  return (event) => {
    if (event.type !== 'completed') return
    const recurring = event.kind ? byKind.get(event.kind) : undefined
    if (!recurring) return
    void queue
      .enqueue({
        kind: recurring.kind,
        key: recurring.key,
        runAt: new Date(Date.now() + recurring.everyMs),
        onConflict: 'earliest',
      })
      .catch((err: unknown) => logger.error('failed to re-arm recurring job', { kind: recurring.kind, err }))
  }
}

export interface JobDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly signingSecret: string
  readonly reencrypt: ReencryptDeps
  readonly exports: ExportDeps
  /** Sampled onto `custody_key_version_backlog` so a rotation's finish line is on a dashboard. */
  readonly onBacklog?: (remaining: number) => void
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  const relayDeps: RelayDeps = {
    sql: deps.sql,
    logger: deps.logger.child({ job: RELAY_KIND }),
    signingSecret: deps.signingSecret,
  }
  runner.register(RELAY_KIND, createRelay(relayDeps))

  runner.register(REENCRYPT_KIND, async (_job, ctx) => {
    const report = await reencryptOnce(deps.reencrypt)
    deps.onBacklog?.(report.remaining)
    if (report.keys > 0 || report.seeds > 0 || report.failures > 0) {
      // Only when something happened. A quiet estate should not produce a log line every thirty
      // seconds saying it did nothing — that is how the line that matters becomes unfindable.
      deps.logger.info('re-encryption pass', { ...report })
    }
    if (ctx.signal.aborted) return
  })

  runner.register(EXPORT_TIMERS_KIND, async () => {
    const expired = await expireExports(deps.exports)
    if (expired > 0) deps.logger.info('export requests expired', { expired })
  })

  return runner
}
