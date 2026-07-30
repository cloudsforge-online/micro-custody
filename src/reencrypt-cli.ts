/**
 * The re-encryption pass, as a one-shot command.
 *
 * The job in `jobs.ts` drains the backlog on its own every thirty seconds, and that is the normal
 * path. This exists for the two cases where waiting is wrong:
 *
 *   - A rehearsal. SD-06 asks for a quarterly rotation rehearsal on staging, and a rehearsal that
 *     consists of "restart the service and come back in an hour" is not one anybody performs.
 *   - An incident. When the old secret is believed compromised, the interval between it being
 *     retired and it having to be retired is exactly the exposure, and an operator needs to close it
 *     now rather than at the runner's convenience.
 *
 * It exits NON-ZERO while anything remains, so it is safe to put in a loop or a deploy gate: the
 * command succeeding is the same statement as "the old secret can now be removed".
 */

import postgres from 'postgres'
import { Logger } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { Keyring } from './crypto.ts'
import { reencryptOnce, remainingCount } from './reencrypt.ts'
import { FileVault } from './vault.ts'

const log = new Logger({ service: SERVICE, level: env.logLevel, version: env.version, env: env.env }).child({
  step: 'reencrypt',
})

const sql = postgres(env.databaseUrl, { max: 2, onnotice: () => {} })
const keyring = new Keyring(env.masterSecrets, env.keyVersion)
const vault = new FileVault(env.dataDir)
const deps = { sql, vault, keyring, logger: log }

try {
  log.info('re-encryption starting', {
    writeVersion: keyring.writeVersion,
    readableVersions: keyring.readableVersions,
    remaining: await remainingCount(sql, keyring.writeVersion),
  })

  let totalKeys = 0
  let totalSeeds = 0
  let totalFailures = 0
  // Batched rather than one query, for the same reason the job is: each row costs a full scrypt
  // derivation at the new cost parameter, and an unbounded pass holds the CPU for as long as custody
  // is large. The loop ends when a pass does no work, which is either "finished" or "everything left
  // is failing" — and the exit code below distinguishes them.
  for (;;) {
    const report = await reencryptOnce(deps)
    totalKeys += report.keys
    totalSeeds += report.seeds
    totalFailures += report.failures
    if (report.keys === 0 && report.seeds === 0) break
    log.info('re-encryption progress', { ...report })
  }

  const remaining = await remainingCount(sql, keyring.writeVersion)
  log.info('re-encryption complete', { keys: totalKeys, seeds: totalSeeds, failures: totalFailures, remaining })
  await sql.end({ timeout: 5 })
  if (remaining > 0) {
    // Loud, and non-zero. An operator who removed the old master secret on the strength of a partial
    // run would lose every key still on it — irrecoverably, which is the whole class of failure this
    // machinery exists to remove.
    log.fatal('re-encryption did not finish — DO NOT remove the previous master secret', { remaining })
    process.exit(1)
  }
  process.exit(0)
} catch (err) {
  log.fatal('re-encryption failed', { err })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}
