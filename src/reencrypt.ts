/**
 * The re-encryption pass — the second half of SD-06, and the thing that makes
 * `CUSTODY_MASTER_SECRET_V<n>` rotatable at all.
 *
 * A version in the envelope on its own only lets old blobs keep decrypting. It does not RETIRE the
 * old secret, and a secret that can never be retired has not been rotated — it has been supplemented.
 * SDR-03 says to treat any custody host compromise as unrecoverable precisely because there is no
 * pass like this one: the compromised secret stays load-bearing for ever.
 *
 * THE ROTATION, END TO END:
 *
 *   1. Generate a new secret and add `CUSTODY_MASTER_SECRET_V<n+1>`. Leave V<n> in place.
 *   2. Set `CUSTODY_KEY_VERSION=<n+1>` and restart. New keys are written under it immediately; every
 *      existing blob still decrypts under V<n>.
 *   3. Let this job drain — `custody_keys_version_idx` is a partial index on exactly the stragglers,
 *      so "how much is left" is one cheap query and the finish line is observable.
 *   4. Only when nothing remains below <n+1>, remove `CUSTODY_MASTER_SECRET_V<n>`. THAT is the
 *      moment the old secret stops mattering, and it is the moment a compromise becomes recoverable.
 *
 * IT IS RESTARTABLE AND IT CANNOT LOSE A KEY. Per row: write the new blob first (atomically —
 * `FileVault.write` renames into place), then update the row. A crash between the two leaves a blob
 * at the NEW version under a row that claims the old one; the next pass selects it again, decrypts
 * it by the stamp the blob itself carries rather than by the row, re-encrypts and updates. The
 * operation is idempotent, and the only cost of a crash is doing one row twice.
 *
 * THE SEEDS ARE ROTATED TOO. A mnemonic is the master secret for every address of a (user, family);
 * leaving seed blobs on an old envelope version would mean rotating the keys and not the thing they
 * were derived from.
 */

import type { Logger } from '@cloudsforge/telemetry'
import type { Keyring } from './crypto.ts'
import { versionOf } from './crypto.ts'
import type { Db } from './outbox.ts'
import { listStaleKeys, setKeyVersion } from './store.ts'
import { seedSlot, type Vault } from './vault.ts'

export interface ReencryptDeps {
  readonly sql: Db
  readonly vault: Vault
  readonly keyring: Keyring
  readonly logger: Logger
}

export interface ReencryptReport {
  readonly keys: number
  readonly seeds: number
  readonly failures: number
  readonly remaining: number
}

/**
 * One batch. Bounded rather than "everything", because this runs as a leased job alongside live
 * traffic and each row costs a full scrypt derivation at the new cost parameter — an unbounded pass
 * would hold the CPU for as long as custody is large.
 */
export async function reencryptOnce(deps: ReencryptDeps, batchSize = 50): Promise<ReencryptReport> {
  const target = deps.keyring.writeVersion
  let keys = 0
  let seeds = 0
  let failures = 0

  const stale = await listStaleKeys(deps.sql, target, batchSize)
  for (const row of stale) {
    try {
      await rewriteSlot(deps, row.address, target)
      await setKeyVersion(deps.sql, row.address, target)
      keys += 1
    } catch (err) {
      // Counted and logged, never thrown: one unreadable blob must not stop the rotation of every
      // other key. A row that keeps failing stays in the partial index, so the backlog gauge never
      // reaches zero and the rotation visibly does not finish — which is the correct alarm.
      failures += 1
      deps.logger.error('re-encryption failed for a key', {
        address: row.address,
        from: row.key_version,
        to: target,
        err: err instanceof Error ? err.message : String(err),
      })
    }
  }

  const staleSeeds = await deps.sql<{ id: string; key_version: number }[]>`
    select id, key_version from custody_seeds where key_version < ${target} order by created_at limit ${batchSize}
  `
  for (const seed of staleSeeds) {
    try {
      await rewriteSlot(deps, seedSlot(seed.id), target)
      await deps.sql`update custody_seeds set key_version = ${target} where id = ${seed.id}`
      seeds += 1
    } catch (err) {
      failures += 1
      deps.logger.error('re-encryption failed for a seed', {
        seedId: seed.id,
        from: seed.key_version,
        to: target,
        err: err instanceof Error ? err.message : String(err),
      })
    }
  }

  return { keys, seeds, failures, remaining: await remainingCount(deps.sql, target) }
}

/**
 * Read, decrypt under whatever version the BLOB says, re-encrypt under the target, write.
 *
 * The blob's own stamp is authoritative and the row's `key_version` is only an index — that is what
 * makes an interrupted run resumable, and it is why this function never takes the row's version as
 * a parameter. A blob already at the target is left alone rather than needlessly rewritten.
 */
async function rewriteSlot(deps: ReencryptDeps, slot: string, target: number): Promise<void> {
  const blob = await deps.vault.read(slot)
  if (versionOf(blob) === target) return
  const plaintext = deps.keyring.decrypt(slot, blob)
  await deps.vault.write(slot, deps.keyring.encryptAs(target, slot, plaintext))
}

/** How many blobs are still on an older version. The gauge an operator watches to zero. */
export async function remainingCount(sql: Db, target: number): Promise<number> {
  const rows = await sql<{ n: number }[]>`
    select
      (select count(*) from custody_keys  where key_version < ${target} and status <> 'retired')
    + (select count(*) from custody_seeds where key_version < ${target}) as n
  `
  return Number(rows[0]?.n ?? 0)
}
