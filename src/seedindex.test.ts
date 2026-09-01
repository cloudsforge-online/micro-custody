/**
 * One address index counter PER DERIVATION PATH, not per seed.
 *
 * `hd.ts` already proves each chain derives at its own SLIP-0044 coin type — LTC at 2', DOGE at 3',
 * testnet at 1' — and that getting that wrong makes two chains share one address. This proves the
 * consequence one level up: because a single seed serves all of those paths, an index counter that
 * is shared across them interleaves, and every path is left with holes.
 *
 * Holes are not cosmetic. BIP-44 restore walks a path until it sees a run of unused addresses — the
 * gap limit, 20 by convention — and stops. Twenty consecutive holes make every address past them
 * invisible to a wallet restoring from the phrase `exports.ts` hands the user, at the exact path
 * `custody_keys.derivation_path` claims. The platform can still derive them; the owner cannot see
 * them. That is the same silent-loss-on-restore failure `hd.ts` exists to prevent, reached by a
 * different route, and migration 9 is what closes it.
 *
 * Before that migration this file fails on its first assertion: the three mainnet paths come back
 * holding {0,2,5}, {1,4} and {3} instead of {0,1,2}, {0,1} and {0}.
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import type postgres from 'postgres'
import { coinTypeFor } from './hd.ts'
import { provisionAddress } from './keys.ts'
import { MemoryVault } from './vault.ts'
import {
  ALICE,
  SECRET_V1,
  enabled,
  harness,
  keyringFor,
  migrateTestDb,
  openDb,
  resetCustody,
  skip,
  type Harness,
} from './testsupport.ts'

let sql: postgres.Sql

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
})

after(async () => {
  if (!enabled) return
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (!enabled) return
  await resetCustody(sql)
})

async function mint(h: Harness, chain: string, network: 'mainnet' | 'testnet', orderId: string) {
  const result = await provisionAddress(h.keys, {
    chain,
    network,
    purpose: 'deposit',
    userId: ALICE,
    orderId,
    createdBy: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(result.ok, true, result.ok ? '' : result.error)
}

/** The index each row actually landed on, read back out of the path rather than assumed. */
function indexOf(path: string): number {
  const parts = path.split('/')
  // Six segments for BIP-32 (m/44'/coin'/0'/0/index); five for SLIP-0010 (m/44'/coin'/index'/0').
  return Number.parseInt((parts.length === 6 ? parts[5] : parts[3])!.replace("'", ''), 10)
}

test('every derivation path a seed serves is allocated contiguously from 0', { skip }, async () => {
  const h = await harness({ sql, vault: new MemoryVault(), keyring: keyringFor({ 1: SECRET_V1 }, 1) })

  // BTC, LTC and DOGE are ONE family (`bitcoin`) and therefore one seed, but three coin types.
  // Deliberately interleaved: a shared counter cannot survive this ordering, and this ordering is
  // what a user actually does — a deposit address per coin, taken as they need them.
  await mint(h, 'bitcoin', 'mainnet', 'o1')
  await mint(h, 'litecoin', 'mainnet', 'o2')
  await mint(h, 'bitcoin', 'mainnet', 'o3')
  await mint(h, 'dogecoin', 'mainnet', 'o4')
  await mint(h, 'litecoin', 'mainnet', 'o5')
  await mint(h, 'bitcoin', 'mainnet', 'o6')
  await mint(h, 'bitcoin', 'testnet', 'o7')

  const rows = await sql<{ derivation_path: string }[]>`
    select derivation_path from custody_keys
     where user_id = ${ALICE} and derivation_path is not null
  `
  const byPath = new Map<string, number[]>()
  for (const row of rows) {
    const prefix = row.derivation_path.split('/').slice(0, 3).join('/')
    byPath.set(prefix, [...(byPath.get(prefix) ?? []), indexOf(row.derivation_path)])
  }

  const expected = new Map([
    [`m/44'/${coinTypeFor('bitcoin', 'mainnet', 'bitcoin')}'`, [0, 1, 2]],
    [`m/44'/${coinTypeFor('bitcoin', 'mainnet', 'litecoin')}'`, [0, 1]],
    [`m/44'/${coinTypeFor('bitcoin', 'mainnet', 'dogecoin')}'`, [0]],
    [`m/44'/${coinTypeFor('bitcoin', 'testnet', 'bitcoin')}'`, [0]],
  ])
  assert.deepEqual([...byPath.keys()].sort(), [...expected.keys()].sort())
  for (const [prefix, indexes] of expected) {
    assert.deepEqual(
      byPath.get(prefix)!.sort((a, b) => a - b),
      indexes,
      `${prefix} must be contiguous from 0, so a restore's gap scan never stops early`,
    )
  }

  // The seed itself is NOT split. One mnemonic per (user, family) is what BIP-44 is for, and it is
  // what micro-org#510 proposed to break by keying the seed on network as well. The counter moved;
  // the seed did not.
  const seeds = await sql<{ n: number }[]>`
    select count(*)::int as n from custody_seeds where user_id = ${ALICE}
  `
  assert.equal(seeds[0]!.n, 1)

  // And the legacy whole-seed counter is still advanced past everything handed out, which is what
  // lets the previous image be rolled back to without it re-minting an address this one already did.
  const seed = await sql<{ next_index: number }[]>`
    select next_index from custody_seeds where user_id = ${ALICE}
  `
  assert.ok(seed[0]!.next_index >= 3, `whole-seed high-water mark was ${seed[0]!.next_index}`)
})
