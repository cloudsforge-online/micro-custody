/**
 * The re-encryption pass, driven through the database — SD-06's other half.
 *
 * `crypto.test.ts` proves the ENVELOPE can be rotated. This proves the SERVICE can: that the job
 * finds the stragglers, that the seed blobs go with the keys, that an interrupted run resumes, and
 * that at the end the old secret can be REMOVED and every key still signs. That last step is the one
 * SDR-03 says is impossible today, and removing the old secret is what makes a compromise
 * recoverable rather than terminal.
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import type postgres from 'postgres'
import { versionOf } from './crypto.ts'
import { provisionAddress, signForAddress } from './keys.ts'
import { reencryptOnce, remainingCount } from './reencrypt.ts'
import { pinTreasury, treasuryBinding } from './store.ts'
import { MemoryVault } from './vault.ts'
import {
  ALICE,
  SECRET_V1,
  SECRET_V2,
  enabled,
  harness,
  keyringFor,
  migrateTestDb,
  openDb,
  resetCustody,
  silentLogger,
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

async function mint(h: Harness, orderId: string, purpose: 'deposit' | 'treasury' = 'deposit') {
  // A treasury takes the DERIVED binding, not a caller's: since micro-org#250 an address bound to
  // anyone else is refused a pin, and the pin below is what this test needs the treasury for.
  const binding = treasuryBinding('ethereum', 'testnet')
  const result = await provisionAddress(h.keys, {
    chain: 'ethereum',
    network: 'testnet',
    purpose,
    ...(purpose === 'treasury'
      ? { userId: binding.userId, orderId: binding.orderId, scheme: 'flat_random' as const }
      : { userId: ALICE, orderId }),
    createdBy: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(result.ok, true, result.ok ? '' : result.error)
  return result.ok ? result.key.address : ''
}

test('THE ROTATION, THROUGH THE SERVICE: v1 keys → v2 write version → drained → v1 secret removed', { skip }, async () => {
  const vault = new MemoryVault()

  // 1. A world encrypted under v1 only. Three deposit addresses and one treasury, plus the seed that
  //    derived the deposits — the seed matters because a mnemonic is the master secret for every
  //    address of a (user, family), and rotating the keys without it would rotate nothing.
  const before = await harness({ sql, vault, keyring: keyringFor({ 1: SECRET_V1 }, 1) })
  const addresses = [await mint(before, 'o1'), await mint(before, 'o2'), await mint(before, 'o3')]
  const treasury = await mint(before, 'o4', 'treasury')
  assert.equal(await pinTreasury(sql, { chain: 'ethereum', network: 'testnet', address: treasury, setBy: 'op' }).then((r) => 'refusal' in r), false)
  for (const address of [...addresses, treasury]) assert.equal(versionOf(await vault.read(address)), 1)
  assert.equal((await sql`select count(*)::int as n from custody_keys where key_version = 1`)[0]!.n, 4)
  assert.equal((await sql`select count(*)::int as n from custody_seeds where key_version = 1`)[0]!.n, 1)

  // 2. The new secret is added and becomes the write version. Nothing is rewritten yet.
  const during = await harness({ sql, vault, keyring: keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2) })
  const deps = { sql, vault, keyring: during.keys.keyring, logger: silentLogger }
  assert.equal(await remainingCount(sql, 2), 5)

  // A key minted DURING the rotation goes straight to the new version.
  const fresh = await mint(during, 'o5')
  assert.equal(versionOf(await vault.read(fresh)), 2)

  // 3. Drain.
  const report = await reencryptOnce(deps)
  assert.equal(report.failures, 0)
  assert.equal(report.keys, 4)
  assert.equal(report.seeds, 1)
  assert.equal(report.remaining, 0)
  for (const address of [...addresses, treasury, fresh]) assert.equal(versionOf(await vault.read(address)), 2)

  // Idempotent: a second pass finds nothing and rewrites nothing.
  assert.deepEqual(await reencryptOnce(deps), { keys: 0, seeds: 0, failures: 0, remaining: 0 })

  // 4. THE OLD SECRET IS REMOVED — and every key still signs. This is the step that today would
  //    make every key in custody undecryptable.
  const after = await harness({ sql, vault, keyring: keyringFor({ 2: SECRET_V2 }, 2) })
  const outcome = await signForAddress(after.keys, {
    address: addresses[0]!,
    chain: 'ethereum',
    network: 'testnet',
    family: 'evm',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o1',
    payload: {
      to: treasury,
      value: '1000000000000000',
      nonce: 0,
      gasLimit: 21_000,
      chainId: 11_155_111,
      maxFeePerGas: '20000000000',
      maxPriorityFeePerGas: '1000000000',
    },
    actor: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.error)
})

test('an interrupted pass resumes: the BLOB stamp is authoritative, not the row', { skip }, async () => {
  const vault = new MemoryVault()
  const before = await harness({ sql, vault, keyring: keyringFor({ 1: SECRET_V1 }, 1) })
  const address = await mint(before, 'o1')

  // Simulate a crash between the blob write and the row update — the window this ordering chooses.
  const during = await harness({ sql, vault, keyring: keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2) })
  const keyring = during.keys.keyring
  await vault.write(address, keyring.encryptAs(2, address, keyring.decrypt(address, await vault.read(address))))
  assert.equal(versionOf(await vault.read(address)), 2)
  assert.equal((await sql`select key_version from custody_keys where address = ${address}`)[0]!.key_version, 1)

  // The next pass selects it again by the row, decrypts by the blob's own stamp, and finishes.
  const report = await reencryptOnce({ sql, vault, keyring, logger: silentLogger })
  assert.equal(report.failures, 0)
  assert.equal((await sql`select key_version from custody_keys where address = ${address}`)[0]!.key_version, 2)
})

test('one unreadable blob is counted, logged and does not stop the rest of the rotation', { skip }, async () => {
  const vault = new MemoryVault()
  const before = await harness({ sql, vault, keyring: keyringFor({ 1: SECRET_V1 }, 1) })
  const good = await mint(before, 'o1')
  const bad = await mint(before, 'o2')
  await vault.write(bad, 'v1:bm90LWEtcmVhbC1ibG9i')

  const keyring = keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2)
  const report = await reencryptOnce({ sql, vault, keyring, logger: silentLogger })
  assert.equal(report.failures, 1)
  assert.equal(report.keys, 1)
  assert.equal(versionOf(await vault.read(good)), 2)
  // The failed row STAYS in the backlog, so the rotation visibly does not finish. That is the alarm:
  // an operator who removed the old secret now would lose that key.
  assert.equal(report.remaining > 0, true)
})

test('the backlog count is the number an operator watches to zero before retiring a secret', { skip }, async () => {
  const vault = new MemoryVault()
  const before = await harness({ sql, vault, keyring: keyringFor({ 1: SECRET_V1 }, 1) })
  await mint(before, 'o1')
  await mint(before, 'o2')
  assert.equal(await remainingCount(sql, 2), 3)
  assert.equal(await remainingCount(sql, 1), 0)
})
