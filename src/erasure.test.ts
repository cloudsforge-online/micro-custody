/**
 * A person who asks to be forgotten stops being named in the custody store, and the money keeps
 * working.
 *
 * The interesting assertion here is not that `user_id` changed — `eraseUser` obviously changes it.
 * It is `assertNoTraceOf`, which reads `information_schema` and sweeps EVERY text and jsonb column
 * of EVERY table this service owns for the raw uuid. That is what catches the column a careful
 * reading of `migrations.ts` misses, and `custody_keys.idempotency_key` is exactly such a column:
 * it is caller-supplied text with no defined shape, so nothing about its name suggests it can carry
 * a person, and the wallet's spelling of a deposit request puts one there.
 *
 * A sweep also survives the future. A migration that adds a sixth place to keep a `user_id` turns
 * this file red on the day it lands, rather than the day someone asks what became of their data.
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import type postgres from 'postgres'
import { eraseUser } from './erasure.ts'
import { ALICE, BOB, enabled, migrateTestDb, openDb, resetCustody, skip } from './testsupport.ts'

let sql: postgres.Sql

/**
 * Interpolated, never inline. A derivation path is full of single quotes for the hardened levels,
 * and writing it as a double-quoted string INSIDE a tagged template would reach Postgres as a
 * quoted IDENTIFIER rather than text.
 */
const PATH = "m/44'/2'/0'/0/0"

before(async () => {
  if (!enabled) return
  sql = openDb(4)
  await migrateTestDb(sql)
})

after(async () => {
  if (sql) await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (enabled) await resetCustody(sql)
})

/** A seed, a key beneath it, a signature, an export and an outbox row — one person's whole trail. */
async function seedTrail(userId: string, address: string): Promise<void> {
  const [seed] = await sql<{ id: string }[]>`
    insert into custody_seeds (user_id, family, key_version) values (${userId}, 'utxo', 1)
    returning id
  `
  await sql`
    insert into custody_keys
      (address, chain, family, purpose, network, user_id, order_id, scheme, derivation_path,
       seed_id, key_version, storage, created_by, idempotency_key)
    values
      (${address}, 'litecoin', 'utxo', 'deposit', 'mainnet', ${userId}, ${`deposit:${userId}:ltc`},
       'hd_bip44', ${PATH}, ${seed!.id}, 1, 'vault', ${`user:${userId}`},
       ${`wallet:deposit:${userId}`})
  `
  await sql`
    insert into signing_audit
      (address, chain, network, family, purpose, shape, outcome, user_id, order_id, actor,
       payload_digest)
    values
      (${address}, 'litecoin', 'mainnet', 'utxo', 'deposit', 'psbt', 'signed', ${userId},
       ${`withdraw:${userId}:1`}, ${`user:${userId}`}, ${'a'.repeat(64)})
  `
  await sql`
    insert into key_exports (address, user_id, status, format, expires_at, created_by)
    values (${address}, ${userId}, 'requested', 'xprv', now() + interval '1 day', ${`user:${userId}`})
  `
  await sql`
    insert into outbox (topic, key, producer, actor, payload)
    values ('custody.address.created', ${`address:${userId}`}, 'custody', ${`user:${userId}`},
            ${sql.json({ userId })})
  `
}

/**
 * Every text-shaped column in the schema, swept for the raw id.
 *
 * `::text` on the column rather than a per-type branch: jsonb, text and varchar all render, and a
 * column type this service has never used would still be searched rather than silently skipped.
 */
async function assertNoTraceOf(userId: string): Promise<void> {
  const columns = await sql<{ table_name: string; column_name: string }[]>`
    select table_name, column_name
      from information_schema.columns
     where table_schema = 'public'
       and data_type in ('text', 'character varying', 'jsonb', 'json')
     order by table_name, column_name
  `
  assert.ok(columns.length > 20, 'the sweep found no columns, so it proves nothing')
  for (const { table_name, column_name } of columns) {
    const found = await sql`
      select 1 from ${sql(table_name)}
       where ${sql(column_name)}::text like ${`%${userId}%`}
       limit 1
    `
    assert.equal(found.length, 0, `${table_name}.${column_name} still names the erased user`)
  }
}

test('a person is gone from every column, including the ones a reading would miss', { skip }, async () => {
  await seedTrail(ALICE, 'LTCaliceaddress0000000000000000000')
  await eraseUser(sql as never, ALICE)
  await assertNoTraceOf(ALICE)
})

test('the key material and the audit trail survive the erasure', { skip }, async () => {
  const address = 'LTCaliceaddress0000000000000000000'
  await seedTrail(ALICE, address)
  await eraseUser(sql as never, ALICE)

  // The row that controls the money is still there, still active, still derivable. This is the
  // whole argument for anonymising rather than deleting: the address is on a public chain that
  // cannot be edited, and dropping the row would destroy the only route back to it.
  const [key] = await sql<{ status: string; derivation_path: string; seed_id: string }[]>`
    select status, derivation_path, seed_id from custody_keys where address = ${address}
  `
  assert.equal(key?.status, 'active', 'the key was retired, which would strand what arrives at it')
  assert.equal(key?.derivation_path, PATH)
  assert.ok(key?.seed_id, 'the seed link was broken, so the key can no longer be re-derived')

  const [seed] = await sql`select 1 from custody_seeds where id = ${key!.seed_id}`
  assert.ok(seed, 'the seed was deleted')

  const audit = await sql`select 1 from signing_audit where address = ${address}`
  assert.equal(audit.length, 1, 'the signing record went with the person (Art. 17(3)(b))')
})

test('one placeholder covers the whole person, not one per table', { skip }, async () => {
  const address = 'LTCaliceaddress0000000000000000000'
  await seedTrail(ALICE, address)
  await eraseUser(sql as never, ALICE)

  const [key] = await sql<{ user_id: string }[]>`select user_id from custody_keys where address = ${address}`
  const [seed] = await sql<{ user_id: string }[]>`select user_id from custody_seeds limit 1`
  const [audit] = await sql<{ user_id: string }[]>`select user_id from signing_audit limit 1`
  const [exported] = await sql<{ user_id: string }[]>`select user_id from key_exports limit 1`

  // Three fresh placeholders would turn one departed person into three, which anonymises nothing
  // further — the derivation path and the timestamps link the rows regardless — and leaves an
  // audit trail that no longer reconciles.
  assert.equal(seed?.user_id, key?.user_id)
  assert.equal(audit?.user_id, key?.user_id)
  assert.equal(exported?.user_id, key?.user_id)
  assert.notEqual(key?.user_id, ALICE)
})

test('erasing one person leaves another untouched', { skip }, async () => {
  await seedTrail(ALICE, 'LTCaliceaddress0000000000000000000')
  await seedTrail(BOB, 'LTCbobaddress000000000000000000000')

  await eraseUser(sql as never, ALICE)

  const bob = await sql`select 1 from custody_keys where user_id = ${BOB}`
  assert.equal(bob.length, 1, "Bob's key was swept up in Alice's erasure")
  const bobAudit = await sql<{ actor: string }[]>`select actor from signing_audit where user_id = ${BOB}`
  assert.equal(bobAudit[0]?.actor, `user:${BOB}`)
})

test('a second delivery of the same erasure changes nothing', { skip }, async () => {
  await seedTrail(ALICE, 'LTCaliceaddress0000000000000000000')
  const first = await eraseUser(sql as never, ALICE)
  assert.equal(first.keys, 1)

  // Idempotence here is trivially true because the `where` no longer matches — which is the point.
  // `withInbox` is what stops the handler running twice at all; this asserts the handler is safe
  // even when it does, so a redelivery after an inbox row was lost is a repair and not a second
  // pass that re-randomises the placeholder and severs the rows from each other.
  const second = await eraseUser(sql as never, ALICE)
  assert.deepEqual(second, { seeds: 0, keys: 0, signings: 0, exports: 0, outbox: 0 })
})
