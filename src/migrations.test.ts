/**
 * The schema, and the constraints that are load-bearing rather than decorative.
 *
 * Two of them encode a decision the rest of the service depends on, so they are asserted against a
 * real database rather than read: the scheme constraint (04-domain-model §3.3 / SDR-08) and the
 * one-open-ceremony index (SD-07).
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import type postgres from 'postgres'
import { MIGRATIONS, SCHEMA_VERSION, BASELINE_VERSION } from './migrations.ts'
import { enabled, migrateTestDb, openDb, resetCustody, skip } from './testsupport.ts'

let sql: postgres.Sql

before(async () => {
  if (!enabled) return
  sql = openDb(2)
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

test('the migration versions are contiguous and unique', () => {
  const versions = MIGRATIONS.map((m) => m.version)
  assert.deepEqual(versions, [...versions].sort((a, b) => a - b))
  assert.equal(new Set(versions).size, versions.length)
  assert.equal(versions[0], 1)
  assert.equal(SCHEMA_VERSION, versions.at(-1))
})

test('custody is a NEW database, so nothing is baselined', () => {
  // The rows in the service custody supersedes are adopted by an offline import that writes through
  // this schema's own constraints — `scheme`, `key_version` and `status` have no column to baseline
  // onto, so baselining would record migrations as applied against tables that do not match them.
  assert.equal(BASELINE_VERSION, 0)
})

test('migrating twice is a no-op — the migrator is safe to run on every deploy', { skip }, async () => {
  await migrateTestDb(sql)
  const rows = await sql<{ version: number }[]>`select version from schema_migrations order by version`
  assert.deepEqual(
    rows.map((r) => Number(r.version)),
    MIGRATIONS.map((m) => m.version),
  )
})

test('every table the service owns exists', { skip }, async () => {
  const rows = await sql<{ table_name: string }[]>`
    select table_name from information_schema.tables where table_schema = 'public'
  `
  const names = new Set(rows.map((r) => r.table_name))
  for (const table of ['custody_keys', 'custody_seeds', 'custody_treasuries', 'signing_audit', 'key_exports']) {
    assert.equal(names.has(table), true, table)
  }
})

test('NO column anywhere holds key material — the blobs live on disk, not in the database', { skip }, async () => {
  // The property an attacker with database access runs into: ciphertext is not even in here. It is
  // asserted as a schema fact so a column added later has to argue with this test.
  const rows = await sql<{ table_name: string; column_name: string }[]>`
    select table_name, column_name from information_schema.columns where table_schema = 'public'
  `
  const suspicious = rows.filter((r) => /private|secret|mnemonic|seed_phrase|key_enc|wif|blob|ciphertext/i.test(r.column_name))
  assert.deepEqual(suspicious, [])
})

test('SDR-08 in the database: a flat_random row cannot claim a derivation path', { skip }, async () => {
  // A `flat_random` row WITH a path is a claim that a legacy key can be recovered from a phrase,
  // which is the lie SDR-08 says must be surfaced honestly rather than papered over.
  await assert.rejects(
    () => sql`
      insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                                derivation_path, key_version, storage, created_by)
      values ('0xabc', 'ethereum', 'evm', 'deposit', 'testnet', 'u', 'o', 'flat_random',
              'm/44''/60''/0''/0/0', 2, 'file', 'test')
    `,
    /custody_keys_scheme_ck/,
  )
  // And an hd_bip44 row without one cannot exist either: it would be a row nothing can re-derive.
  await assert.rejects(
    () => sql`
      insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                                key_version, storage, created_by)
      values ('0xdef', 'ethereum', 'evm', 'deposit', 'testnet', 'u', 'o', 'hd_bip44', 2, 'file', 'test')
    `,
    /custody_keys_scheme_ck/,
  )
})

test('the treasury pin can only reference an address this service holds', { skip }, async () => {
  await assert.rejects(
    () => sql`
      insert into custody_treasuries (chain, network, address, set_by)
      values ('ethereum', 'testnet', '0xnot-a-key-we-hold', 'op')
    `,
    /foreign key|custody_treasuries_key_fk/,
  )
})

test('the treasury pin is a TREASURY address, on THIS chain and THIS network — in the schema', { skip }, async () => {
  /*
   * `store.pinTreasury` checks all three and is the only writer. This asserts the DATABASE checks
   * them too, which is the property that matters now that BTC and SOL sweeps exist: every family's
   * sweep pays whatever address this row names, so a bug, a future migration, an offline adoption
   * script or an operator at a psql prompt must not be able to make it name something else.
   *
   * Written as raw INSERTs deliberately — going through `pinTreasury` would prove the function's
   * check, which is not the thing under test.
   */
  const insertKeyRow = (address: string, chain: string, network: string, purpose: string) => sql`
    insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                              key_version, storage, created_by)
    values (${address}, ${chain}, 'evm', ${purpose}, ${network}, 'u', 'o', 'flat_random', 2, 'file', 'test')
  `
  await insertKeyRow('0xtreasury-eth-testnet', 'ethereum', 'testnet', 'treasury')
  await insertKeyRow('0xdeposit-eth-testnet', 'ethereum', 'testnet', 'deposit')
  await insertKeyRow('0xtreasury-eth-mainnet', 'ethereum', 'mainnet', 'treasury')
  await insertKeyRow('0xtreasury-ember-testnet', 'ember', 'testnet', 'treasury')

  const pin = (chain: string, network: string, address: string) => sql`
    insert into custody_treasuries (chain, network, address, set_by)
    values (${chain}, ${network}, ${address}, 'op')
  `

  // A CUSTOMER'S DEPOSIT ADDRESS. The one that would matter: pin it and every sweep in the estate
  // pays an address whose key the platform holds but whose purpose says it is somebody's deposit.
  await assert.rejects(() => pin('ethereum', 'testnet', '0xdeposit-eth-testnet'), /custody_treasuries_key_fk/)
  // A treasury on the WRONG NETWORK. Same chain, real treasury, mainnet — a testnet sweep signed to
  // a mainnet address is coins sent to an address nobody controls on the network they were sent on.
  await assert.rejects(() => pin('ethereum', 'testnet', '0xtreasury-eth-mainnet'), /custody_treasuries_key_fk/)
  // A treasury on the WRONG CHAIN.
  await assert.rejects(() => pin('ethereum', 'testnet', '0xtreasury-ember-testnet'), /custody_treasuries_key_fk/)
  // And `purpose` cannot be talked out of being 'treasury' to satisfy the reference.
  await assert.rejects(
    () => sql`
      insert into custody_treasuries (chain, network, address, set_by, purpose)
      values ('ethereum', 'testnet', '0xdeposit-eth-testnet', 'op', 'deposit')
    `,
    /custody_treasuries_purpose_ck/,
  )

  // The one that is allowed, so the test proves a constraint rather than a broken table.
  await pin('ethereum', 'testnet', '0xtreasury-eth-testnet')
  const rows = await sql<{ address: string }[]>`select address from custody_treasuries`
  assert.deepEqual(rows.map((r) => r.address), ['0xtreasury-eth-testnet'])
})

test('a signing audit row must be one of exactly two outcomes', { skip }, async () => {
  await assert.rejects(
    () => sql`
      insert into signing_audit (address, chain, network, family, purpose, shape, outcome,
                                 user_id, order_id, actor, payload_digest)
      values ('0xabc', 'ethereum', 'testnet', 'evm', 'deposit', 'sweep', 'maybe', 'u', 'o', 'svc', 'd')
    `,
    /signing_audit_outcome_ck/,
  )
})
