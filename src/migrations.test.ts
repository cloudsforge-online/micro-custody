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

/* ------------------------------------------------------------------ migration 8: `pool` */

test('migration 8: a `pool` key is storable, and the purpose check is still a closed set', { skip }, async () => {
  // The capability micro-pool needs: an address whose private key custody holds, that the coinbase
  // of a found block can be paid to (36-multi-chain-and-mining-pool §5.3).
  await sql`
    insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                              key_version, storage, created_by)
    values ('ltc1qpool-mainnet', 'litecoin', 'bitcoin', 'pool', 'mainnet', 'cloudsforge:pool',
            'pool:litecoin:mainnet', 'flat_random', 2, 'file', 'test')
  `
  const rows = await sql<{ purpose: string }[]>`select purpose from custody_keys where address = 'ltc1qpool-mainnet'`
  assert.equal(rows[0]?.purpose, 'pool')

  // Widened, not opened. The check is what keeps `purpose` a value the rest of the service can
  // exhaustively reason about — `exports.PLATFORM_OWNED_PURPOSES` and `gates.SIGNABLE_PURPOSES` both
  // decide by membership, so a typo that reached this column would silently be neither.
  for (const typo of ['pools', 'POOL', 'mining', '']) {
    await assert.rejects(
      () => sql`
        insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                                  key_version, storage, created_by)
        values (${`addr-${typo}`}, 'litecoin', 'bitcoin', ${typo}, 'mainnet', 'u', 'o', 'flat_random',
                2, 'file', 'test')
      `,
      /custody_keys_purpose_ck/,
      typo,
    )
  }
})

test('migration 8: a `pool` address CANNOT be pinned as the settlement treasury', { skip }, async () => {
  /*
   * The reason migration 8 exists at all, asserted against the database rather than argued.
   *
   * The pool mines LTC, and settlement pins an LTC treasury. Had the payout address simply been
   * minted with `purpose = 'treasury'`, it would have been a rotation CANDIDATE for that pin — and
   * a pinned pool address turns every block the pool ever mined into custody inflow the ledger has
   * no entry for. That is the shape of the drift that froze EMBER withdrawals for three days from
   * 2026-08-05 (micro-org#247, #248), with a coinbase's magnitude behind it.
   *
   * Raw INSERTs, deliberately: `pinTreasury` refuses this too, and its refusal is not what is under
   * test. What is under test is that migration 8's widening did not weaken migration 5's composite
   * reference — the FK compares `purpose` by VALUE against the literal 'treasury', so a new legal
   * purpose is a purpose no pin row can name.
   */
  const insertKeyRow = (address: string, purpose: string) => sql`
    insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                              key_version, storage, created_by)
    values (${address}, 'litecoin', 'bitcoin', ${purpose}, 'mainnet', 'cloudsforge:pool', 'o',
            'flat_random', 2, 'file', 'test')
  `
  await insertKeyRow('ltc1qpool', 'pool')
  await insertKeyRow('ltc1qtreasury', 'treasury')

  await assert.rejects(
    () => sql`
      insert into custody_treasuries (chain, network, address, set_by)
      values ('litecoin', 'mainnet', 'ltc1qpool', 'op')
    `,
    /custody_treasuries_key_fk/,
  )
  // Nor by naming the purpose the pin row would need in order to reach it: the column is held at
  // 'treasury' by an EQUALITY, which nothing added to the keys check can widen.
  await assert.rejects(
    () => sql`
      insert into custody_treasuries (chain, network, address, set_by, purpose)
      values ('litecoin', 'mainnet', 'ltc1qpool', 'op', 'pool')
    `,
    /custody_treasuries_purpose_ck/,
  )
  // And the treasury on the same chain still pins, so this proves a constraint rather than a table
  // that has stopped accepting anything.
  await sql`
    insert into custody_treasuries (chain, network, address, set_by)
    values ('litecoin', 'mainnet', 'ltc1qtreasury', 'op')
  `
  const rows = await sql<{ address: string }[]>`select address from custody_treasuries`
  assert.deepEqual(rows.map((r) => r.address), ['ltc1qtreasury'])
})

test('migration 8: the binding index does NOT cover `pool`, so a payout key stays re-mintable', { skip }, async () => {
  /*
   * The uniqueness decision, asserted so it is a decision rather than an oversight.
   *
   * `custody_keys_binding_uniq` still covers 'deposit' and 'deployer' only. A pool payout key
   * ACCUMULATES — every block found adds to it — so it is exactly the key an operator must be able
   * to abandon and replace on a suspected compromise. Under a binding index the replacement mint
   * would fail and the only routes left would be mutating or deleting the live row, which in this
   * service means orphaning the coin at an address whose row no longer says who holds it. This is
   * migration 6's reason for keeping `treasury` out, one purpose later.
   *
   * Which of these two is the LIVE payout address is not a fact custody holds: micro-pool reads one
   * address per chain from `POOL_<CHAIN>_PAYOUT_ADDRESS` and refuses to boot without it.
   */
  const insertPool = (address: string) => sql`
    insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                              key_version, storage, created_by)
    values (${address}, 'litecoin', 'bitcoin', 'pool', 'mainnet', 'cloudsforge:pool',
            'pool:litecoin:mainnet', 'flat_random', 2, 'file', 'test')
  `
  await insertPool('ltc1qpool-first')
  await insertPool('ltc1qpool-second')
  const rows = await sql<{ n: number }[]>`
    select count(*)::int as n from custody_keys where purpose = 'pool'
  `
  assert.equal(rows[0]?.n, 2, 'a rotation must be able to mint a second pool address')

  // The index it is absent from is still doing its job for the two purposes that ARE one-per-binding.
  await sql`
    insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                              key_version, storage, created_by)
    values ('ltc1qdeposit', 'litecoin', 'bitcoin', 'deposit', 'mainnet', 'u', 'assignment-1',
            'flat_random', 2, 'file', 'test')
  `
  await assert.rejects(
    () => sql`
      insert into custody_keys (address, chain, family, purpose, network, user_id, order_id, scheme,
                                key_version, storage, created_by)
      values ('ltc1qdeposit-again', 'litecoin', 'bitcoin', 'deposit', 'mainnet', 'u', 'assignment-1',
              'flat_random', 2, 'file', 'test')
    `,
    /custody_keys_binding_uniq/,
  )
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

test('the token allowlist stores ONE spelling of a contract, and the schema is what says so', { skip }, async () => {
  // The invariant the whole `token_sweep` allowlist rests on. `signing.ts` lower-cases the
  // candidate before asking, so a checksummed row in this table would be a row that can never match
  // — an entry an operator adds, sees accepted, and which silently never authorises anything.
  await assert.rejects(
    () => sql`
      insert into custody_token_contracts (chain, network, contract, symbol, decimals, set_by)
      values ('ethereum', 'mainnet', '0xdAC17F958D2ee523a2206206994597C13D831ec7', 'USDT', 6, 'test')
    `,
    /custody_token_contracts_contract_ck/,
  )
  // Nor a string that is merely lower-case without being an address.
  await assert.rejects(
    () => sql`
      insert into custody_token_contracts (chain, network, contract, symbol, decimals, set_by)
      values ('ethereum', 'mainnet', 'usdt', 'USDT', 6, 'test')
    `,
    /custody_token_contracts_contract_ck/,
  )
  // The lower-cased form is accepted, which is the half that proves the constraint is not simply
  // rejecting everything.
  await sql`
    insert into custody_token_contracts (chain, network, contract, symbol, decimals, set_by)
    values ('ethereum', 'mainnet', '0xdac17f958d2ee523a2206206994597c13d831ec7', 'USDT', 6, 'test')
  `
  const rows = await sql<{ contract: string }[]>`
    select contract from custody_token_contracts where chain = 'ethereum' and network = 'mainnet'
  `
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.contract, '0xdac17f958d2ee523a2206206994597c13d831ec7')
})

test('the same contract on two networks is two rows, and they cannot collide', { skip }, async () => {
  // A brand of stablecoin is a different deployment per network, and one being registered must
  // never make another callable. The primary key carries (chain, network) for that reason.
  const usdc = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
  await sql`
    insert into custody_token_contracts (chain, network, contract, symbol, decimals, set_by)
    values ('ethereum', 'mainnet', ${usdc}, 'USDC', 6, 'test'),
           ('ethereum', 'testnet', ${usdc}, 'USDC', 6, 'test')
  `
  await assert.rejects(
    () => sql`
      insert into custody_token_contracts (chain, network, contract, symbol, decimals, set_by)
      values ('ethereum', 'mainnet', ${usdc}, 'USDC', 6, 'test')
    `,
    /custody_token_contracts_pkey/,
  )
  const mainnet = await sql<{ contract: string }[]>`
    select contract from custody_token_contracts
    where chain = 'ethereum' and network = 'mainnet' and contract = ${usdc}
  `
  assert.equal(mainnet.length, 1, 'a network-scoped lookup must not see the other network\'s row')
})

test('a stablecoin registered with absurd decimals is refused at write time', { skip }, async () => {
  // Decimals are the field whose error is worth 10^12. The band does not make an operator right,
  // but it refuses the values that cannot be right at the moment they are typed.
  await assert.rejects(
    () => sql`
      insert into custody_token_contracts (chain, network, contract, symbol, decimals, set_by)
      values ('ethereum', 'mainnet', '0x0000000000000000000000000000000000000001', 'X', 99, 'test')
    `,
    /custody_token_contracts_decimals_ck/,
  )
  await assert.rejects(
    () => sql`
      insert into custody_token_contracts (chain, network, contract, symbol, decimals, set_by)
      values ('ethereum', 'testnet', '0x0000000000000000000000000000000000000002', '', 6, 'test')
    `,
    /custody_token_contracts_symbol_ck/,
  )
})
