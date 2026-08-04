/**
 * PROVISIONING IS IDEMPOTENT, AND THE PROOF IS NOT A LOOKUP.
 *
 * `POST /v1/addresses` mints the address a user is told to send money to. Both callers reach it
 * over HTTP, so a timeout on a request that actually succeeded is the ordinary case rather than an
 * exotic one — and `@cloudsforge/http` makes it likelier still, because a request carrying an
 * `idempotency-key` is one it will RETRY by itself (`node_modules/@cloudsforge/http/dist/index.js`
 * line 138: `retriable = IDEMPOTENT_METHODS.has(method) || options.idempotencyKey !== undefined`).
 * Until migration 6 a retry minted a SECOND address: a second place a user's money can arrive,
 * which has to be noticed, swept and accounted for before it is money at all.
 *
 * ── WHAT COUNTS AS "THE SAME REQUEST" ────────────────────────────────────────────────────────
 *
 * Two identities, because the two callers hand over two different things:
 *
 *   1. **the caller's own key**, `(created_by, idempotency-key)`. wallet sends one
 *      (`wallet/src/custodyclient.ts:266`) and so does mint (`mint/src/custodyclient.ts:203`).
 *      Scoped by actor because the string is the caller's to choose and two services must not be
 *      able to collide by coincidence.
 *   2. **the binding**, `(chain, network, purpose, user_id, order_id)`, for `deposit` and
 *      `deployer` only. Those two purposes take their `orderId` from a row that is created once per
 *      ADDRESS — wallet's assignment id (`wallet/src/deposits.ts:196`) and mint's token id
 *      (`mint/src/deploy.ts:179`) — so a second row under one binding cannot be anything but a
 *      duplicate. It catches the retry that carried no key, or a different one.
 *
 * And `treasury` is deliberately NOT in the second identity. Its binding is fixed per chain and
 * network by derivation (`keys.treasuryBinding`), so a rotation candidate is minted with the SAME
 * binding on purpose — `pickOutstandingCandidate` (`store.ts:350`) is that route's own reuse rule
 * and it has to be able to hand back a NEW address after a pin. Deduplicating on the binding there
 * would make a treasury rotation impossible, which is the "too loose" failure this file also pins.
 *
 * ── AND WHY THE FIRST TEST IS AN INSERT AND NOT A REQUEST ────────────────────────────────────
 *
 * A lookup that runs before a mint is a check that cannot fail in a test and cannot succeed under a
 * race: both requests read, both find nothing, both mint. The invariant is therefore a UNIQUE INDEX
 * and the lookup is only an optimisation — so the first case here bypasses every line of
 * application code and asserts the database itself refuses.
 */

import test, { after, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { ADDRESS_CREATE_SCOPE } from './server.ts'
import { insertKey } from './store.ts'
import {
  ALICE,
  BOB,
  capturingLogger,
  enabled,
  harness,
  migrateTestDb,
  openDb,
  resetCustody,
  serviceToken,
  silentLogger,
  skip,
  startServer,
  stubVerifier,
  testLifecycle,
  testMetrics,
  userToken,
  type Harness,
  type RunningServer,
} from './testsupport.ts'

const OPERATOR = '99999999-9999-4999-8999-999999999999'
const TOKENS = {
  wallet: serviceToken('wallet', [ADDRESS_CREATE_SCOPE]),
  mint: serviceToken('mint', [ADDRESS_CREATE_SCOPE]),
  operator: userToken(OPERATOR, { roles: ['admin'] }),
}

let sql: postgres.Sql
let h: Harness
let server: RunningServer
/** Keeps the `provision_raced` audits, which is how the concurrency cases prove what refused them. */
const provisioning = capturingLogger()

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
  h = await harness({ sql, logger: provisioning })
  server = await startServer({
    lifecycle: testLifecycle(),
    logger: silentLogger,
    metrics: testMetrics(),
    verifier: stubVerifier(TOKENS),
    keys: h.keys,
    exports: h.exports,
    // High enough that the rate limiter never decides one of these cases for us: a 429 and a
    // deduplicated 200 are both "no second address", and only one of them is what is being proved.
    limits: { signPerMinute: 50, addressPerHour: 500 },
    now: () => h.clock(),
  })
})

after(async () => {
  if (!enabled) return
  await server.close()
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (!enabled) return
  await resetCustody(sql)
  provisioning.audits.length = 0
})

const DEPOSIT = { chain: 'ember', network: 'testnet', purpose: 'deposit', userId: ALICE } as const

const create = (body: Record<string, unknown>, idempotencyKey?: string) =>
  server.request('/v1/addresses', {
    method: 'POST',
    token: 'wallet',
    body,
    ...(idempotencyKey === undefined ? {} : { headers: { 'idempotency-key': idempotencyKey } }),
  })

const addressOf = (response: { body: Record<string, unknown> }): string =>
  (response.body.key as Record<string, unknown>).address as string

/** Counted, never listed. The point is how many exist, and the address is not the interesting part. */
async function keyCount(): Promise<number> {
  const rows = await sql<{ n: number }[]>`select count(*)::int as n from custody_keys`
  return rows[0]!.n
}

async function createdEvents(): Promise<number> {
  const rows = await sql<{ n: number }[]>`
    select count(*)::int as n from outbox where topic = 'custody.address.created'
  `
  return rows[0]!.n
}

/* ------------------------------------------------------------------ the invariant itself */

test('THE INVARIANT: the DATABASE refuses a second deposit key for one binding', { skip }, async () => {
  // No route, no `provisionAddress`, no lookup. This is what is left when the application is the
  // thing that is wrong — "the application is one deploy away from being wrong and the row outlives
  // the deploy". Two DIFFERENT addresses, so nothing but the binding index can refuse the second.
  const row = (address: string) =>
    ({
      address,
      chain: 'ember',
      family: 'evm',
      purpose: 'deposit',
      network: 'testnet',
      userId: ALICE,
      orderId: 'one-assignment',
      scheme: 'flat_random',
      derivationPath: null,
      seedId: null,
      keyVersion: 1,
      storage: 'memory',
      createdBy: 'service:wallet',
    }) as const

  await insertKey(sql, row(`0x${'11'.repeat(20)}`))
  await assert.rejects(
    () => insertKey(sql, row(`0x${'22'.repeat(20)}`)),
    (err: unknown) => {
      const e = err as { code?: string; constraint_name?: string }
      assert.equal(e.code, '23505', 'a duplicate binding must be a unique violation, not a second row')
      assert.equal(e.constraint_name, 'custody_keys_binding_uniq')
      return true
    },
  )
  assert.equal(await keyCount(), 1)
})

test('THE INVARIANT: the DATABASE refuses one caller reusing one idempotency key', { skip }, async () => {
  // Different bindings, so the binding index is not what refuses — the second insert is a caller
  // saying "this is the same request" about a request that is not the same one.
  const row = (address: string, orderId: string) =>
    ({
      address,
      chain: 'ember',
      family: 'evm',
      purpose: 'deposit',
      network: 'testnet',
      userId: ALICE,
      orderId,
      scheme: 'flat_random',
      derivationPath: null,
      seedId: null,
      keyVersion: 1,
      storage: 'memory',
      createdBy: 'service:wallet',
      idempotencyKey: 'wallet:deposit:alice:EMBER:testnet:first',
    }) as const

  await insertKey(sql, row(`0x${'33'.repeat(20)}`, 'assignment-1'))
  await assert.rejects(
    () => insertKey(sql, row(`0x${'44'.repeat(20)}`, 'assignment-2')),
    (err: unknown) => {
      const e = err as { code?: string; constraint_name?: string }
      assert.equal(e.code, '23505')
      assert.equal(e.constraint_name, 'custody_keys_idempotency_uniq')
      return true
    },
  )
  assert.equal(await keyCount(), 1)
})

test('the idempotency key is scoped to the caller, so two services cannot collide', { skip }, async () => {
  const key = 'provision-1'
  const first = await create({ ...DEPOSIT, orderId: 'assignment-1' }, key)
  const second = await server.request('/v1/addresses', {
    method: 'POST',
    token: 'mint',
    body: { chain: 'ember', network: 'testnet', purpose: 'deployer', userId: BOB, orderId: 'token-1' },
    headers: { 'idempotency-key': key },
  })
  assert.equal(first.status, 201, first.text)
  assert.equal(second.status, 201, second.text)
  assert.notEqual(addressOf(first), addressOf(second))
  assert.equal(await keyCount(), 2)
})

/* ------------------------------------------------------------------ the replay */

test('THE REPLAY: a repeat returns the ORIGINAL address and does not look like a fresh mint', { skip }, async () => {
  const body = { ...DEPOSIT, orderId: 'assignment-1' }
  const first = await create(body, 'wallet:deposit:alice:EMBER:testnet:first')
  const second = await create(body, 'wallet:deposit:alice:EMBER:testnet:first')

  assert.equal(first.status, 201, first.text)
  assert.equal(first.body.reused, undefined, 'a fresh mint keeps the body it has always had — `{ key }` and nothing else')

  assert.equal(second.status, 200, 'not 201: a replay CREATED nothing, and the status is the first place a caller reads that')
  assert.equal(second.body.reused, true, 'the vocabulary the treasury mint route already uses (server.ts:680)')
  assert.equal(addressOf(second), addressOf(first))

  assert.equal(await keyCount(), 1, 'one address, which is the whole point')
  assert.equal(
    await createdEvents(),
    1,
    'and ONE custody.address.created. A second event is a second downstream effect — an indexer ' +
      'registration, a ledger entry — for an address that was not created',
  )
})

test('THE REPLAY: it works with no idempotency key at all, because the binding is one too', { skip }, async () => {
  // The retry that lost its key, and the caller that never sent one. mint's client documents this
  // exact property — "Idempotent on (chain, network, userId, orderId)"
  // (`mint/src/custodyclient.ts:124`) — and it was not true until migration 6.
  const body = { ...DEPOSIT, orderId: 'assignment-1' }
  const first = await create(body)
  const second = await create(body)
  assert.equal(first.status, 201, first.text)
  assert.equal(second.status, 200, second.text)
  assert.equal(second.body.reused, true)
  assert.equal(addressOf(second), addressOf(first))
  assert.equal(await keyCount(), 1)
  assert.equal(await createdEvents(), 1)
})

test('THE REPLAY: a rotation is NOT a retry — a fresh orderId mints a distinct address', { skip }, async () => {
  // The shape wallet actually sends on `rotate: true`: a new assignment id, and an idempotency key
  // that names the assignment being replaced (`wallet/src/deposits.ts:222`). Both differ, so
  // neither identity matches, and the user gets the second address a rotation exists to give them.
  const first = await create({ ...DEPOSIT, orderId: 'assignment-1' }, 'wallet:deposit:alice:EMBER:testnet:first')
  const second = await create({ ...DEPOSIT, orderId: 'assignment-2' }, 'wallet:deposit:alice:EMBER:testnet:assignment-1')
  assert.equal(first.status, 201, first.text)
  assert.equal(second.status, 201, second.text)
  assert.notEqual(addressOf(first), addressOf(second))
  assert.equal(await keyCount(), 2)
  assert.equal(await createdEvents(), 2, 'two mints, two events — a rotation IS a fresh mint')
})

test('a treasury rotation still mints, because its binding is shared by design', { skip }, async () => {
  // `treasuryBinding` is derived from (chain, network) alone (`keys.ts:528`), so every rotation
  // candidate for a chain carries the SAME binding. If `treasury` were inside the binding index the
  // first pin would be the last one this chain could ever have.
  const mint = () => server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  const first = await mint()
  assert.equal(first.status, 201, first.text)
  const pinned = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'operator',
    body: { address: addressOf(first) },
  })
  assert.equal(pinned.status, 200, pinned.text)

  const candidate = await mint()
  assert.equal(candidate.status, 201, candidate.text)
  assert.notEqual(addressOf(candidate), addressOf(first), 'a pinned treasury must have somewhere to rotate TO')
})

/* ------------------------------------------------------------------ the conflict */

test('THE CONFLICT: one key over two bindings is refused, never answered with the wrong address', { skip }, async () => {
  /*
   * The dangerous direction, and the reason the key alone is not the identity.
   *
   * `orderId` is what settlement restates character for character to sweep the address — "a guessed
   * binding is a sweep refused every tick for ever" (`settlement/src/server.ts:739`). Handing back
   * the FIRST request's address to a caller that named the SECOND request's orderId would file an
   * address under a binding custody never stored, and every sweep of it would be refused for ever.
   * A 409 costs the caller a retry. The alternative costs a user their deposit.
   */
  const first = await create({ ...DEPOSIT, orderId: 'assignment-1' }, 'one-key')
  const second = await create({ ...DEPOSIT, orderId: 'assignment-2' }, 'one-key')
  assert.equal(first.status, 201, first.text)
  assert.equal(second.status, 409, second.text)
  assert.equal((second.body.error as Record<string, unknown>).code, 'idempotency_conflict')
  assert.equal(second.body.key, undefined, 'and no address at all, rather than one bound to somebody else’s order')
  assert.equal(await keyCount(), 1)
})

/* ------------------------------------------------------------------ the race */

test('CONCURRENT: four in-flight requests with one idempotency key yield ONE address', { skip }, async () => {
  /*
   * THE ONE THAT MATTERS. A sequential pair proves the lookup ran; it cannot distinguish a service
   * that is idempotent from one whose window is merely narrow. These four requests are dispatched
   * without awaiting each other, so every one of them reads the table before any of them has
   * committed — which is precisely the interleaving where a find-then-create is no protection at
   * all, and the unique index is the only thing left.
   */
  const body = { ...DEPOSIT, orderId: 'assignment-1' }
  const responses = await Promise.all([
    create(body, 'one-key'),
    create(body, 'one-key'),
    create(body, 'one-key'),
    create(body, 'one-key'),
  ])

  const addresses = new Set(responses.map(addressOf))
  assert.equal(addresses.size, 1, 'four callers, one address')
  assert.equal(responses.filter((r) => r.status === 201).length, 1, 'exactly one of them minted')
  assert.equal(responses.filter((r) => r.status === 200 && r.body.reused === true).length, 3)
  assert.equal(await keyCount(), 1)
  assert.equal(await createdEvents(), 1)
})

test('CONCURRENT: four in-flight requests with NO key yield one address too', { skip }, async () => {
  // The binding index carrying the same weight for a caller that sent no key.
  const body = { ...DEPOSIT, orderId: 'assignment-1' }
  const responses = await Promise.all([create(body), create(body), create(body), create(body)])
  assert.equal(new Set(responses.map(addressOf)).size, 1)
  assert.equal(responses.filter((r) => r.status === 201).length, 1)
  assert.equal(await keyCount(), 1)
  assert.equal(await createdEvents(), 1)
})

test('CONCURRENT: one key over two bindings races to one 201 and one 409', { skip }, async () => {
  // wallet's real double-tap: two requests that both got past its find-or-create row check, each
  // carrying a freshly minted assignment id and the SAME derived key. One address, and the loser is
  // told no rather than handed the winner's address under its own orderId.
  const [a, b] = await Promise.all([
    create({ ...DEPOSIT, orderId: 'assignment-1' }, 'one-key'),
    create({ ...DEPOSIT, orderId: 'assignment-2' }, 'one-key'),
  ])
  const statuses = [a!.status, b!.status].sort((x, y) => x - y)
  assert.deepEqual(statuses, [201, 409])
  assert.equal(await keyCount(), 1)
  assert.equal(await createdEvents(), 1)
})

test('CONCURRENT: an insert that commits mid-request is refused BY THE INDEX, deterministically', { skip }, async () => {
  /*
   * THE CASE THE THREE ABOVE CANNOT GUARANTEE THEY EXERCISED.
   *
   * `Promise.all` produces a genuine race, but not a chosen one: on a fast machine the first
   * request can commit before the others have read, and then it is the LOOKUP that deduplicates and
   * the index is never reached. Every assertion still passes — which is the shape of a check that
   * cannot fail, and the reason this case exists.
   *
   * So the interleaving is constructed rather than hoped for. A transaction holding an unrelated
   * connection inserts the winning row and is held OPEN, so the request's lookup cannot see it;
   * the request derives a key, writes its blob, and its own insert blocks on the unique index
   * (Postgres waits on the other transaction rather than failing). Only when the winner commits is
   * the 23505 raised — the exact ordering a lookup is powerless against.
   *
   * `provision_raced` is logged from nowhere but the 23505 handler, so asserting it is asserting
   * that the constraint, and nothing else, is what kept this to one address.
   */
  const body = { ...DEPOSIT, orderId: 'assignment-1' }
  const winnerAddress = `0x${'55'.repeat(20)}`

  let commitWinner!: () => void
  const held = new Promise<void>((resolve) => {
    commitWinner = resolve
  })
  const winner = sql.begin(async (tx) => {
    await insertKey(tx, {
      address: winnerAddress,
      chain: 'ember',
      family: 'evm',
      purpose: 'deposit',
      network: 'testnet',
      userId: ALICE,
      orderId: 'assignment-1',
      scheme: 'flat_random',
      derivationPath: null,
      seedId: null,
      keyVersion: 1,
      storage: 'memory',
      createdBy: 'service:wallet',
    })
    await held
  })

  const pending = create(body, 'one-key')
  await waitUntilBlockedOnLock()
  commitWinner()
  await winner

  const response = await pending
  assert.equal(response.status, 200, response.text)
  assert.equal(response.body.reused, true)
  assert.equal(addressOf(response), winnerAddress, 'the caller is given the address that actually exists')
  assert.equal(provisioning.count('provision_raced'), 1, 'and it got there through the 23505 handler, not the lookup')
  assert.equal(await keyCount(), 1)
  assert.equal(await createdEvents(), 0, 'the winner here was a bare insert, so the only event would be a wrong one')
})

/**
 * Wait until some backend is waiting on another's lock.
 *
 * Polling `pg_blocking_pids` rather than sleeping: a sleep long enough to be reliable is a slow
 * suite, and a sleep short enough to be fast is a flaky one that silently stops testing the thing.
 */
async function waitUntilBlockedOnLock(): Promise<void> {
  for (let attempt = 0; attempt < 250; attempt += 1) {
    const rows = await sql<{ n: number }[]>`
      select count(*)::int as n from pg_stat_activity
       where cardinality(pg_blocking_pids(pid)) > 0
    `
    if ((rows[0]?.n ?? 0) > 0) return
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  throw new Error('no backend ever blocked, so the request never reached the unique index')
}
