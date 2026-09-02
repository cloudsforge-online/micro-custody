/**
 * THE PROVISIONING CONTRACT, PINNED FROM THIS SIDE.
 *
 * `POST /v1/addresses` is the only way an address enters the platform, and therefore the only way
 * money does: payments here are crypto-native, so a balance is funded by an on-chain deposit to an
 * address this route minted, or it is not funded at all.
 *
 * Its caller is wallet, in another repository, which cannot import this server — so the two agree
 * about the wire by each pinning it, and this file is this side's half. Between 2026 and 2026-08-04
 * they did not agree and nothing said so:
 *
 *   * wallet sent no `orderId`, which this route requires, so every live call answered
 *     400 `bad_request`. wallet's own suite passed throughout, against a fake custody that did not
 *     ask for it.
 *   * wallet expected a flat body with a `custodyKeyUrn` on it. This route has never sent either —
 *     the body is `{ key: … }` and `CustodyKeyRecord` has no identifier field, because the key
 *     table is keyed by `address` (`migrations.ts`) and `04-domain-model.md` §3.3 names no other.
 *
 * So the two properties below are the ones a caller in another repository has to be able to rely
 * on, and they are asserted by NAME rather than by a snapshot: a field that disappears must fail
 * saying which field, because the person reading the failure is working in a different repository
 * from the one they will have to change.
 *
 * The matching half is `wallet/src/custodycontract.test.ts`, which drives wallet's real HTTP client
 * against a stub built from the assertions in this file, each line citing where it was read from.
 */

import test, { after, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { ADDRESS_CREATE_SCOPE } from './server.ts'
import {
  ALICE,
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
  type Harness,
  type RunningServer,
} from './testsupport.ts'

/** Any value: these suites never post a signed event, they only satisfy `ServerDeps`. */
const EVENT_SECRET = 'test-event-signing-secret'

const TOKENS = { wallet: serviceToken('wallet', [ADDRESS_CREATE_SCOPE]) }

let sql: postgres.Sql
let h: Harness
let server: RunningServer

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
  h = await harness({ sql })
  server = await startServer({
    lifecycle: testLifecycle(),
    logger: silentLogger,
    metrics: testMetrics(),
    verifier: stubVerifier(TOKENS),
    keys: h.keys,
    exports: h.exports,
    limits: { signPerMinute: 5, addressPerHour: 50 },
    eventSigningSecret: EVENT_SECRET,
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
})

const create = (body: Record<string, unknown>) =>
  server.request('/v1/addresses', { method: 'POST', token: 'wallet', body })

/**
 * Every field `toKeyRecord` publishes (`store.ts`), and no others.
 *
 * Both directions are checked. A field that vanishes breaks a caller reading it; a field that
 * APPEARS is the one that matters most here, because this is the service that holds private keys
 * and SD-16's body scan (`bodyscan.test.ts`) is a scan for known secret VALUES — a new field
 * carrying something derived from a key would pass it. An exact set means a new field has to be
 * added here deliberately, by someone who has read this comment.
 */
const PUBLISHED = [
  'address',
  'chain',
  'createdAt',
  'derivationPath',
  'exportedAt',
  'family',
  'keyVersion',
  'network',
  'purpose',
  'scheme',
  'status',
] as const

test('THE CONTRACT: the minted key is published under `key`, with exactly these fields', { skip }, async () => {
  const response = await create({
    chain: 'ember',
    network: 'testnet',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'an-assignment-id',
  })
  assert.equal(response.status, 201, response.text)

  assert.deepEqual(
    Object.keys(response.body).sort(),
    ['key'],
    'the success body is `{ key: … }` and nothing else — a caller reading the top level for an ' +
      'address finds undefined, which is exactly the defect this file exists to stop',
  )
  const key = response.body.key as Record<string, unknown>
  assert.deepEqual([...Object.keys(key)].sort(), [...PUBLISHED].sort())

  // The three a caller cannot do without, by value rather than by presence.
  assert.match(String(key.address), /^0x[0-9a-fA-F]{40}$/)
  assert.equal(key.chain, 'ember', 'chain is echoed, so a caller can detect a mint on the wrong one')
  assert.equal(key.network, 'testnet')
  assert.equal(key.scheme, 'hd_bip44', 'the default scheme, and the one that carries a path')
  assert.equal(typeof key.derivationPath, 'string')

  // NOT published, and the reason is load-bearing: `userId` and `orderId` are the entropy in the
  // /sign binding (`keys.ts`), so serving them under the same credential that signs would make
  // the binding check circular. A caller must already know them — see `store.ts`.
  assert.equal(key.userId, undefined)
  assert.equal(key.orderId, undefined)
  // And there is no identifier of any kind. The address IS the identity (`migrations.ts`).
  assert.equal(key.id, undefined)
  assert.equal(key.custodyKeyUrn, undefined)
})

test('THE CONTRACT: orderId is required, and its absence is a 400 that says so', { skip }, async () => {
  const response = await create({
    chain: 'ember',
    network: 'testnet',
    purpose: 'deposit',
    userId: ALICE,
  })
  assert.equal(
    response.status,
    400,
    'orderId is read with `stringField` and no default (server.ts:349) because it is one of ' +
      'SD-09’s five binding fields — if this ever answers 201, the binding has been hollowed out',
  )
  const error = response.body.error as Record<string, unknown>
  assert.equal(error.code, 'bad_request')
  assert.equal(error.message, 'orderId must be a non-empty string')
})

test('an orderId of whitespace is refused as emptily as an absent one', { skip }, async () => {
  const response = await create({
    chain: 'ember',
    network: 'testnet',
    purpose: 'deposit',
    userId: ALICE,
    orderId: '   ',
  })
  assert.equal(response.status, 400, response.text)
  assert.equal((response.body.error as Record<string, unknown>).message, 'orderId must be a non-empty string')
})

test('THE CONTRACT: network, purpose and scheme default, which is why they were never missed', { skip }, async () => {
  // The asymmetry that hid the defect for the life of the service. These three are `enumField`
  // with a fallback (`server.ts`); `chain`, `userId` and `orderId` are `stringField` with
  // none. A caller that omitted all six would be told about exactly the three that matter.
  const response = await create({ chain: 'ember', userId: ALICE, orderId: 'an-assignment-id' })
  assert.equal(response.status, 201, response.text)
  const key = response.body.key as Record<string, unknown>
  assert.equal(key.network, 'testnet')
  assert.equal(key.purpose, 'deposit')
  assert.equal(key.scheme, 'hd_bip44')
})

test('the binding is stored as sent, because a sweep has to restate it character for character', { skip }, async () => {
  // wallet sends its deposit assignment id here and settlement restates it to sweep the address
  // (`settlement/src/server.ts`). Whatever arrives must be what is stored: a trim is fine, a
  // normalisation would silently break every future signature for the address.
  const orderId = '0199a3f0-7c2a-7000-8000-0000000000ab'
  const response = await create({
    chain: 'ember',
    network: 'testnet',
    purpose: 'deposit',
    userId: ALICE,
    orderId: `  ${orderId}  `,
  })
  assert.equal(response.status, 201, response.text)
  const address = (response.body.key as Record<string, unknown>).address as string
  const rows = await sql<{ order_id: string; user_id: string }[]>`
    select order_id, user_id from custody_keys where address = ${address}
  `
  assert.equal(rows[0]?.order_id, orderId)
  assert.equal(rows[0]?.user_id, ALICE)
})

test('two assignments for one user are two addresses, so the binding is per address', { skip }, async () => {
  // wallet uses the assignment id rather than a stable per-(user, asset) string precisely so that
  // a rotation does not reuse a binding. This is the property that makes that choice mean anything.
  const first = await create({ chain: 'ember', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'assignment-1' })
  const second = await create({ chain: 'ember', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'assignment-2' })
  assert.equal(first.status, 201, first.text)
  assert.equal(second.status, 201, second.text)
  assert.notEqual(
    (first.body.key as Record<string, unknown>).address,
    (second.body.key as Record<string, unknown>).address,
  )
})

test('THE CONTRACT: a repeated request returns the ORIGINAL address, and says it created nothing', { skip }, async () => {
  /*
   * THIS TEST USED TO ASSERT THE OPPOSITE, and it was right to.
   *
   * Until migration 6 it read "THE GAP: the same idempotency key mints a SECOND address — custody
   * does not dedupe", and it passed: `provisionAddress` minted unconditionally and the
   * `idempotency-key` header was not read anywhere, while wallet's client documented "Custody
   * returns the same address for the same key" and mint's still says "Idempotent on (chain,
   * network, userId, orderId)" (`mint/src/custodyclient.ts`). Two callers believed a property
   * this service had never had. It said of itself: "THE DAY THIS TEST STARTS FAILING IS THE DAY
   * CUSTODY GAINED IDEMPOTENCY", and that day is what this rewrite records.
   *
   * The full behaviour — the two identities, the conflict, the concurrency — is
   * `idempotency.test.ts`. What belongs HERE is the part a caller in another repository has to be
   * able to rely on: the address, and the status that distinguishes a replay from a mint.
   */
  const body = { chain: 'ember', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'assignment-1' }
  const first = await create(body)
  const second = await create(body)
  assert.equal(first.status, 201, first.text)
  assert.equal(second.status, 200, 'a replay created nothing, and 201 would say it had')
  assert.equal(second.body.reused, true)
  assert.equal(
    (second.body.key as Record<string, unknown>).address,
    (first.body.key as Record<string, unknown>).address,
    'a retry must be given the address the first call published, not a second place money can land',
  )
})
