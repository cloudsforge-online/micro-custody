/**
 * The routes, against a real database and a real socket.
 *
 * This is where the gates stop being pure functions and become the behaviour of a service: the order
 * they run in, the audit row that a successful signature is committed with, the rate limit that
 * counts that audit row, and the route that no longer exists.
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import { ethers } from 'ethers'
import type postgres from 'postgres'
import { ADDRESS_CREATE_SCOPE, TREASURY_READ_SCOPE } from './server.ts'
import {
  ALICE,
  BOB,
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

const SIGN_SCOPES = ['custody:sign:deposit', 'custody:sign:treasury', 'custody:sign:deployer']
const TOKENS = {
  wallet: serviceToken('wallet', [ADDRESS_CREATE_SCOPE, TREASURY_READ_SCOPE, ...SIGN_SCOPES]),
  // Deliberately narrow: SD-05's "a test per service asserting it is refused on a scope it should
  // not hold". `settlement` may sweep deposits and may not touch the treasury.
  settlement: serviceToken('settlement', ['custody:sign:deposit', TREASURY_READ_SCOPE]),
  unscoped: serviceToken('marketing', ['pricing:read']),
  alice: userToken(ALICE),
  bob: userToken(BOB),
  operator: userToken('99999999-9999-4999-8999-999999999999', { roles: ['admin'] }),
}

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
    limits: { signPerMinute: 5, addressPerHour: 10 },
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

/* ------------------------------------------------------------------ helpers */

async function mint(body: Record<string, unknown>, token = 'wallet') {
  const response = await server.request('/v1/addresses', { method: 'POST', token, body })
  return response
}

async function mintDeposit(userId = ALICE, orderId = 'order-1') {
  const response = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId, orderId })
  assert.equal(response.status, 201, response.text)
  return (response.body.key as Record<string, unknown>).address as string
}

async function mintAndPinTreasury(chain = 'ethereum', network = 'testnet') {
  const minted = await server.request(`/v1/admin/treasuries/${chain}/${network}/mint`, {
    method: 'POST',
    token: 'operator',
  })
  assert.equal(minted.status, 201, minted.text)
  const address = (minted.body.key as Record<string, unknown>).address as string
  const pinned = await server.request(`/v1/admin/treasuries/${chain}/${network}`, {
    method: 'PUT',
    token: 'operator',
    body: { address },
  })
  assert.equal(pinned.status, 200, pinned.text)
  return address
}

const sweepTx = (to: string, chainId = 11_155_111) => ({
  to,
  value: '1000000000000000',
  nonce: 0,
  gasLimit: 21_000,
  chainId,
  maxFeePerGas: '20000000000',
  maxPriorityFeePerGas: '1000000000',
})

async function signRequest(body: Record<string, unknown>, token = 'wallet') {
  return server.request('/v1/sign', { method: 'POST', token, body })
}

/** The error envelope, narrowed. `noUncheckedIndexedAccess` makes the raw index `string | undefined`. */
function errorOf(response: { body: Record<string, unknown> }): { code: string; message: string } {
  const error = (response.body.error ?? {}) as Record<string, unknown>
  return { code: String(error.code ?? ''), message: String(error.message ?? '') }
}

function depositBinding(address: string, payload: unknown, overrides: Record<string, unknown> = {}) {
  return {
    address,
    chain: 'ethereum',
    network: 'testnet',
    family: 'evm',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'order-1',
    payload,
    ...overrides,
  }
}

/* ------------------------------------------------------------------ health */

test('health and metrics answer without a token', { skip }, async () => {
  assert.equal((await server.request('/livez')).status, 200)
  assert.equal((await server.request('/readyz')).status, 200)
  const metrics = await server.request('/metrics')
  assert.equal(metrics.status, 200)
  assert.match(metrics.text, /custody_signatures_total/)
})

test('every response is no-store — SD-07 gate 8, set centrally so a route cannot forget it', { skip }, async () => {
  for (const path of ['/livez', '/v1/keys', '/v1/addresses/nope']) {
    const response = await server.request(path, { token: 'alice' })
    assert.equal(response.headers.get('cache-control'), 'no-store', path)
  }
})

/* ------------------------------------------------------------------ SD-08 */

test('SD-08: POST /admin/keys/:address/reveal DOES NOT EXIST — 404, under an admin token', { skip }, async () => {
  // The route that returned any private key in plaintext to any administrator JWT. Asserted rather
  // than trusted, and asserted under the credential that used to be sufficient for it.
  const address = await mintDeposit()
  for (const path of [
    `/admin/keys/${address}/reveal`,
    `/v1/admin/keys/${address}/reveal`,
    `/v1/keys/${address}/reveal`,
  ]) {
    const response = await server.request(path, { method: 'POST', token: 'operator' })
    assert.equal(response.status, 404, path)
  }
})

/* ------------------------------------------------------------------ provisioning */

test('an address is minted HD by default, and the response states the scheme', { skip }, async () => {
  const response = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1' })
  assert.equal(response.status, 201, response.text)
  const key = response.body.key as Record<string, unknown>
  assert.equal(key.scheme, 'hd_bip44')
  assert.equal(key.derivationPath, "m/44'/1'/0'/0/0")
  assert.equal(key.status, 'active')
  assert.equal(ethers.isAddress(key.address as string), true)
  // 04-domain-model §3.3: every custody response states the scheme, because it decides which export
  // formats can honestly be offered.
  assert.equal('privateKey' in key, false)
})

test('a second address for one user advances the index on the SAME seed', { skip }, async () => {
  const first = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1' })
  const second = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o2' })
  assert.equal((second.body.key as Record<string, unknown>).derivationPath, "m/44'/1'/0'/0/1")
  assert.notEqual((first.body.key as Record<string, unknown>).address, (second.body.key as Record<string, unknown>).address)
  const seeds = await sql`select count(*)::int as n from custody_seeds where user_id = ${ALICE}`
  assert.equal(seeds[0]!.n, 1)
})

test('THE XRP FIX: a flat-random XRP key cannot be minted at all', { skip }, async () => {
  // The only path that could reintroduce SD-09's "one signed Payment is submittable on either
  // network" defect for a key this service creates.
  const response = await mint({ chain: 'xrp', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1', scheme: 'flat_random' })
  assert.equal(response.status, 400)
  assert.equal((response.body.error as Record<string, unknown>).code, 'scheme_refused')

  const hd = await mint({ chain: 'xrp', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1' })
  assert.equal(hd.status, 201, hd.text)
  const testnetAddress = (hd.body.key as Record<string, unknown>).address
  const mainnet = await mint({ chain: 'xrp', network: 'mainnet', purpose: 'deposit', userId: ALICE, orderId: 'o2' })
  assert.notEqual((mainnet.body.key as Record<string, unknown>).address, testnetAddress)
})

test('a legacy flat-random key stays mintable in the families that had them, and is NOT migratable', { skip }, async () => {
  const response = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1', scheme: 'flat_random' })
  assert.equal(response.status, 201, response.text)
  const key = response.body.key as Record<string, unknown>
  assert.equal(key.scheme, 'flat_random')
  // SDR-08, in the database: the CHECK constraint refuses a flat row that claims a path, so nothing
  // can quietly relabel a legacy key as recoverable from a phrase that does not exist.
  assert.equal(key.derivationPath, null)
  await assert.rejects(
    () => sql`update custody_keys set derivation_path = 'm/44''/60''/0''/0/0' where address = ${key.address as string}`,
    /custody_keys_scheme_ck/,
  )
})

test('an unknown chain is refused', { skip }, async () => {
  const response = await mint({ chain: 'dogecoin', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1' })
  assert.equal(response.status, 400)
})

test('minting requires the address scope, not merely a token', { skip }, async () => {
  const response = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1' }, 'unscoped')
  assert.equal(response.status, 403)
})

test('GET /v1/addresses/:address publishes neither userId nor orderId', { skip }, async () => {
  // Publishing them made the binding check circular in forge-keyvault: everything a caller had to
  // prove it knew was served, under the same credential, from a read.
  const address = await mintDeposit()
  const response = await server.request(`/v1/addresses/${address}`, { token: 'wallet' })
  assert.equal(response.status, 200)
  const key = response.body.key as Record<string, unknown>
  assert.equal('userId' in key, false)
  assert.equal('orderId' in key, false)
})

test('a user cannot read another user\'s address, and is told 404 rather than 403', { skip }, async () => {
  const address = await mintDeposit(ALICE)
  assert.equal((await server.request(`/v1/addresses/${address}`, { token: 'alice' })).status, 200)
  // A 403 would confirm the address exists, which is the fact a stranger has no business learning.
  assert.equal((await server.request(`/v1/addresses/${address}`, { token: 'bob' })).status, 404)
})

/* ------------------------------------------------------------------ signing */

test('a permitted sweep is signed, and the signature is FROM the address', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit()
  const response = await signRequest(depositBinding(address, sweepTx(treasury)))
  assert.equal(response.status, 200, response.text)
  const parsed = ethers.Transaction.from(response.body.signedTx as string)
  assert.equal(parsed.from, address)
  assert.equal(parsed.to, treasury)
  assert.equal(parsed.chainId, 11_155_111n)
})

test('SD-09/SD-15: a SUCCESSFUL sign writes an audit row, in the same transaction', { skip }, async () => {
  // In forge-keyvault a successful sign recorded nothing at all; only refusals reached a log line.
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit()
  const response = await signRequest(depositBinding(address, sweepTx(treasury)))
  assert.equal(response.status, 200, response.text)

  const rows = await sql`select * from signing_audit where address = ${address}`
  assert.equal(rows.length, 1)
  const row = rows[0]!
  assert.equal(row.outcome, 'signed')
  assert.equal(row.actor, 'service:wallet')
  assert.equal(row.user_id, ALICE)
  assert.equal(row.shape, 'sweep')
  // The id is returned so a caller can quote it, and the audit row is what it names.
  assert.equal(row.id, response.body.auditId)
  // NEITHER the payload NOR the signature is stored — a signed transaction in a table is a
  // submittable transaction anyone with database read access could broadcast.
  assert.equal(typeof row.payload_digest, 'string')
  assert.equal(row.payload_digest.length, 64)
  assert.equal(String(row.signature_digest).length, 64)
  assert.equal(JSON.stringify(row).includes(response.body.signedTx as string), false)
})

test('the audit row and the signature commit together — an outbox event lands with it', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit()
  await signRequest(depositBinding(address, sweepTx(treasury)))
  const events = await sql`select topic, key from outbox where topic = 'custody.key.signed'`
  assert.equal(events.length, 1)
  assert.equal(events[0]!.key, address)
})

test('SD-09 §1: a deposit key attempting a TRANSFER to a stranger is refused and audited', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit()
  const stranger = ethers.Wallet.createRandom().address
  const response = await signRequest(depositBinding(address, sweepTx(stranger)))
  assert.equal(response.status, 403)
  assert.match(errorOf(response).message, /a sweep does not choose its own destination/)

  const rows = await sql`select outcome, gate from signing_audit where address = ${address}`
  assert.equal(rows.length, 1)
  assert.deepEqual({ outcome: rows[0]!.outcome, gate: rows[0]!.gate }, { outcome: 'refused', gate: 'shape' })
  void treasury
})

test('SD-09 §2: a mismatched binding on EACH of the five fields is refused', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit(ALICE, 'order-1')
  const good = depositBinding(address, sweepTx(treasury))

  const mutations: Array<[string, Record<string, unknown>]> = [
    ['address', { address: ethers.Wallet.createRandom().address }],
    ['chain', { chain: 'ember' }],
    ['network', { network: 'mainnet' }],
    ['userId', { userId: BOB }],
    ['orderId', { orderId: 'order-2' }],
  ]
  for (const [field, mutation] of mutations) {
    const response = await signRequest({ ...good, ...mutation })
    assert.equal(response.status === 403 || response.status === 404, true, `${field} produced ${response.status}`)
    const error = errorOf(response)
    // A wrong `address` is a different row (404); the other four are the binding refusing.
    if (response.status === 403) {
      assert.equal(error.code, 'binding_mismatch', field)
      // The message does NOT name the field that disagreed: the binding's entropy is in userId and
      // orderId, and a 403 that says which one was wrong is an oracle a caller walks one at a time.
      assert.equal(/userId|orderId|order-2/.test(error.message), false, field)
    }
  }
})

test('the userId comparison is real — the same address under another customer is refused', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit(ALICE)
  const response = await signRequest(depositBinding(address, sweepTx(treasury), { userId: BOB }))
  assert.equal(response.status, 403)
  assert.equal(errorOf(response).code, 'binding_mismatch')
})

test('SD-09 §3: an address minted under the GENERIC `evm` chain cannot be signed for', { skip }, async () => {
  const minted = await mint({ chain: 'evm', network: 'testnet', purpose: 'deployer', userId: ALICE, orderId: 'o1' })
  assert.equal(minted.status, 201, minted.text)
  const address = (minted.body.key as Record<string, unknown>).address as string
  const response = await signRequest({
    address,
    chain: 'evm',
    network: 'testnet',
    family: 'evm',
    purpose: 'deployer',
    userId: ALICE,
    orderId: 'o1',
    payload: { to: null, data: '0x60806040', value: 0, nonce: 0, gasLimit: 1_000_000, chainId: 1, gasPrice: '1000000000' },
  })
  assert.equal(response.status, 403)
  assert.match(errorOf(response).message, /valid on every EVM chain/)
  const rows = await sql`select gate from signing_audit where address = ${address}`
  assert.equal(rows[0]!.gate, 'chain_id')
})

test('SD-09 §4: a sweep on a chain with NO pinned treasury is refused before anything is decrypted', { skip }, async () => {
  const address = await mintDeposit()
  const response = await signRequest(depositBinding(address, sweepTx(ethers.Wallet.createRandom().address)))
  assert.equal(response.status, 403)
  assert.equal(errorOf(response).code, 'no_treasury_pinned')
  const rows = await sql`select gate from signing_audit where address = ${address}`
  assert.equal(rows[0]!.gate, 'treasury_pin')
})

test('a `user`-purpose key is refused before the row is even loaded — there is no such scope', { skip }, async () => {
  // `user` deliberately has no signing shape, so there is no `custody:sign:user` for anyone to hold.
  // The refusal therefore lands at the scope check, which runs on the CLAIMED purpose before the
  // address is looked up — so this route cannot be used to probe which addresses exist either.
  const minted = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'user', userId: ALICE, orderId: 'o1' })
  const address = (minted.body.key as Record<string, unknown>).address as string
  const response = await signRequest({
    address,
    chain: 'ethereum',
    network: 'testnet',
    family: 'evm',
    purpose: 'user',
    userId: ALICE,
    orderId: 'o1',
    payload: {},
  })
  assert.equal(response.status, 403)
  assert.match(errorOf(response).message, /custody:sign:user/)
})

test('the gate ORDER: a purpose refusal fires before the binding is even looked at', { skip }, async () => {
  // An EXPORTED key with a deliberately wrong binding on four fields. If the binding ran first the
  // audit row would say `binding`; SD-09 fixes purpose as gate 1, so it says `purpose`. This is also
  // SD-07 gate 9 enforced: the platform stops sweeping a key the customer now holds too.
  const address = await mintDeposit()
  await sql`update custody_keys set status = 'exported', exported_at = now() where address = ${address}`
  const response = await signRequest(
    depositBinding(address, sweepTx(ethers.ZeroAddress), { chain: 'ember', network: 'mainnet', userId: BOB, orderId: 'wrong' }),
  )
  assert.equal(response.status, 403)
  assert.equal(errorOf(response).code, 'purpose_forbidden')
  assert.match(errorOf(response).message, /'exported' and is no longer signed for/)
  const rows = await sql`select gate from signing_audit where address = ${address}`
  assert.equal(rows[0]!.gate, 'purpose')
})

test('a deposit address on a family with no sweep shape is refused', { skip }, async () => {
  for (const chain of ['solana', 'bitcoin']) {
    const minted = await mint({ chain, network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1' })
    assert.equal(minted.status, 201, minted.text)
    const address = (minted.body.key as Record<string, unknown>).address as string
    const response = await signRequest({
      address,
      chain,
      network: 'testnet',
      family: chain === 'solana' ? 'solana' : 'bitcoin',
      purpose: 'deposit',
      userId: ALICE,
      orderId: 'o1',
      payload: 'AAAA',
    })
    assert.equal(response.status, 403, chain)
    assert.match(errorOf(response).message, /have no sweep shape/)
  }
})

test('SD-05: a service is refused on a scope it should not hold', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit()
  // `settlement` holds custody:sign:deposit and may sweep.
  assert.equal((await signRequest(depositBinding(address, sweepTx(treasury)), 'settlement')).status, 200)
  // It does not hold custody:sign:treasury, so it cannot spend the treasury.
  const spend = await signRequest(
    {
      address: treasury,
      chain: 'ethereum',
      network: 'testnet',
      family: 'evm',
      purpose: 'treasury',
      userId: 'cloudsforge:treasury',
      orderId: 'treasury:ethereum:testnet',
      payload: sweepTx(ethers.Wallet.createRandom().address),
    },
    'settlement',
  )
  assert.equal(spend.status, 403)
  assert.match(errorOf(spend).message, /custody:sign:treasury/)
})

test('an unknown address is 404 and writes no audit row', { skip }, async () => {
  const response = await signRequest(depositBinding(ethers.Wallet.createRandom().address, sweepTx(ethers.ZeroAddress)))
  assert.equal(response.status, 404)
  const rows = await sql`select count(*)::int as n from signing_audit`
  assert.equal(rows[0]!.n, 0)
})

/* ------------------------------------------------------------------ rate limiting */

test('SD-09: /sign is rate limited, and REFUSALS count towards the limit', { skip }, async () => {
  // Counting refusals is the point: the caller a limit must bite hardest on is the one probing gates
  // in a loop, and that caller never produces a successful signature to be counted.
  const address = await mintDeposit()
  const body = depositBinding(address, sweepTx(ethers.Wallet.createRandom().address))
  for (let i = 0; i < 5; i += 1) {
    const response = await signRequest(body)
    assert.equal(response.status, 403, `attempt ${i} was ${response.status}`)
  }
  const limited = await signRequest(body)
  assert.equal(limited.status, 429)
  assert.equal(errorOf(limited).code, 'rate_limited')
  assert.equal(Number(limited.headers.get('retry-after')) > 0, true)

  // Per ACTOR, not per address: a different credential is unaffected, which is what makes the limit
  // bound a leaked token rather than a customer.
  assert.notEqual((await signRequest(body, 'settlement')).status, 429)
})

test('address creation is rate limited too', { skip }, async () => {
  for (let i = 0; i < 10; i += 1) {
    const response = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: `o${i}` })
    assert.equal(response.status, 201, response.text)
  }
  const limited = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o-last' })
  assert.equal(limited.status, 429)
})

/* ------------------------------------------------------------------ the treasury pin */

test('the pin may only name a treasury address this service minted on that chain and network', { skip }, async () => {
  const deposit = await mintDeposit()
  const wrong = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'operator',
    body: { address: deposit },
  })
  assert.equal(wrong.status, 400)
  assert.equal(errorOf(wrong).code, 'address_not_treasury')

  const unknown = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'operator',
    body: { address: ethers.Wallet.createRandom().address },
  })
  assert.equal(errorOf(unknown).code, 'address_unknown')
})

test('a treasury minted on the wrong network cannot be pinned to this one', { skip }, async () => {
  const minted = await server.request('/v1/admin/treasuries/ethereum/mainnet/mint', { method: 'POST', token: 'operator' })
  const address = (minted.body.key as Record<string, unknown>).address as string
  const pinned = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'operator',
    body: { address },
  })
  assert.equal(errorOf(pinned).code, 'address_wrong_network')
})

test('a repeat mint returns the outstanding candidate and creates nothing', { skip }, async () => {
  const first = await server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  assert.equal(first.status, 201)
  const second = await server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  assert.equal(second.status, 200)
  assert.equal(second.body.reused, true)
  assert.equal((second.body.key as Record<string, unknown>).address, (first.body.key as Record<string, unknown>).address)
  const rows = await sql`select count(*)::int as n from custody_keys where purpose = 'treasury'`
  assert.equal(rows[0]!.n, 1)
})

test('a mint does NOT pin — rotation stays three deliberate steps', { skip }, async () => {
  await server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  const pins = await server.request('/v1/admin/treasuries', { token: 'operator' })
  assert.deepEqual(pins.body.treasuries, [])
})

test('a rotation names the superseded address so its balance is not silently stranded', { skip }, async () => {
  const first = await mintAndPinTreasury()
  const minted = await server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  const second = (minted.body.key as Record<string, unknown>).address as string
  const rotated = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'operator',
    body: { address: second },
  })
  assert.equal(rotated.status, 200)
  assert.equal(rotated.body.supersededAddress, first)
  // The superseded row is deliberately untouched, so its balance stays spendable.
  const rows = await sql`select purpose, status from custody_keys where address = ${first}`
  assert.deepEqual({ ...rows[0] }, { purpose: 'treasury', status: 'active' })
})

test('there is no write route for the pin on the signing surface', { skip }, async () => {
  // If a signing credential could write the pin, the sweep shape would be a total-loss
  // vulnerability rather than a containment.
  for (const method of ['PUT', 'POST']) {
    assert.equal((await server.request('/v1/treasuries/ethereum/testnet', { method, token: 'wallet' })).status, 404)
  }
  const asService = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'wallet',
    body: { address: ethers.ZeroAddress },
  })
  assert.equal(asService.status, 403)
})

test('the pin is readable by a scoped service and publishes only the address', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const response = await server.request('/v1/treasuries/ethereum/testnet', { token: 'wallet' })
  assert.equal(response.status, 200)
  assert.deepEqual(response.body, { chain: 'ethereum', network: 'testnet', address: treasury })
})

/* ------------------------------------------------------------------ the operator surface */

test('the admin key list needs the admin role, and a service token cannot reach it', { skip }, async () => {
  await mintDeposit()
  assert.equal((await server.request('/v1/admin/keys', { token: 'operator' })).status, 200)
  assert.equal((await server.request('/v1/admin/keys', { token: 'wallet' })).status, 403)
  assert.equal((await server.request('/v1/admin/keys', { token: 'alice' })).status, 403)
})

test('the operator surface serves the signing history in place of the deleted reveal', { skip }, async () => {
  const treasury = await mintAndPinTreasury()
  const address = await mintDeposit()
  await signRequest(depositBinding(address, sweepTx(treasury)))
  const response = await server.request(`/v1/admin/keys/${address}/audit`, { token: 'operator' })
  assert.equal(response.status, 200)
  const audit = response.body.audit as Record<string, unknown>[]
  assert.equal(audit.length, 1)
  assert.equal(audit[0]!.outcome, 'signed')
})

test('the rotation view reports the write version and the backlog', { skip }, async () => {
  const response = await server.request('/v1/admin/rotation', { token: 'operator' })
  assert.equal(response.status, 200)
  assert.equal(response.body.writeVersion, 2)
  assert.deepEqual(response.body.readableVersions, [1, 2])
  assert.equal(response.body.remaining, 0)
})
