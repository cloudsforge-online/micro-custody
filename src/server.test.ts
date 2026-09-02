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
import * as bitcoin from 'bitcoinjs-lib'
import { PublicKey, SystemProgram, Transaction as SolanaTransaction } from '@solana/web3.js'
import type postgres from 'postgres'
import { ADDRESS_CREATE_SCOPE, TREASURY_READ_SCOPE } from './server.ts'
import { chainOutsideEveryRegistry } from './chains.ts'
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

/** Any value: these suites never post a signed event, they only satisfy `ServerDeps`. */
const EVENT_SECRET = 'test-event-signing-secret'

const SIGN_SCOPES = ['custody:sign:deposit', 'custody:sign:treasury', 'custody:sign:deployer']
/**
 * A chain custody holds no keys for, derived from the registry rather than named. See
 * `chainOutsideEveryRegistry` in chains.ts for why a named one kept going stale (micro-org#290).
 */
const UNKNOWN_CHAIN = chainOutsideEveryRegistry()

const TOKENS = {
  wallet: serviceToken('wallet', [ADDRESS_CREATE_SCOPE, TREASURY_READ_SCOPE, ...SIGN_SCOPES]),
  // Deliberately narrow: SD-05's "a test per service asserting it is refused on a scope it should
  // not hold". `settlement` may sweep deposits and may not touch the treasury.
  settlement: serviceToken('settlement', ['custody:sign:deposit', TREASURY_READ_SCOPE]),
  unscoped: serviceToken('marketing', ['pricing:read']),
  /*
   * A credential holding a scope NOTHING IN THE ESTATE CAN MINT.
   *
   * `custody:sign:pool` is in `scope-exemptions.json` as demandable-but-unregistered: /v1/sign
   * synthesises the name from the purpose set, identity has no way to issue it, and every real
   * caller is therefore refused at the scope check before a row is loaded — which is what the
   * `pool` sign test above asserts. That refusal is real and it is also the SHALLOWER of the two
   * walls, so on its own it hides the deeper one. Forging the scope here walks past it and reaches
   * gate 1, so the suite states what happens if the scope registry ever changes its mind:
   * `SIGNABLE_PURPOSES` still does not contain 'pool' and `purposeGate` still refuses.
   */
  poolsigner: serviceToken('pool', ['custody:sign:pool']),
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

test('a `pool` payout address is mintable on the chains the pool mines, and is HD', { skip }, async () => {
  // What micro-pool needs and all it needs: an address to put in `POOL_<CHAIN>_PAYOUT_ADDRESS`
  // whose private key custody holds, so a found block's coinbase — the pool's revenue and the
  // miners' claim on it, 36 §5.3 — is not sitting under a key on the pool host.
  //
  // Driven on litecoin and bitcoin because those are the two chains micro-pool builds templates
  // for, and litecoin is the one that makes the purpose necessary: settlement pins an LTC treasury,
  // so a payout address minted as `treasury` here would be a rotation candidate for it.
  for (const chain of ['litecoin', 'bitcoin']) {
    const response = await mint({
      chain,
      network: 'mainnet',
      purpose: 'pool',
      userId: 'cloudsforge:pool',
      orderId: `pool:${chain}:mainnet`,
    })
    assert.equal(response.status, 201, response.text)
    const key = response.body.key as Record<string, unknown>
    assert.equal(key.purpose, 'pool')
    assert.equal(key.family, 'bitcoin')
    assert.equal(key.scheme, 'hd_bip44')
    assert.equal('privateKey' in key, false)
  }
  // The coin types are the chains' own — LTC 2, BTC 0 — and NOT the family's, which is Bitcoin's 0
  // for both. Purpose is absent from the path entirely: the account level stays `0'`, and the two
  // addresses are separated by the COIN TYPE alone. Both are index 0 because each path carries its
  // own counter since migration 9; before it they were 1 and 0, and the difference in index masked
  // the fact that the coin type was doing the work.
  const paths = await sql<{ chain: string; derivation_path: string }[]>`
    select chain, derivation_path from custody_keys where purpose = 'pool' order by chain
  `
  assert.deepEqual(
    paths.map((row) => [row.chain, row.derivation_path]),
    [
      ['bitcoin', "m/44'/0'/0'/0/0"],
      ['litecoin', "m/44'/2'/0'/0/0"],
    ],
  )
})

test('a `pool` address is never signed for, and no `custody:sign:pool` scope exists to ask with', { skip }, async () => {
  // The other half of the purpose. Custody holds the key so the coin is not stranded under a key on
  // the pool host; it does not sign payouts, because a payout names N miner destinations for amounts
  // custody cannot see — no field is left for the vault to choose, which is the same answer `user`
  // gets. 36 §5.3 pays miners by CREDITING THE LEDGER, so nothing is blocked by this refusal.
  const minted = await mint({
    chain: 'litecoin',
    network: 'mainnet',
    purpose: 'pool',
    userId: 'cloudsforge:pool',
    orderId: 'pool:litecoin:mainnet',
  })
  assert.equal(minted.status, 201, minted.text)
  const address = (minted.body.key as Record<string, unknown>).address as string

  // Refused at the SCOPE check, on the claimed purpose, before the row is loaded — so the route
  // cannot be used to probe which addresses exist either. `wallet` holds every signing scope the
  // estate issues and still cannot reach this one.
  const response = await signRequest({
    address,
    chain: 'litecoin',
    network: 'mainnet',
    family: 'bitcoin',
    purpose: 'pool',
    userId: 'cloudsforge:pool',
    orderId: 'pool:litecoin:mainnet',
    payload: {},
  })
  assert.equal(response.status, 403)
  assert.match(errorOf(response).message, /custody:sign:pool/)
  const audit = await sql`select id from signing_audit where address = ${address}`
  assert.equal(audit.length, 0, 'a scope refusal never reaches the row, so it writes no audit')
})

test('a `pool` address cannot be pinned as the treasury, through the route an operator actually has', { skip }, async () => {
  // The schema half is in `migrations.test.ts`. This is the operator-facing half: the only write
  // route to the pin is this one, it forwards an operator's own token, and it refuses a `pool`
  // address by purpose before anything else. Were it not to, every LTC sweep in the estate would
  // pay an address whose balance is the miners' claim on the pool's revenue.
  const minted = await mint({
    chain: 'litecoin',
    network: 'mainnet',
    purpose: 'pool',
    userId: 'cloudsforge:pool',
    orderId: 'pool:litecoin:mainnet',
  })
  assert.equal(minted.status, 201, minted.text)
  const address = (minted.body.key as Record<string, unknown>).address as string

  const pinned = await server.request('/v1/admin/treasuries/litecoin/mainnet', {
    method: 'PUT',
    token: 'operator',
    body: { address },
  })
  assert.equal(pinned.status, 400, pinned.text)
  assert.equal(errorOf(pinned).code, 'address_not_treasury')
  assert.match(errorOf(pinned).message, /not purpose 'treasury'/)
  const rows = await sql`select address from custody_treasuries`
  assert.equal(rows.length, 0)
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
  // `dogecoin` used to stand in here and stopped being unknown when DOGE was added, at which point
  // this test would still have passed while asserting nothing about an unknown chain. `bitcoincash`
  // replaced it and carried the same fuse. It is DERIVED from the registry now (micro-org#290), so
  // the chain it names cannot become known behind this assertion's back.
  const response = await mint({ chain: UNKNOWN_CHAIN, network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'o1' })
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
  // No such family exists today — every one custody holds keys for now has a built sweep shape. The
  // gate is kept as an ALLOWLIST for the family that does not exist yet, and this is the end-to-end
  // half of `gates.test.ts`'s assertion of the same thing: the refusal is reached through the real
  // route, with the real audit row, and it happens before anything is decrypted.
  const address = await mintDeposit()
  await sql`update custody_keys set family = 'aptos' where address = ${address}`
  const response = await signRequest(depositBinding(address, sweepTx(address), { family: 'aptos' }))
  assert.equal(response.status, 403)
  assert.match(errorOf(response).message, /have no sweep shape/)
  const rows = await sql`select gate from signing_audit where address = ${address}`
  assert.equal(rows[0]!.gate, 'purpose')
})

/* --------------------------------- BTC and SOL sweeps, end to end (§5 item 3) */

/** A PSBT spending `from`'s only output, paying each of `to`. Values are nominal; nothing broadcasts. */
function sweepPsbt(from: string, to: readonly string[]): string {
  const net = bitcoin.networks.testnet
  const psbt = new bitcoin.Psbt({ network: net })
  psbt.addInput({
    hash: Buffer.alloc(32, 7),
    index: 0,
    witnessUtxo: { script: bitcoin.address.toOutputScript(from, net), value: 100_000 },
    sighashType: bitcoin.Transaction.SIGHASH_ALL,
  })
  for (const address of to) psbt.addOutput({ address, value: Math.floor(90_000 / to.length) })
  return psbt.toBase64()
}

/** One System Transfer out of `from`. The blockhash is a placeholder — this is never submitted. */
function solSweepTx(from: string, to: string): string {
  const payer = new PublicKey(from)
  const tx = new SolanaTransaction({ feePayer: payer, recentBlockhash: 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi' })
  tx.add(SystemProgram.transfer({ fromPubkey: payer, toPubkey: new PublicKey(to), lamports: 90_000 }))
  return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64')
}

/**
 * A DISTINCT deposit address on `chain`, every call.
 *
 * The counter is not decoration. This used to pass a fixed `orderId: 'order-1'`, and two calls in
 * one case then relied on custody minting a second address for a binding it had already minted —
 * which it did, because it had no idempotency at all. Migration 6 makes that a replay, so a fixture
 * that wants a SECOND address now has to ask for one the way wallet does: a new assignment id per
 * address (`wallet/src/deposits.ts`). The cases below need a stranger address to prove a sweep
 * cannot pay it, and a stranger that is the same address proves nothing.
 */
let depositOrdinal = 0
async function mintDepositOn(chain: string): Promise<{ address: string; orderId: string }> {
  depositOrdinal += 1
  const orderId = `order-${depositOrdinal}`
  const minted = await mint({ chain, network: 'testnet', purpose: 'deposit', userId: ALICE, orderId })
  assert.equal(minted.status, 201, minted.text)
  // The orderId comes BACK, because it is half of what a signature is bound to and the caller now
  // has to restate it — exactly as settlement does for a real sweep.
  return { address: (minted.body.key as Record<string, unknown>).address as string, orderId }
}

test('§5 item 3: a BTC deposit sweeps to the PIN, and to nothing else', { skip }, async () => {
  const treasury = await mintAndPinTreasury('bitcoin', 'testnet')
  const { address, orderId } = await mintDepositOn('bitcoin')
  const binding = (payload: unknown) =>
    depositBinding(address, payload, { chain: 'bitcoin', family: 'bitcoin', orderId })

  const signed = await signRequest(binding(sweepPsbt(address, [treasury])))
  assert.equal(signed.status, 200, signed.text)
  // A finalised raw transaction, and its one output pays the treasury this service pinned.
  const tx = bitcoin.Transaction.fromHex(signed.body.signedTx as string)
  assert.equal(tx.outs.length, 1)
  assert.equal(
    bitcoin.address.fromOutputScript(tx.outs[0]!.script, bitcoin.networks.testnet),
    treasury,
  )

  // THE NEGATIVE, which is the one that matters. Same address, same key, same route — a destination
  // the caller chose instead of the one the vault did.
  const stranger = await mintDepositOn('bitcoin')
  const refused = await signRequest(binding(sweepPsbt(address, [stranger.address])))
  assert.equal(refused.status, 403, refused.text)
  assert.match(errorOf(refused).message, /every output of a sweep pays the pin/)
})

test('§5 item 3: a BTC sweep may not keep CHANGE, even paying the pin with the rest', { skip }, async () => {
  // The specific hole the output policy exists for: `signAllInputs` signs the whole transaction, so
  // a change output beside a pin-paying one is signed by the same signature and cannot be separated
  // from it. A sweep leaves nothing behind.
  const treasury = await mintAndPinTreasury('bitcoin', 'testnet')
  const { address, orderId } = await mintDepositOn('bitcoin')
  const response = await signRequest(
    depositBinding(address, sweepPsbt(address, [treasury, address]), {
      chain: 'bitcoin',
      family: 'bitcoin',
      orderId,
    }),
  )
  assert.equal(response.status, 403, response.text)
  assert.match(errorOf(response).message, /change included/)
})

test('§5 item 3: a SOL deposit sweeps to the PIN, and to nothing else', { skip }, async () => {
  const treasury = await mintAndPinTreasury('solana', 'testnet')
  const { address, orderId } = await mintDepositOn('solana')
  const binding = (payload: unknown) =>
    depositBinding(address, payload, { chain: 'solana', family: 'solana', orderId })

  const signed = await signRequest(binding(solSweepTx(address, treasury)))
  assert.equal(signed.status, 200, signed.text)
  const parsed = SolanaTransaction.from(Buffer.from(signed.body.signedTx as string, 'base64'))
  assert.equal(parsed.feePayer?.toBase58(), address)
  assert.equal(parsed.instructions.length, 1)

  const stranger = await mintDepositOn('solana')
  const refused = await signRequest(binding(solSweepTx(address, stranger.address)))
  assert.equal(refused.status, 403, refused.text)
  assert.match(errorOf(refused).message, /a sweep does not choose its own destination/)
})

test('§5 item 3: a BTC or SOL deposit on an UNPINNED chain signs nothing at all', { skip }, async () => {
  // Gate 4, before gate 5. An unconfigured chain is not "sweep to anywhere", it is a named refusal
  // reached with no private key in this process at all.
  for (const chain of ['bitcoin', 'solana']) {
    const { address, orderId } = await mintDepositOn(chain)
    const payload = chain === 'bitcoin' ? sweepPsbt(address, [address]) : solSweepTx(address, address)
    const response = await signRequest(depositBinding(address, payload, { chain, family: chain, orderId }))
    assert.equal(response.status, 403, chain)
    assert.equal(errorOf(response).code, 'no_treasury_pinned')
    const rows = await sql`select gate from signing_audit where address = ${address}`
    assert.equal(rows[0]!.gate, 'treasury_pin', chain)
  }
})

test('§5 item 3: a SOL DEPOSIT key still cannot createAccount — the mint set is the deployer shape', { skip }, async () => {
  // The hazard `SWEEPABLE_FAMILIES` was standing in for, asserted where it now lives. `createAccount`
  // can park 50,000,000 lamports in an account nothing in this estate can recover, and admitting
  // `deposit` to the signer without a shape would have handed that to any holder of
  // `custody:sign:deposit` over every customer's SOL key.
  await mintAndPinTreasury('solana', 'testnet')
  const { address, orderId } = await mintDepositOn('solana')
  const payer = new PublicKey(address)
  const tx = new SolanaTransaction({ feePayer: payer, recentBlockhash: 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi' })
  tx.add(
    SystemProgram.createAccount({
      fromPubkey: payer,
      newAccountPubkey: new PublicKey((await mintDepositOn('solana')).address),
      lamports: 50_000_000,
      space: 82,
      programId: new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),
    }),
  )
  const payload = tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64')
  const response = await signRequest(
    depositBinding(address, payload, { chain: 'solana', family: 'solana', orderId }),
  )
  assert.equal(response.status, 403, response.text)
  assert.match(errorOf(response).message, /only system-program instruction a solana transfer signs is Transfer/)
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

/* ------------------------------------ micro-org#250: purpose 'treasury' is not "the treasury" */

/**
 * Another service's platform-owned address, minted the way `foresight` and the `faucet` actually
 * mint theirs on the live estate: `purpose: 'treasury'`, its own binding, the ordinary address
 * route. It is a legitimate address and the mint below must keep succeeding — what it must never
 * become is the address deposits sweep into.
 */
async function mintForeignTreasury(userId = ALICE, orderId = 'foresight-house-seed') {
  const response = await mint({ chain: 'ethereum', network: 'testnet', purpose: 'treasury', userId, orderId })
  assert.equal(response.status, 201, response.text)
  return (response.body.key as Record<string, unknown>).address as string
}

test('another service\'s treasury-purpose address is NOT handed back as the rotation candidate', { skip }, async () => {
  // The measured failure: on the live testnet stack the only two `purpose: 'treasury'` keys on
  // ember/testnet belonged to foresight and the faucet, nothing was pinned, and the mint route
  // answered 200 `reused: true` with foresight's house seed. Every user deposit would have swept
  // into it.
  const foreign = await mintForeignTreasury()
  const minted = await server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  assert.equal(minted.status, 201, 'the platform treasury is CREATED, not reused from a stranger')
  assert.equal(minted.body.reused, false)
  const address = (minted.body.key as Record<string, unknown>).address as string
  assert.notEqual(address, foreign)
  // And it carries the derived binding, which is the thing that made it selectable.
  const rows = await sql<{ user_id: string; order_id: string }[]>`
    select user_id, order_id from custody_keys where address = ${address}
  `
  assert.deepEqual({ ...rows[0] }, { user_id: 'cloudsforge:treasury', order_id: 'treasury:ethereum:testnet' })
})

test('another service\'s treasury-purpose address cannot be pinned, whoever asks', { skip }, async () => {
  // The query above decides what a REPEAT MINT hands back. This is the wall: an operator can name
  // any address here, and settlement's provision route forwards an operator's token verbatim.
  const foreign = await mintForeignTreasury()
  const pinned = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'operator',
    body: { address: foreign },
  })
  assert.equal(pinned.status, 400)
  assert.equal(errorOf(pinned).code, 'address_not_platform_treasury')
  const pins = await server.request('/v1/admin/treasuries', { token: 'operator' })
  assert.deepEqual(pins.body.treasuries, [])
})

test('a rotation candidate is still reused, and a rotation still rotates, with a stranger present', { skip }, async () => {
  // The binding filter must not narrow the set so far that a treasury has nowhere to rotate to —
  // the failure `keys.ts` warns about at BINDING_NAMES_ONE_ADDRESS. Both properties, with a
  // foreign treasury-purpose address sitting in the same (chain, network) throughout.
  await mintForeignTreasury(BOB, 'faucet-funding')
  const first = await mintAndPinTreasury()
  const candidate = await server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  assert.equal(candidate.status, 201)
  const second = (candidate.body.key as Record<string, unknown>).address as string
  assert.notEqual(second, first, 'a pinned treasury must have somewhere to rotate TO')
  const again = await server.request('/v1/admin/treasuries/ethereum/testnet/mint', { method: 'POST', token: 'operator' })
  assert.equal(again.body.reused, true)
  assert.equal((again.body.key as Record<string, unknown>).address, second)
  const rotated = await server.request('/v1/admin/treasuries/ethereum/testnet', {
    method: 'PUT',
    token: 'operator',
    body: { address: second },
  })
  assert.equal(rotated.status, 200, rotated.text)
  assert.equal(rotated.body.supersededAddress, first)
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

/* --------------------------- the pool payout address, micro-org#293 */

/**
 * The route that exists because no principal in the estate could mint a `pool` address.
 *
 * `POST /v1/addresses` is the only route that mints a purpose the caller names and its gate is
 * `requireScope`, which `hasScope` refuses for every non-service principal — so an operator could
 * never reach it. Nor could a service reach it honestly for THIS purpose: micro-pool never calls
 * custody, so it holds no grant, and minting through wallet's credential writes `service:wallet`
 * into `created_by` for the address every block reward on the platform pays into.
 */
const POOL_MINT = '/v1/admin/pool-payouts/litecoin/mainnet/mint'

async function mintPoolPayout(path = POOL_MINT, token = 'operator') {
  return server.request(path, { method: 'POST', token })
}

test('the pool payout mint is admin-only — a user token and a SCOPED service token are both refused', { skip }, async () => {
  // The second assertion is the one that carries weight. `wallet` holds `custody:address:create`,
  // which is the authority that mints every other address in this service, and it is REFUSED here —
  // which is how the suite states that this route did not quietly become a second entrance to the
  // signing surface's gate. Were it to have, the `created_by` column this route exists to keep
  // honest would be back to naming a service that has never heard of the pool.
  assert.equal((await mintPoolPayout(POOL_MINT, 'alice')).status, 403)
  assert.equal((await mintPoolPayout(POOL_MINT, 'wallet')).status, 403)
  assert.equal((await mintPoolPayout(POOL_MINT, 'unscoped')).status, 403)
  const rows = await sql`select count(*)::int as n from custody_keys where purpose = 'pool'`
  assert.equal(rows[0]!.n, 0, 'a refused mint creates nothing')
})

test('the pool payout mint refuses an unknown chain and a bad network, with the treasury route\'s codes', { skip }, async () => {
  // The same derived fixture the provisioning test above uses, so the two cannot drift apart and
  // neither can quietly stop naming an unknown chain.
  const unknown = await mintPoolPayout(`/v1/admin/pool-payouts/${UNKNOWN_CHAIN}/mainnet/mint`)
  assert.equal(unknown.status, 400)
  assert.equal(errorOf(unknown).code, 'unknown_chain')

  const network = await mintPoolPayout('/v1/admin/pool-payouts/litecoin/regtest/mint')
  assert.equal(network.status, 400)
  assert.equal(errorOf(network).code, 'bad_request')
  assert.match(errorOf(network).message, /mainnet or testnet/)
})

test('a repeat pool payout mint returns the SAME address and creates nothing', { skip }, async () => {
  // Migration 8 refused `unique (chain, network) where purpose = 'pool'` deliberately, so nothing in
  // the schema enforces this: the idempotency is the route's derived binding and this is the test
  // that says it works. Two calls a minute apart are the same request.
  const first = await mintPoolPayout()
  assert.equal(first.status, 201, first.text)
  assert.equal(first.body.reused, false)
  const second = await mintPoolPayout()
  assert.equal(second.status, 200, second.text)
  assert.equal(second.body.reused, true)
  assert.equal((second.body.key as Record<string, unknown>).address, (first.body.key as Record<string, unknown>).address)

  const rows = await sql`select count(*)::int as n from custody_keys where purpose = 'pool'`
  assert.equal(rows[0]!.n, 1)
})

test('the minted row is purpose `pool`, flat random, and is NOT in custody_treasuries', { skip }, async () => {
  const minted = await mintPoolPayout()
  assert.equal(minted.status, 201, minted.text)
  const key = minted.body.key as Record<string, unknown>
  assert.equal(key.purpose, 'pool')
  // A pool payout address belongs to the platform: there is no per-user seed to derive it from and
  // no recovery phrase to offer anybody, which is the argument the treasury mint already makes.
  assert.equal(key.scheme, 'flat_random')
  assert.equal(key.derivationPath, null)
  assert.equal('privateKey' in key, false)
  // The operator projection, so an operator can see the binding the route derived. It is a SEPARATE
  // binding from the treasury's, which is the point: `boundAsTreasury` compares against
  // `treasuryBinding` and a colliding string would be one purpose check away from pinnable.
  assert.equal(key.userId, 'cloudsforge:pool')
  assert.equal(key.orderId, 'pool:litecoin:mainnet')
  assert.notEqual(key.orderId, 'treasury:litecoin:mainnet')

  // Migration 8's load-bearing sentence: a `pool` row must never appear in this table. The route
  // pins nothing and the response says so.
  assert.equal(minted.body.configured, false)
  const pins = await sql`select address from custody_treasuries`
  assert.equal(pins.length, 0)
  const treasuries = await server.request('/v1/admin/treasuries', { token: 'operator' })
  assert.deepEqual(treasuries.body.treasuries, [])
})

test('a minted pool payout address is refused at GATE 1 even by a forged custody:sign:pool', { skip }, async () => {
  // The scope refusal is asserted above with `wallet`. This is the wall behind it: with the
  // unmintable scope forged into the token, /v1/sign reaches `purposeGate`, `SIGNABLE_PURPOSES` is
  // {deployer, treasury, deposit}, and the refusal is audited as gate `purpose` — before a key is
  // decrypted. The coinbase is paid TO this address by the chain; spending from it is a decision
  // nobody has made, and this route creating the address does not make it.
  const minted = await mintPoolPayout()
  const address = (minted.body.key as Record<string, unknown>).address as string
  const response = await signRequest(
    {
      address,
      chain: 'litecoin',
      network: 'mainnet',
      family: 'bitcoin',
      purpose: 'pool',
      userId: 'cloudsforge:pool',
      orderId: 'pool:litecoin:mainnet',
      payload: {},
    },
    'poolsigner',
  )
  assert.equal(response.status, 403, response.text)
  assert.match(errorOf(response).message, /purpose this service does not sign for/)
  const rows = await sql`select gate from signing_audit where address = ${address}`
  assert.equal(rows[0]!.gate, 'purpose')
})

test('rotation stays reachable — retiring the live payout address makes the next mint a 201', { skip }, async () => {
  // The property migration 8 refused the unique index to preserve, asserted rather than argued. A
  // pool payout key accumulates every block the pool ever finds, so it is exactly the key an
  // operator must be able to abandon and replace; under `unique (chain, network) where purpose =
  // 'pool'` the replacement mint would be a 23505 no operator can act on.
  const first = await mintPoolPayout()
  const original = (first.body.key as Record<string, unknown>).address as string
  await sql`update custody_keys set status = 'retired' where address = ${original}`

  const replacement = await mintPoolPayout()
  assert.equal(replacement.status, 201, replacement.text)
  assert.equal(replacement.body.reused, false)
  assert.notEqual((replacement.body.key as Record<string, unknown>).address, original)
  // And the abandoned row is left alone, so the coin sitting at it still has a row saying who holds
  // the key to it.
  const rows = await sql`select status from custody_keys where address = ${original}`
  assert.equal(rows[0]!.status, 'retired')
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
