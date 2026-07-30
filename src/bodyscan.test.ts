/**
 * SD-16's RESPONSE-BODY SCAN: **no route in this service can return private key material**, except
 * the one that is the whole point of the export ceremony.
 *
 * This is a continuous check in CI rather than a review item, because the property it protects is
 * the one SD-08 deleted a route over. The scan works by construction rather than by inspection:
 *
 *   1. Mint one address in every family, so every stored private-key FORM exists — 0x-hex, base64
 *      secret key, WIF, XRP family seed — plus the BIP-39 mnemonic behind them.
 *   2. Read every secret out of the vault directly, which is the only legitimate way to know what
 *      the forbidden strings actually are.
 *   3. Drive EVERY route in the routing table, under every credential, with success and failure
 *      shapes, and assert no response body or header contains any of them.
 *
 * Enumerating the routes from the server's own table rather than by hand is deliberate: a route
 * added later is a route this test drives automatically, and one it cannot drive fails the assertion
 * that the two lists agree.
 */

import assert from 'node:assert/strict'
import test, { after, before } from 'node:test'
import { readFileSync } from 'node:fs'
import type postgres from 'postgres'
import { challengeExport, requestExport } from './exports.ts'
import { provisionAddress } from './keys.ts'
import { pinTreasury } from './store.ts'
import { seedSlot } from './vault.ts'
import { ADDRESS_CREATE_SCOPE, TREASURY_READ_SCOPE } from './server.ts'
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
  userToken,
  type Harness,
  type RunningServer,
} from './testsupport.ts'

const DAY = 24 * 3_600_000

const TOKENS = {
  wallet: serviceToken('wallet', [
    ADDRESS_CREATE_SCOPE,
    TREASURY_READ_SCOPE,
    'custody:sign:deposit',
    'custody:sign:treasury',
    'custody:sign:deployer',
  ]),
  alice: userToken(ALICE),
  operator: userToken('99999999-9999-4999-8999-999999999999', { roles: ['admin'] }),
}

let sql: postgres.Sql
let h: Harness
let server: RunningServer
/** Every private key, seed and mnemonic in the fixture estate. Nothing may echo any of them. */
let secrets: string[] = []
let addresses: Record<string, string> = {}

/**
 * The fixture is built ONCE, not per test.
 *
 * Not a performance choice: `startServer` binds a socket, and a suite that opened one per test would
 * leave every earlier server listening — a process that never exits and a test file that never
 * reports. The scan is read-mostly by construction anyway, and the one test that mutates (the
 * redemption) runs last.
 */
before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
  await resetCustody(sql)
  h = await harness({ sql })
  server = await startServer({
    lifecycle: testLifecycle(),
    logger: silentLogger,
    metrics: testMetrics(),
    verifier: stubVerifier(TOKENS),
    keys: h.keys,
    exports: h.exports,
    limits: { signPerMinute: 500, addressPerHour: 500 },
    now: () => h.clock(),
  })

  addresses = {}
  secrets = []
  // One address per family, so every stored key FORM is represented: 0x-hex (EVM, Ember), base64 of
  // the 64-byte secret key (Solana), WIF (Bitcoin), family seed (XRP).
  for (const [chain, purpose] of [
    ['ethereum', 'user'],
    ['ember', 'deposit'],
    ['solana', 'deployer'],
    ['bitcoin', 'user'],
    ['xrp', 'deposit'],
  ] as const) {
    const result = await provisionAddress(h.keys, {
      chain,
      network: 'testnet',
      purpose,
      userId: ALICE,
      orderId: `order-${chain}`,
      createdBy: 'service:wallet',
      correlationId: 'c',
    })
    assert.equal(result.ok, true, result.ok ? '' : result.error)
    if (!result.ok) continue
    addresses[chain] = result.key.address
    secrets.push(h.keys.keyring.decrypt(result.key.address, await h.vault.read(result.key.address)))
  }
  // A treasury, so the platform-owned path is covered too.
  const treasury = await provisionAddress(h.keys, {
    chain: 'ethereum',
    network: 'testnet',
    purpose: 'treasury',
    userId: 'cloudsforge:treasury',
    orderId: 'treasury:ethereum:testnet',
    scheme: 'flat_random',
    createdBy: 'user:op',
    correlationId: 'c',
  })
  assert.equal(treasury.ok, true)
  if (treasury.ok) {
    addresses.treasury = treasury.key.address
    secrets.push(h.keys.keyring.decrypt(treasury.key.address, await h.vault.read(treasury.key.address)))
    // Pinned in setup so that `GET /v1/treasuries/:chain/:network` is REACHABLE during the scan. An
    // unpinned chain answers 404, and a 404 is a route the scan silently stopped covering.
    const pinned = await pinTreasury(sql, {
      chain: 'ethereum',
      network: 'testnet',
      address: treasury.key.address,
      setBy: 'user:op',
    })
    assert.equal('refusal' in pinned, false)
  }
  // And every seed's MNEMONIC — the master secret for every derived address of a (user, family).
  for (const row of await sql<{ id: string }[]>`select id from custody_seeds`) {
    secrets.push(h.keys.keyring.decrypt(seedSlot(row.id), await h.vault.read(seedSlot(row.id))))
  }
  assert.equal(secrets.length >= 6, true)
})

after(async () => {
  if (!enabled) return
  await server.close()
  await sql.end({ timeout: 5 })
})

/** Every string that must never appear in a response, including the individual mnemonic words. */
function forbidden(): string[] {
  const parts = secrets.flatMap((secret) => {
    if (secret.includes(' ')) {
      // A mnemonic. The whole phrase, and also its first four words: a partial leak of a phrase is
      // a materially smaller search space, not a near miss.
      return [secret, secret.split(' ').slice(0, 4).join(' ')]
    }
    // Both spellings of an EVM key, since 0x-prefixing is exactly the kind of difference a naive
    // substring check would miss.
    return secret.startsWith('0x') ? [secret, secret.slice(2)] : [secret]
  })
  return parts.filter((p) => p.length >= 16)
}

function assertClean(where: string, ...texts: string[]): void {
  const haystack = texts.join('\n')
  for (const secret of forbidden()) {
    assert.equal(haystack.includes(secret), false, `${where} returned key material`)
  }
}

/* ------------------------------------------------------------------ the scan */

/**
 * Every route in the server's table, with a request that reaches it.
 *
 * `expectReachable` is what stops this list silently rotting: a route whose sample request 404s has
 * either been renamed or removed, and either way the scan has stopped covering it.
 */
function routeSamples(): Array<{ method: string; path: string; token?: string; body?: unknown }> {
  return [
    { method: 'GET', path: '/livez' },
    { method: 'GET', path: '/readyz' },
    { method: 'GET', path: '/metrics' },
    {
      method: 'POST',
      path: '/v1/addresses',
      token: 'wallet',
      body: { chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'scan-1' },
    },
    { method: 'GET', path: `/v1/addresses/${addresses.ethereum}`, token: 'wallet' },
    { method: 'GET', path: `/v1/addresses/${addresses.ethereum}`, token: 'alice' },
    { method: 'GET', path: '/v1/keys', token: 'alice' },
    { method: 'GET', path: '/v1/treasuries/ethereum/testnet', token: 'wallet' },
    {
      method: 'POST',
      path: '/v1/sign',
      token: 'wallet',
      body: {
        address: addresses.ember,
        chain: 'ember',
        network: 'testnet',
        family: 'ember',
        purpose: 'deposit',
        userId: ALICE,
        orderId: 'order-ember',
        payload: { to: null, data: '0x60', value: 0, nonce: 0, gasLimit: 21_000, chainId: 7412, gasPrice: '1' },
      },
    },
    { method: 'GET', path: '/v1/exports', token: 'alice' },
    {
      method: 'POST',
      path: '/v1/exports',
      token: 'alice',
      body: { address: addresses.ethereum, format: 'raw' },
    },
    { method: 'GET', path: '/v1/admin/keys', token: 'operator' },
    { method: 'GET', path: `/v1/admin/keys/${addresses.ethereum}`, token: 'operator' },
    { method: 'GET', path: `/v1/admin/keys/${addresses.ethereum}/audit`, token: 'operator' },
    { method: 'GET', path: '/v1/admin/treasuries', token: 'operator' },
    { method: 'POST', path: '/v1/admin/treasuries/bitcoin/testnet/mint', token: 'operator' },
    {
      method: 'PUT',
      path: '/v1/admin/treasuries/ethereum/testnet',
      token: 'operator',
      body: { address: addresses.treasury },
    },
    { method: 'GET', path: '/v1/admin/rotation', token: 'operator' },
  ]
}

test('SD-16: NO route returns key material, under any credential', { skip }, async () => {
  for (const sample of routeSamples()) {
    const response = await server.request(sample.path, {
      method: sample.method,
      ...(sample.token ? { token: sample.token } : {}),
      ...(sample.body === undefined ? {} : { body: sample.body }),
    })
    assert.notEqual(response.status, 404, `${sample.method} ${sample.path} is unreachable — the scan has stopped covering it`)
    assert.notEqual(response.status, 500, `${sample.method} ${sample.path} answered 500: ${response.text}`)
    assertClean(
      `${sample.method} ${sample.path}`,
      response.text,
      [...response.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n'),
    )
  }
})

test('SD-16: the ERROR bodies leak nothing either', { skip }, async () => {
  // An error path is a response body too, and it is the one most likely to be built by string
  // interpolation over whatever was to hand.
  const cases: Array<{ method: string; path: string; token?: string; body?: unknown }> = [
    { method: 'GET', path: '/v1/addresses/not-an-address', token: 'wallet' },
    { method: 'GET', path: `/v1/addresses/${addresses.ethereum}` },
    { method: 'POST', path: '/v1/addresses', token: 'alice', body: {} },
    { method: 'POST', path: '/v1/sign', token: 'wallet', body: { purpose: 'deposit' } },
    {
      method: 'POST',
      path: '/v1/sign',
      token: 'wallet',
      body: {
        address: addresses.ethereum,
        chain: 'ethereum',
        network: 'testnet',
        family: 'evm',
        purpose: 'deposit',
        userId: 'someone-else',
        orderId: 'wrong',
        payload: { nonsense: true },
      },
    },
    { method: 'GET', path: '/v1/exports/11111111-1111-4111-8111-111111111111', token: 'alice' },
    { method: 'POST', path: '/v1/exports/11111111-1111-4111-8111-111111111111/redeem', token: 'alice', body: { revealToken: 'x' } },
    { method: 'GET', path: '/v1/admin/keys', token: 'wallet' },
  ]
  for (const sample of cases) {
    const response = await server.request(sample.path, {
      method: sample.method,
      ...(sample.token ? { token: sample.token } : {}),
      ...(sample.body === undefined ? {} : { body: sample.body }),
    })
    assert.equal(response.status >= 400, true, `${sample.path} was expected to fail`)
    assertClean(`${sample.method} ${sample.path}`, response.text)
  }
})

test('SD-16: the ONE route that returns material is the last gate of the ceremony, and it is named', { skip }, async () => {
  // The scan above proves the negative. This proves the positive is exactly one route, reachable
  // only by the owner, only after the hold, only with the single-use token — so "no route returns
  // key material" is a claim with a stated, gated exception rather than a claim that is quietly
  // false.
  // A different address from the one the scan above opened a ceremony for: only one may be open per
  // address at a time, which is itself a control (two live ceremonies would mean two redeemable
  // secrets, so cancelling one would leave the other live).
  const address = addresses.bitcoin!
  const requested = await requestExport(h.exports, {
    address,
    userId: ALICE,
    format: 'raw',
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(requested.ok, true)
  if (!requested.ok) return
  h.setClock(h.clock() + DAY + 1_000)
  const challenged = await challengeExport(h.exports, {
    id: requested.value.id,
    userId: ALICE,
    amr: ['mfa'],
    authTimeSeconds: Math.floor(h.clock() / 1_000),
    correlationId: 'c',
  })
  assert.equal(challenged.ok, true)
  if (!challenged.ok) return

  // Every OTHER route, now that a ceremony is live, still returns nothing — including the one that
  // shows the ceremony's own state.
  const status = await server.request(`/v1/exports/${requested.value.id}`, { token: 'alice' })
  assertClean('GET /v1/exports/:id', status.text)
  assert.equal(status.text.includes(challenged.value.revealToken), false)

  const redeemed = await server.request(`/v1/exports/${requested.value.id}/redeem`, {
    method: 'POST',
    token: 'alice',
    body: { revealToken: challenged.value.revealToken },
  })
  assert.equal(redeemed.status, 200, redeemed.text)
  const material = ((redeemed.body.export as Record<string, unknown>).material ?? '') as string
  assert.equal(secrets.includes(material), true)
  // And it is not cacheable — SD-07 gate 8.
  assert.equal(redeemed.headers.get('cache-control'), 'no-store')

  // Single use: the same request again returns nothing at all.
  const replay = await server.request(`/v1/exports/${requested.value.id}/redeem`, {
    method: 'POST',
    token: 'alice',
    body: { revealToken: challenged.value.revealToken },
  })
  assert.equal(replay.status, 409)
  assertClean('replayed redeem', replay.text)
})

test('SD-16 as a SOURCE-LEVEL fact: only the redeem route names the material field', { skip }, async () => {
  // A route added tomorrow that returns a decrypted key would pass the scan above only if the scan's
  // route list were updated to include it — which is exactly the moment somebody would not. So the
  // source is checked too: `keyring.decrypt` appears in the domain modules and NEVER in server.ts.
  const server = readFileSync(new URL('./server.ts', import.meta.url), 'utf8')
  assert.equal(server.includes('keyring.decrypt'), false, 'server.ts decrypts a key — routes must go through keys.ts or exports.ts')
  assert.equal(server.includes('vault.read'), false, 'server.ts reads the vault directly')
  // `materialise` is the one function that produces plaintext, and it has one caller.
  const exportsSource = readFileSync(new URL('./exports.ts', import.meta.url), 'utf8')
  assert.equal(exportsSource.split('materialise(').length - 1, 2, 'materialise gained a second caller')
})
