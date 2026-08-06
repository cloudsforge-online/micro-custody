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
 * **THE ROUTE LIST IS THE SERVER'S, NOT THIS FILE'S**, and that is the load-bearing part. This
 * comment used to say so while `routeSamples()` below was a hand-typed array that named eighteen of
 * the service's twenty-one routes; the three it missed included
 * `POST /v1/exports/:id/challenge`, which returns the reveal token — "the one secret in the estate
 * that yields a private key" (`exports.ts`). A hand-written list does not go red when somebody
 * adds a route; it just stops covering it, silently, which is exactly what happened. So:
 *
 *   * `server.routeTable()` is the enumeration, derived from `buildRoutes()` itself.
 *   * Every sample below DECLARES which route it covers, and the two sets must be equal in both
 *     directions — a route with no sample fails naming it, a sample for a route that no longer
 *     exists fails naming it too.
 *   * After the sweep, the server's OWN request counter is read back: every route must have been
 *     matched exactly as many times as samples claim to drive it, and nothing may have landed on
 *     `unmatched`. That is what makes "declares it covers a route" mean "reached that route",
 *     rather than "typed its name in a string".
 *
 * THE TWO ROUTES THAT MAY RETURN SOMETHING FORBIDDEN are handled by subtracting the ONE permitted
 * value, by exact value, exactly once, from that one response — never by exempting the route. The
 * rest of that body, and every one of its headers, is scanned in full. An exemption spanning a whole
 * response is how this gap reappears with the paperwork done.
 */

import assert from 'node:assert/strict'
import test, { after, before } from 'node:test'
import { readFileSync } from 'node:fs'
import type postgres from 'postgres'
import type { Metrics } from '@cloudsforge/telemetry'
import { challengeExport, hashToken, requestExport, type ExportRecord, type RevealedKey } from './exports.ts'
import { provisionAddress } from './keys.ts'
import { pinTreasury } from './store.ts'
import { seedSlot } from './vault.ts'
import { ADDRESS_CREATE_SCOPE, TREASURY_READ_SCOPE, routeTable } from './server.ts'
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
/** The server's own metrics, held so the sweep can read back WHICH route each request matched. */
let metrics: Metrics
/** Every private key, seed and mnemonic in the fixture estate. Nothing may echo any of them. */
let secrets: string[] = []
/** The same secrets, by chain, for the assertions that must name WHICH key a route handed back. */
let secretByChain: Record<string, string> = {}
let addresses: Record<string, string> = {}
/** A ceremony in its cooling-off, so `GET /v1/exports/:id` and the cancel route have one to act on. */
let ceremonyToCancel = ''
/** A ceremony past its hold, so the challenge and redeem routes can be driven over HTTP. */
let ceremonyToRedeem = ''
/** The reveal token the challenge route hands back, once the sweep has reached that route. */
let scanRevealToken = ''

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
  metrics = testMetrics()
  server = await startServer({
    lifecycle: testLifecycle(),
    logger: silentLogger,
    metrics,
    verifier: stubVerifier(TOKENS),
    keys: h.keys,
    exports: h.exports,
    limits: { signPerMinute: 500, addressPerHour: 500 },
    now: () => h.clock(),
  })

  addresses = {}
  secrets = []
  secretByChain = {}
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
    const secret = h.keys.keyring.decrypt(result.key.address, await h.vault.read(result.key.address))
    secrets.push(secret)
    secretByChain[chain] = secret
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
  /*
   * AND AN EMBER TREASURY, PINNED, so that `POST /v1/sign` actually SIGNS.
   *
   * Found by tightening this sweep's status assertion from "not 404" to the exact status each route
   * answers when it does its job: the sign sample has been answering 403 `no_treasury_pinned` — gate
   * 4 of `keys.ts` refuses a deposit signature until the chain has somewhere to sweep to — so the one
   * route in this service that decrypts a private key was never once driven past the gate BEFORE the
   * decryption. Its response body has therefore never been scanned in the state that matters.
   */
  const emberTreasury = await provisionAddress(h.keys, {
    chain: 'ember',
    network: 'testnet',
    purpose: 'treasury',
    userId: 'cloudsforge:treasury',
    orderId: 'treasury:ember:testnet',
    scheme: 'flat_random',
    createdBy: 'user:op',
    correlationId: 'c',
  })
  assert.equal(emberTreasury.ok, true, emberTreasury.ok ? '' : emberTreasury.error)
  if (emberTreasury.ok) {
    addresses.emberTreasury = emberTreasury.key.address
    secrets.push(
      h.keys.keyring.decrypt(emberTreasury.key.address, await h.vault.read(emberTreasury.key.address)),
    )
    const pinned = await pinTreasury(sql, {
      chain: 'ember',
      network: 'testnet',
      address: emberTreasury.key.address,
      setBy: 'user:op',
    })
    assert.equal('refusal' in pinned, false, `the ember treasury pin was refused: ${JSON.stringify(pinned)}`)
  }

  // And every seed's MNEMONIC — the master secret for every derived address of a (user, family).
  for (const row of await sql<{ id: string }[]>`select id from custody_seeds`) {
    secrets.push(h.keys.keyring.decrypt(seedSlot(row.id), await h.vault.read(seedSlot(row.id))))
  }
  assert.equal(secrets.length >= 6, true)

  /*
   * TWO OPEN CEREMONIES, opened here through the domain functions rather than by the sweep.
   *
   * The four `/v1/exports/:id/*` routes need an id that exists before the sample list is built, and
   * a sample list that cannot name them is a sample list that does not cover them. They are on
   * DIFFERENT addresses because a redemption is a state transition: the redeem sample moves the XRP
   * key to `exported`, and nothing else in the sweep touches XRP.
   */
  const cancellable = await requestExport(h.exports, {
    address: addresses.ethereum!,
    userId: ALICE,
    format: 'raw',
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(cancellable.ok, true)
  if (cancellable.ok) ceremonyToCancel = cancellable.value.id

  const redeemable = await requestExport(h.exports, {
    address: addresses.xrp!,
    userId: ALICE,
    format: 'xrp_seed',
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(redeemable.ok, true)
  if (redeemable.ok) ceremonyToRedeem = redeemable.value.id

  // Past the 24-hour hold, with `auth_time` set to now, so the challenge route's gate 6 is satisfied
  // over HTTP by a real token rather than being driven through the domain function behind it.
  h.setClock(h.clock() + DAY + 1_000)
  TOKENS.alice = userToken(ALICE, { authTimeMs: h.clock() })
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
  /*
   * THE SECOND TIER, and it is the same boundary micro-conformance's static estate-wide scan draws,
   * sourced from `exports.ts`: the reveal token, because it is "the one secret in the estate
   * that yields a private key", and its SHA-256, because "the hash is what a redemption is compared
   * against". Both are forbidden EVERYWHERE, including on the route that mints the token — that
   * response has its single permitted copy subtracted by exact value before this list is applied,
   * which is a different thing from being exempt from it.
   *
   * Deliberately NOT here, for the same reason it is not there: `derivationPath`. Custody returns it
   * on nine routes and `exports.ts` argues why — a path with no seed behind it opens nothing,
   * and a response goes to one authenticated user where an event goes to five stores.
   */
  if (scanRevealToken) parts.push(scanRevealToken, hashToken(scanRevealToken))
  return parts.filter((p) => p.length >= 16)
}

function assertClean(where: string, ...texts: string[]): void {
  const haystack = texts.join('\n')
  for (const secret of forbidden()) {
    assert.equal(haystack.includes(secret), false, `${where} returned key material`)
  }
}

/* ------------------------------------------------------------------ the permitted shapes */

/*
 * The exact field list of the two projections that reach a caller, as a TYPE-CHECKED fact.
 *
 * `Record<keyof T, true>` does not compile until every field is listed, so a field added to either
 * interface is a typecheck failure here before it is a red assertion — and the assertions below then
 * refuse any response whose key set is not exactly this. `ExportRecord` is documented as having "no
 * field that could carry key material" (`exports.ts`); this is that claim as something that
 * breaks.
 */
const EXPORT_RECORD_FIELDS = Object.keys({
  id: true,
  address: true,
  status: true,
  format: true,
  requestedAt: true,
  availableAt: true,
  expiresAt: true,
  challengedAt: true,
  tokenExpiresAt: true,
  redeemedAt: true,
  cancelledAt: true,
  policyDecision: true,
  policyReasons: true,
} satisfies Record<keyof ExportRecord, true>).sort()

const REVEALED_KEY_FIELDS = Object.keys({
  address: true,
  chain: true,
  network: true,
  scheme: true,
  derivationPath: true,
  format: true,
  material: true,
} satisfies Record<keyof RevealedKey, true>).sort()

function recordOf(body: Record<string, unknown>, field: string): Record<string, unknown> {
  const value = body[field]
  assert.equal(typeof value === 'object' && value !== null, true, `expected an object at '${field}'`)
  return value as Record<string, unknown>
}

/* ------------------------------------------------------------------ the scan */

interface ScanResponse {
  readonly status: number
  readonly headers: Headers
  readonly body: Record<string, unknown>
  readonly text: string
}

interface Sample {
  readonly method: string
  /** The path AS THE SERVER DECLARES IT. This is the route the sample claims to cover. */
  readonly route: string
  /** The concrete path requested. Defaults to `route`, which is right for a route with no params. */
  readonly path?: string
  readonly token?: string
  readonly body?: unknown
  /** A body that depends on an earlier response in the sweep, computed when the sample is driven. */
  readonly bodyFrom?: () => unknown
  /**
   * The status this route answers when it is REACHED and does its job.
   *
   * Exact, not "anything but 404". A route answering 409 because the fixture drifted is a route the
   * sweep is walking past, and "not 404" is how it would keep walking past it.
   */
  readonly expect: number
  /** Asserted before the body is scanned: precisely what this route is allowed to be. */
  readonly assertShape?: (response: ScanResponse) => void
  /**
   * The exact strings this route may return, each exactly once in the BODY and never in a header.
   * Not an exemption for the route — see the file header.
   */
  readonly permits?: () => readonly string[]
}

/**
 * A request that reaches every route in `server.routeTable()`, one entry per route.
 *
 * Nothing keeps this list honest by itself, and it is not asked to: the test below reconciles it
 * against the server's table, and then against the server's own count of which route each request
 * actually matched.
 */
function routeSamples(): Sample[] {
  return [
    { method: 'GET', route: '/livez', expect: 200 },
    { method: 'GET', route: '/readyz', expect: 200 },
    { method: 'GET', route: '/metrics', expect: 200 },
    {
      method: 'POST',
      route: '/v1/addresses',
      token: 'wallet',
      body: { chain: 'ethereum', network: 'testnet', purpose: 'deposit', userId: ALICE, orderId: 'scan-1' },
      expect: 201,
    },
    { method: 'GET', route: '/v1/addresses/:address', path: `/v1/addresses/${addresses.ethereum}`, token: 'wallet', expect: 200 },
    { method: 'GET', route: '/v1/addresses/:address', path: `/v1/addresses/${addresses.ethereum}`, token: 'alice', expect: 200 },
    { method: 'GET', route: '/v1/keys', token: 'alice', expect: 200 },
    {
      method: 'GET',
      route: '/v1/treasuries/:chain/:network',
      path: '/v1/treasuries/ethereum/testnet',
      token: 'wallet',
      expect: 200,
    },
    // The token allowlist, on the same read surface as the pin and under the same scope. Driven
    // here because SD-16's scan is only a proof about the surface if it covers ALL of it — and the
    // route-table assertion below is what makes forgetting to add a sample a failing test rather
    // than a quietly smaller scan.
    { method: 'GET', route: '/v1/token-contracts', token: 'wallet', expect: 200 },
    {
      method: 'POST',
      route: '/v1/sign',
      token: 'wallet',
      body: {
        address: addresses.ember,
        chain: 'ember',
        network: 'testnet',
        family: 'ember',
        purpose: 'deposit',
        userId: ALICE,
        orderId: 'order-ember',
        // A SWEEP, in the shape `signing.ts` actually accepts: empty calldata, positive value, the
        // [21000, 200000] gas band, and `to` equal to the pinned treasury character for character —
        // the destination is chosen by the vault, not by the caller (SD-09 gate 4).
        payload: {
          to: addresses.emberTreasury,
          data: '0x',
          value: '1000',
          nonce: 0,
          gasLimit: 21_000,
          chainId: 7412,
          gasPrice: '1',
        },
      },
      expect: 200,
      // One of the six custody routes micro-conformance's static scan reports it cannot fully read
      // (the emit callback in `outbox.ts` is opaque to it). Settled here: the response has exactly
      // two fields, both named, and the sweep has the real plaintext to compare them against.
      assertShape: (response) => {
        assert.deepEqual(Object.keys(response.body).sort(), ['auditId', 'signedTx'])
      },
    },
    { method: 'GET', route: '/v1/exports', token: 'alice', expect: 200 },
    {
      method: 'POST',
      route: '/v1/exports',
      token: 'alice',
      // The EMBER key, not one of the two the fixture already opened a ceremony for: `requestExport`
      // refuses an address that is not `active`, so a second open request would be a 409 and a route
      // the sweep only appeared to drive.
      body: { address: addresses.ember, format: 'raw' },
      expect: 201,
      assertShape: (response) => {
        assert.deepEqual(Object.keys(recordOf(response.body, 'export')).sort(), EXPORT_RECORD_FIELDS)
      },
    },
    {
      method: 'GET',
      route: '/v1/exports/:id',
      path: `/v1/exports/${ceremonyToCancel}`,
      token: 'alice',
      expect: 200,
      assertShape: (response) => {
        const record = recordOf(response.body, 'export')
        assert.deepEqual(Object.keys(record).sort(), EXPORT_RECORD_FIELDS)
        assert.equal(record['status'], 'cooling_off')
      },
    },
    {
      method: 'POST',
      route: '/v1/exports/:id/cancel',
      path: `/v1/exports/${ceremonyToCancel}/cancel`,
      token: 'alice',
      expect: 200,
      // Driven by NOTHING before this file was fixed. Also one of the six routes the static scan
      // cannot fully read. It returns the same projection every other ceremony route returns.
      assertShape: (response) => {
        const record = recordOf(response.body, 'export')
        assert.deepEqual(Object.keys(record).sort(), EXPORT_RECORD_FIELDS)
        assert.equal(record['status'], 'cancelled')
      },
    },
    {
      method: 'POST',
      route: '/v1/exports/:id/challenge',
      path: `/v1/exports/${ceremonyToRedeem}/challenge`,
      token: 'alice',
      expect: 200,
      assertShape: assertChallengeShape,
      permits: () => [scanRevealToken],
    },
    {
      method: 'POST',
      route: '/v1/exports/:id/redeem',
      path: `/v1/exports/${ceremonyToRedeem}/redeem`,
      token: 'alice',
      bodyFrom: () => ({ revealToken: scanRevealToken }),
      expect: 200,
      assertShape: assertRedeemShape,
      permits: () => [xrpSecret()],
    },
    { method: 'GET', route: '/v1/admin/keys', token: 'operator', expect: 200 },
    {
      method: 'GET',
      route: '/v1/admin/keys/:address',
      path: `/v1/admin/keys/${addresses.ethereum}`,
      token: 'operator',
      expect: 200,
    },
    {
      method: 'GET',
      route: '/v1/admin/keys/:address/audit',
      path: `/v1/admin/keys/${addresses.ethereum}/audit`,
      token: 'operator',
      expect: 200,
    },
    { method: 'GET', route: '/v1/admin/treasuries', token: 'operator', expect: 200 },
    {
      method: 'POST',
      route: '/v1/admin/treasuries/:chain/:network/mint',
      path: '/v1/admin/treasuries/bitcoin/testnet/mint',
      token: 'operator',
      expect: 201,
    },
    {
      method: 'PUT',
      route: '/v1/admin/treasuries/:chain/:network',
      path: '/v1/admin/treasuries/ethereum/testnet',
      token: 'operator',
      body: { address: addresses.treasury },
      expect: 200,
    },
    { method: 'GET', route: '/v1/admin/rotation', token: 'operator', expect: 200 },
  ]
}

/** The XRP family seed — the plaintext the redeem sample is supposed to hand back, and only it. */
function xrpSecret(): string {
  const secret = secretByChain['xrp']
  assert.equal(typeof secret, 'string', 'the fixture has no XRP secret to compare the redemption against')
  return secret!
}

/**
 * WHAT `POST /v1/exports/:id/challenge` IS ALLOWED TO BE, stated positively and completely.
 *
 * The reveal token in this response is INTENDED — gate 7 of the SD-07 ceremony. It is minted here,
 * handed to the key's owner after a fresh MFA assertion, and it is the credential for the redeem
 * route; there is no design in which it does not reach the caller. What was missing was any check on
 * what ELSE this route returns, because no test drove it at all.
 *
 * So this asserts the whole response rather than waving the route through: two top-level fields and
 * no third; a token of exactly the shape `exports.ts` mints (32 bytes, base64url); the ceremony
 * projection beside it, field for field; and NOT the token's SHA-256, which is the stored form a
 * redemption is compared against and has no business on a wire. The token's single appearance in the
 * body is subtracted by exact value by the sweep, which then scans everything that is left.
 */
function assertChallengeShape(response: ScanResponse): void {
  assert.deepEqual(Object.keys(response.body).sort(), ['export', 'revealToken'])

  const token = response.body['revealToken']
  assert.equal(typeof token, 'string', 'the challenge must return a reveal token')
  assert.match(token as string, /^[A-Za-z0-9_-]{43}$/, 'the reveal token is 32 random bytes, base64url')
  scanRevealToken = token as string

  const record = recordOf(response.body, 'export')
  assert.deepEqual(Object.keys(record).sort(), EXPORT_RECORD_FIELDS)
  assert.equal(record['id'], ceremonyToRedeem)
  assert.equal(record['status'], 'challenged')
  assert.equal(typeof record['tokenExpiresAt'], 'string', 'a challenged ceremony has a token expiry')

  assert.equal(
    response.text.includes(hashToken(scanRevealToken)),
    false,
    'the challenge returned the token HASH — the value a redemption is compared against',
  )
  assert.equal(response.headers.get('cache-control'), 'no-store')
  for (const [, value] of response.headers.entries()) {
    assert.equal(value.includes(scanRevealToken), false, 'the reveal token reached a response HEADER')
  }
}

/**
 * WHAT `POST /v1/exports/:id/redeem` IS ALLOWED TO BE. The one route in the estate that is supposed
 * to return a private key, and it may return exactly one — the plaintext of the address its own
 * ceremony names, in the format that ceremony asked for, and nothing else that is secret.
 */
function assertRedeemShape(response: ScanResponse): void {
  assert.deepEqual(Object.keys(response.body).sort(), ['export'])
  const revealed = recordOf(response.body, 'export')
  assert.deepEqual(Object.keys(revealed).sort(), REVEALED_KEY_FIELDS)
  assert.equal(revealed['address'], addresses.xrp)
  assert.equal(revealed['format'], 'xrp_seed')
  // The material is THE secret for that address and no other — `secrets.includes` alone would pass
  // on a response that handed back somebody else's key.
  assert.equal(revealed['material'], xrpSecret())
  assert.equal(response.headers.get('cache-control'), 'no-store')
}

/**
 * How many times the server matched each route, read back from its own request counter.
 *
 * `server.ts` labels `http_requests_total` with `matched.route.path`, or `unmatched` when nothing
 * matched. It is the server's answer to "which route did that request reach", which is the question
 * a list of sample paths cannot answer about itself.
 */
function matchedRouteCounts(): Map<string, number> {
  const counts = new Map<string, number>()
  for (const line of metrics.render().split('\n')) {
    const parsed = /^http_requests_total\{([^}]*)\} (\d+(?:\.\d+)?)$/.exec(line)
    if (!parsed) continue
    const labels = new Map([...parsed[1]!.matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]))
    const key = `${labels.get('method') ?? '?'} ${labels.get('route') ?? '?'}`
    counts.set(key, (counts.get(key) ?? 0) + Number(parsed[2]))
  }
  return counts
}

const keyOf = (entry: { method: string; route?: string; path?: string }): string =>
  `${entry.method} ${entry.route ?? entry.path}`

test("SD-16: the sweep's route list IS the server's route table", { skip }, () => {
  const declared = routeTable().map((route) => `${route.method} ${route.path}`)
  const covered = routeSamples().map(keyOf)

  // A route the sweep cannot drive is a FAILURE, not an omission. This is the assertion the file's
  // own comment claimed to make and did not, and its absence is why `POST /v1/exports/:id/cancel`
  // and `POST /v1/exports/:id/challenge` were driven by nothing at all.
  for (const route of declared) {
    assert.equal(
      covered.includes(route),
      true,
      `${route} is a route of this server that the SD-16 body scan does not drive — add a sample for it`,
    )
  }
  // And the other direction, so a renamed or deleted route cannot leave a sample behind that quietly
  // covers nothing.
  for (const route of covered) {
    assert.equal(declared.includes(route), true, `the body scan drives ${route}, which this server does not route`)
  }
  assert.equal(declared.length, new Set(declared).size, 'the server declares the same route twice')
})

test('SD-16: NO route returns key material, under any credential', { skip }, async () => {
  const samples = routeSamples()
  for (const sample of samples) {
    const path = sample.path ?? sample.route
    const body = sample.bodyFrom ? sample.bodyFrom() : sample.body
    const response = await server.request(path, {
      method: sample.method,
      ...(sample.token ? { token: sample.token } : {}),
      ...(body === undefined ? {} : { body }),
    })
    const where = `${sample.method} ${sample.route}`
    assert.equal(
      response.status,
      sample.expect,
      `${where} (${path}) answered ${response.status} rather than ${sample.expect} — the sweep is not reaching it: ${response.text}`,
    )

    sample.assertShape?.(response)

    // The permitted values are removed from the haystack by EXACT VALUE and EXACTLY ONCE. Everything
    // else in the body is then scanned as it would be on any other route, so a second leak on a
    // route with a permitted field is still a failure.
    let haystack = response.text
    for (const value of sample.permits?.() ?? []) {
      const occurrences = haystack.split(value).length - 1
      assert.equal(occurrences, 1, `${where} may return this value exactly once; it appeared ${occurrences} times`)
      haystack = haystack.replace(value, '[permitted]')
    }
    assertClean(where, haystack)
    // Headers get no permission at all: nothing forbidden belongs in one, on any route.
    assertClean(`${where} headers`, [...response.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n'))
  }

  /*
   * AND THE SERVER'S OWN ACCOUNT OF WHERE THOSE REQUESTS WENT.
   *
   * Set equality above proves the sample list names every route. This proves the samples REACH the
   * routes they name: a sample whose concrete path matched a different route, or nothing, leaves its
   * declared route on zero here and fails naming it. Without this, `route:` is a string a test author
   * types, and a string a test author types is the defect this file was fixed for.
   */
  const observed = matchedRouteCounts()
  const expected = new Map<string, number>()
  for (const sample of samples) expected.set(keyOf(sample), (expected.get(keyOf(sample)) ?? 0) + 1)

  for (const [key, count] of observed) {
    assert.equal(key.endsWith(' unmatched'), false, `${count} request(s) in the sweep matched no route at all`)
  }
  for (const [key, count] of expected) {
    assert.equal(observed.get(key) ?? 0, count, `the server matched ${key} ${observed.get(key) ?? 0} times; the sweep drives it ${count}`)
  }
  assert.equal(observed.size, expected.size, 'the sweep reached a route it does not have a sample for')
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
    // The two ceremony routes that no test drove at all until this file was fixed, on their REFUSAL
    // paths. Both act on ceremonies the sweep above has already spent — a redeemed one cannot be
    // challenged again and a cancelled one cannot be cancelled — so this case depends on the sweep
    // having run, which within one file it has.
    { method: 'POST', path: `/v1/exports/${ceremonyToRedeem}/challenge`, token: 'alice' },
    { method: 'POST', path: `/v1/exports/${ceremonyToCancel}/cancel`, token: 'alice' },
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
  // A different address from the ones the scan above opened ceremonies for: only one may be open per
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

test('SD-16 as a SOURCE-LEVEL fact: only the redeem route names the material field', { skip }, () => {
  // The sweep above judges what routes RETURN. This judges where plaintext can be PRODUCED, which is
  // the property that survives a route being added faster than a fixture can be built for it:
  // `keyring.decrypt` appears in the domain modules and NEVER in server.ts, so no route can reach
  // plaintext except through the two modules whose exports are all accounted for here.
  const server = readFileSync(new URL('./server.ts', import.meta.url), 'utf8')
  assert.equal(server.includes('keyring.decrypt'), false, 'server.ts decrypts a key — routes must go through keys.ts or exports.ts')
  assert.equal(server.includes('vault.read'), false, 'server.ts reads the vault directly')
  // `materialise` is the one function that produces plaintext, and it has one caller.
  const exportsSource = readFileSync(new URL('./exports.ts', import.meta.url), 'utf8')
  assert.equal(exportsSource.split('materialise(').length - 1, 2, 'materialise gained a second caller')
})
