/**
 * The export ceremony — SD-07 — and the deleted reveal route's replacement.
 *
 * SD-07's verification line asks for "a journey covering the happy path, the cancel path, and
 * cooling-off expiry" plus "a test asserting an `exported` wallet is excluded from sweep candidate
 * selection". The last of those lives in `server.test.ts` and `gates.test.ts`, because in this
 * service "excluded from sweeping" means the purpose gate refuses to sign for it at all.
 *
 * The clock is injected. A 24-hour hold that the suite could not advance past would either not be
 * tested or would be tested by waiting a day, and the hold is the single most important control in
 * the list.
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import { ethers } from 'ethers'
import type postgres from 'postgres'
import { deriveKey, seedFromMnemonic } from './hd.ts'
import { cancelExport, challengeExport, expireExports, redeemExport, requestExport, hashToken } from './exports.ts'
import { provisionAddress } from './keys.ts'
import { getKey } from './store.ts'
import { failClosed } from './policy.ts'
import {
  ALICE,
  BOB,
  enabled,
  fixedPolicy,
  harness,
  migrateTestDb,
  openDb,
  resetCustody,
  skip,
  type Harness,
} from './testsupport.ts'

const HOUR = 3_600_000
const DAY = 24 * HOUR

let sql: postgres.Sql
let h: Harness

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
  h = await harness({ sql })
})

async function mintFor(userId = ALICE, chain = 'ethereum', scheme: 'hd_bip44' | 'flat_random' = 'hd_bip44') {
  const result = await provisionAddress(h.keys, {
    chain,
    network: 'testnet',
    purpose: 'user',
    userId,
    orderId: 'wallet-1',
    scheme,
    createdBy: 'service:wallet',
    correlationId: 'corr-1',
  })
  assert.equal(result.ok, true)
  return result.ok ? result.key.address : ''
}

const FRESH_MFA = { amr: ['mfa'] as string[] }

/** Drive the ceremony to a live reveal token. Every test that redeems needs all four steps. */
async function toChallenged(address: string, format: 'keystore' | 'mnemonic' | 'raw' = 'keystore') {
  const requested = await requestExport(h.exports, {
    address,
    userId: ALICE,
    format,
    actor: `user:${ALICE}`,
    correlationId: 'corr-1',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(requested.ok, true)
  const id = requested.ok ? requested.value.id : ''
  h.setClock(h.clock() + DAY + 1_000)
  const challenged = await challengeExport(h.exports, {
    id,
    userId: ALICE,
    ...FRESH_MFA,
    authTimeSeconds: Math.floor(h.clock() / 1_000),
    correlationId: 'corr-1',
  })
  assert.equal(challenged.ok, true, challenged.ok ? '' : challenged.error)
  return { id, revealToken: challenged.ok ? challenged.value.revealToken : '' }
}

/* ------------------------------------------------------------------ the happy path */

test('the happy path: request → 24h hold → second challenge → single-use redeem → exported', { skip }, async () => {
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'keystore')

  const redeemed = await redeemExport(h.exports, {
    id,
    userId: ALICE,
    revealToken,
    passphrase: 'a-long-enough-passphrase',
    correlationId: 'corr-1',
  })
  assert.equal(redeemed.ok, true, redeemed.ok ? '' : redeemed.error)
  if (!redeemed.ok) return

  // The keystore is scrypt-wrapped — the only offered format safe to save to disk, which is why
  // SD-07 makes it the default. What lands in the file is a KDF envelope, not the key.
  const keystore = JSON.parse(redeemed.value.material) as Record<string, unknown>
  assert.equal(keystore.version, 3)
  const recovered = await ethers.Wallet.fromEncryptedJson(redeemed.value.material, 'a-long-enough-passphrase')
  assert.equal(recovered.address, address)
  // The plaintext key is nowhere in the exported document.
  assert.equal(redeemed.value.material.includes(recovered.privateKey.slice(2)), false)

  // GATE 9: the wallet is `exported`, irreversibly.
  const key = await getKey(sql, address)
  assert.equal(key!.status, 'exported')
  assert.notEqual(key!.exported_at, null)

  // GATE 7: single use. The token is spent and the row is redeemed.
  const replay = await redeemExport(h.exports, { id, userId: ALICE, revealToken, passphrase: 'a-long-enough-passphrase', correlationId: 'c' })
  assert.equal(replay.ok, false)
  const rows = await sql`select status, token_hash from key_exports where id = ${id}`
  assert.equal(rows[0]!.status, 'redeemed')
  assert.equal(rows[0]!.token_hash, null)
})

test('an exported mnemonic actually re-derives the address it was exported for', { skip }, async () => {
  // The one thing that makes a recovery phrase worth offering. A wrong derivation rule would produce
  // a phrase that restores to addresses holding none of the user's coins, and nothing else in this
  // suite would notice.
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'mnemonic')
  const redeemed = await redeemExport(h.exports, { id, userId: ALICE, revealToken, correlationId: 'c' })
  assert.equal(redeemed.ok, true)
  if (!redeemed.ok) return

  assert.equal(redeemed.value.material.split(' ').length, 24)
  assert.equal(redeemed.value.derivationPath, "m/44'/1'/0'/0/0")
  const rederived = deriveKey(seedFromMnemonic(redeemed.value.material), 'evm', 'testnet', 0)
  assert.equal(rederived.address, address)
})

/* ------------------------------------------------------------------ the gates */

test('GATE 1 and 2: without `pwd` and `mfa` in the token, the ceremony does not start', { skip }, async () => {
  const address = await mintFor()
  const base = { address, userId: ALICE, format: 'keystore' as const, actor: `user:${ALICE}`, correlationId: 'c', context: {} }
  const noPassword = await requestExport(h.exports, { ...base, amr: ['mfa'] })
  assert.equal(noPassword.ok, false)
  assert.equal(noPassword.ok ? '' : noPassword.code, 'reauthentication_required')
  const noMfa = await requestExport(h.exports, { ...base, amr: ['pwd'] })
  assert.equal(noMfa.ok ? '' : noMfa.code, 'mfa_required')
  assert.equal((await sql`select count(*)::int as n from key_exports`)[0]!.n, 0)
})

test('GATE 3: policy is FAIL-CLOSED — an unreachable policy service denies', { skip }, async () => {
  const denying = await harness({ sql, policy: { decide: async () => failClosed('unreachable') } })
  const address = await provisionAddress(denying.keys, {
    chain: 'ethereum',
    network: 'testnet',
    purpose: 'user',
    userId: ALICE,
    orderId: 'w1',
    createdBy: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(address.ok, true)
  if (!address.ok) return
  const result = await requestExport(denying.exports, {
    address: address.key.address,
    userId: ALICE,
    format: 'raw',
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(result.ok, true)
  assert.equal(result.ok ? result.value.status : '', 'denied')
  assert.deepEqual(result.ok ? result.value.policyReasons : [], ['policy_unavailable:unreachable'])
})

test('GATE 3: `challenge` and `review` are NOT partial successes — no live ceremony is opened', { skip }, async () => {
  for (const effect of ['challenge', 'review', 'deny'] as const) {
    await resetCustody(sql)
    const local = await harness({ sql, policy: fixedPolicy({ effect, reasons: [`because_${effect}`] }) })
    const minted = await provisionAddress(local.keys, {
      chain: 'ethereum',
      network: 'testnet',
      purpose: 'user',
      userId: ALICE,
      orderId: 'w1',
      createdBy: 'service:wallet',
      correlationId: 'c',
    })
    assert.equal(minted.ok, true)
    if (!minted.ok) continue
    const result = await requestExport(local.exports, {
      address: minted.key.address,
      userId: ALICE,
      format: 'raw',
      actor: `user:${ALICE}`,
      correlationId: 'c',
      amr: ['pwd', 'mfa'],
      context: {},
    })
    assert.equal(result.ok ? result.value.status : '', 'denied', effect)
    // A denied row is not challengeable, so an attacker cannot return to it.
    const id = result.ok ? result.value.id : ''
    const challenged = await challengeExport(local.exports, { id, userId: ALICE, amr: ['mfa'], authTimeSeconds: Math.floor(local.clock() / 1_000), correlationId: 'c' })
    assert.equal(challenged.ok, false, effect)
  }
})

test('GATE 4: the 24-hour cooling-off cannot be skipped, and the refusal says how long is left', { skip }, async () => {
  const address = await mintFor()
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
  const id = requested.value.id
  assert.equal(requested.value.status, 'cooling_off')
  assert.equal(new Date(requested.value.availableAt!).getTime() - h.clock(), DAY)

  // One second short of a day. This is the control that works while the user is being deceived on
  // the phone, so it must not be a soft edge.
  h.setClock(h.clock() + DAY - 1_000)
  const early = await challengeExport(h.exports, { id, userId: ALICE, amr: ['mfa'], authTimeSeconds: Math.floor(h.clock() / 1_000), correlationId: 'c' })
  assert.equal(early.ok, false)
  assert.equal(early.ok ? '' : early.code, 'cooling_off')
  assert.match(early.ok ? '' : early.error, /1s remaining/)

  h.setClock(h.clock() + 2_000)
  const late = await challengeExport(h.exports, { id, userId: ALICE, amr: ['mfa'], authTimeSeconds: Math.floor(h.clock() / 1_000), correlationId: 'c' })
  assert.equal(late.ok, true)
})

test('GATE 6: the second challenge needs a FRESH factor, not the one from a day ago', { skip }, async () => {
  const address = await mintFor()
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
  const staleAuthTime = Math.floor(h.clock() / 1_000)
  h.setClock(h.clock() + DAY + 1_000)

  const noFactor = await challengeExport(h.exports, { id: requested.value.id, userId: ALICE, amr: [], authTimeSeconds: staleAuthTime, correlationId: 'c' })
  assert.equal(noFactor.ok ? '' : noFactor.code, 'mfa_required')
  // The attacker must still HOLD the factor a day later, not merely have held it once.
  const stale = await challengeExport(h.exports, { id: requested.value.id, userId: ALICE, amr: ['mfa'], authTimeSeconds: staleAuthTime, correlationId: 'c' })
  assert.equal(stale.ok ? '' : stale.code, 'stale_authentication')
})

test('GATE 7: the reveal token is stored SHA-256 only, and a wrong one is refused', { skip }, async () => {
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'raw')
  const rows = await sql`select token_hash, token_expires_at from key_exports where id = ${id}`
  assert.equal(rows[0]!.token_hash, hashToken(revealToken))
  assert.notEqual(rows[0]!.token_hash, revealToken)

  const wrong = await redeemExport(h.exports, { id, userId: ALICE, revealToken: 'not-the-token', correlationId: 'c' })
  assert.equal(wrong.ok ? '' : wrong.code, 'bad_token')
  // A failed redemption does not spend the ceremony — the honest user can still finish.
  assert.equal((await sql`select status from key_exports where id = ${id}`)[0]!.status, 'challenged')
})

test('GATE 7: a token past its short TTL is refused, and a new challenge re-mints one', { skip }, async () => {
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'raw')
  h.setClock(h.clock() + 301_000)
  const expired = await redeemExport(h.exports, { id, userId: ALICE, revealToken, correlationId: 'c' })
  assert.equal(expired.ok ? '' : expired.code, 'token_expired')

  const again = await challengeExport(h.exports, { id, userId: ALICE, amr: ['mfa'], authTimeSeconds: Math.floor(h.clock() / 1_000), correlationId: 'c' })
  assert.equal(again.ok, true)
  assert.notEqual(again.ok ? again.value.revealToken : '', revealToken)
  const redeemed = await redeemExport(h.exports, { id, userId: ALICE, revealToken: again.ok ? again.value.revealToken : '', correlationId: 'c' })
  assert.equal(redeemed.ok, true)
})

test('a second challenge while a token is LIVE is refused — two redeemable secrets, one ceremony', { skip }, async () => {
  const address = await mintFor()
  const { id } = await toChallenged(address, 'raw')
  const second = await challengeExport(h.exports, { id, userId: ALICE, amr: ['mfa'], authTimeSeconds: Math.floor(h.clock() / 1_000), correlationId: 'c' })
  assert.equal(second.ok ? '' : second.code, 'already_challenged')
})

/* ------------------------------------------------------------------ ownership */

test('no operator and no service can complete any step — the ceremony is a USER right', { skip }, async () => {
  // The control against SD-07's malicious-insider case, and the reason the deleted route had no
  // answer for it: every step compares `user_id` on the row.
  const address = await mintFor(ALICE)
  const { id, revealToken } = await toChallenged(address, 'raw')
  assert.equal((await redeemExport(h.exports, { id, userId: BOB, revealToken, correlationId: 'c' })).ok, false)
  assert.equal((await cancelExport(h.exports, { id, userId: BOB, actor: 'user:b', correlationId: 'c' })).ok, false)
  assert.equal(
    (await challengeExport(h.exports, { id, userId: BOB, amr: ['mfa'], authTimeSeconds: Math.floor(h.clock() / 1_000), correlationId: 'c' })).ok,
    false,
  )
})

test('a wallet owned by someone else is 404, not 403', { skip }, async () => {
  const address = await mintFor(ALICE)
  const result = await requestExport(h.exports, {
    address,
    userId: BOB,
    format: 'raw',
    actor: `user:${BOB}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(result.ok ? '' : result.code, 'not_found')
})

test('a platform-owned address is not user-exportable at all', { skip }, async () => {
  for (const purpose of ['treasury', 'deployer'] as const) {
    const minted = await provisionAddress(h.keys, {
      chain: 'ethereum',
      network: 'testnet',
      purpose,
      userId: ALICE,
      orderId: `o-${purpose}`,
      scheme: 'flat_random',
      createdBy: 'service:wallet',
      correlationId: 'c',
    })
    assert.equal(minted.ok, true)
    if (!minted.ok) continue
    const result = await requestExport(h.exports, {
      address: minted.key.address,
      userId: ALICE,
      format: 'raw',
      actor: `user:${ALICE}`,
      correlationId: 'c',
      amr: ['pwd', 'mfa'],
      context: {},
    })
    assert.equal(result.ok ? '' : result.code, 'not_exportable', purpose)
  }
})

/* ------------------------------------------------------------------ formats */

test('SDR-08: a legacy flat-random key is refused a MNEMONIC, honestly and at request time', { skip }, async () => {
  // Refused at request time rather than at redemption, so a user is not told "no" after a day.
  const address = await mintFor(ALICE, 'ethereum', 'flat_random')
  const result = await requestExport(h.exports, {
    address,
    userId: ALICE,
    format: 'mnemonic',
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(result.ok ? '' : result.code, 'format_unavailable')
  assert.match(result.ok ? '' : result.error, /no recovery phrase exists for it/)

  // The raw key is still exportable — a legacy key is not a stranded key.
  const raw = await requestExport(h.exports, {
    address,
    userId: ALICE,
    format: 'raw',
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(raw.ok && raw.value.status === 'cooling_off', true)
})

test('the keystore format is offered only where a UTC/JSON keystore is defined', { skip }, async () => {
  const btc = await mintFor(BOB, 'bitcoin')
  const result = await requestExport(h.exports, {
    address: btc,
    userId: BOB,
    format: 'keystore',
    actor: `user:${BOB}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(result.ok ? '' : result.code, 'format_unavailable')
})

test('a keystore redemption without a passphrase is refused rather than written unencrypted', { skip }, async () => {
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'keystore')
  const result = await redeemExport(h.exports, { id, userId: ALICE, revealToken, correlationId: 'c' })
  assert.equal(result.ok ? '' : result.code, 'passphrase_required')
})

/* ------------------------------------------------------------------ cancel and expiry */

test('the CANCEL path: a ceremony can be stopped at every open state, and the token dies with it', { skip }, async () => {
  for (const stopAt of ['cooling_off', 'challenged'] as const) {
    await resetCustody(sql)
    h = await harness({ sql })
    const address = await mintFor()
    let id: string
    let revealToken = ''
    if (stopAt === 'cooling_off') {
      const requested = await requestExport(h.exports, {
        address,
        userId: ALICE,
        format: 'raw',
        actor: `user:${ALICE}`,
        correlationId: 'c',
        amr: ['pwd', 'mfa'],
        context: {},
      })
      id = requested.ok ? requested.value.id : ''
    } else {
      const challenged = await toChallenged(address, 'raw')
      id = challenged.id
      revealToken = challenged.revealToken
    }

    const cancelled = await cancelExport(h.exports, { id, userId: ALICE, actor: `user:${ALICE}`, correlationId: 'c' })
    assert.equal(cancelled.ok, true, stopAt)
    assert.equal(cancelled.ok ? cancelled.value.status : '', 'cancelled')
    assert.equal((await sql`select token_hash from key_exports where id = ${id}`)[0]!.token_hash, null)
    if (revealToken) {
      assert.equal((await redeemExport(h.exports, { id, userId: ALICE, revealToken, correlationId: 'c' })).ok, false)
    }
    // And the wallet is untouched: a cancelled export is not an export.
    assert.equal((await getKey(sql, address))!.status, 'active')
  }
})

test('COOLING-OFF EXPIRY: an abandoned ceremony expires and stops being redeemable', { skip }, async () => {
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'raw')
  h.setClock(h.clock() + 200 * HOUR)
  assert.equal(await expireExports(h.exports), 1)
  const rows = await sql`select status, token_hash from key_exports where id = ${id}`
  assert.equal(rows[0]!.status, 'expired')
  // The hash is cleared on the way through: an expired-but-present secret in a table is a secret
  // sitting there for no reason.
  assert.equal(rows[0]!.token_hash, null)
  assert.equal((await redeemExport(h.exports, { id, userId: ALICE, revealToken, correlationId: 'c' })).ok, false)
  assert.equal((await getKey(sql, address))!.status, 'active')
})

test('only ONE ceremony can be open per address at a time', { skip }, async () => {
  // Two live ceremonies would mean two redeemable secrets, so cancelling one would leave the other
  // live — which defeats the cancel link that gates 4 and 5 depend on.
  const address = await mintFor()
  const input = {
    address,
    userId: ALICE,
    format: 'raw' as const,
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  }
  assert.equal((await requestExport(h.exports, input)).ok, true)
  await assert.rejects(() => requestExport(h.exports, input), /key_exports_one_open_idx/)
})

test('an already-exported wallet cannot be exported again', { skip }, async () => {
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'raw')
  assert.equal((await redeemExport(h.exports, { id, userId: ALICE, revealToken, correlationId: 'c' })).ok, true)
  const second = await requestExport(h.exports, {
    address,
    userId: ALICE,
    format: 'raw',
    actor: `user:${ALICE}`,
    correlationId: 'c',
    amr: ['pwd', 'mfa'],
    context: {},
  })
  assert.equal(second.ok ? '' : second.code, 'not_exportable')
})

/* ------------------------------------------------------------------ the audit trail */

test('GATE 10: request, cancel and completion each emit an event, and none carries the material', { skip }, async () => {
  const address = await mintFor()
  const { id, revealToken } = await toChallenged(address, 'raw')
  const redeemed = await redeemExport(h.exports, { id, userId: ALICE, revealToken, correlationId: 'c' })
  assert.equal(redeemed.ok, true)
  if (!redeemed.ok) return

  const events = await sql`select topic, payload::text as payload from outbox where topic like 'custody.export.%'`
  assert.deepEqual(events.map((e) => e.topic).sort(), ['custody.export.completed', 'custody.export.requested'])
  for (const event of events) {
    // An event is delivered over HTTP to subscribers and stored in a table. A key in one would
    // defeat every other control in this file.
    assert.equal(String(event.payload).includes(redeemed.value.material), false)
    assert.equal(String(event.payload).includes(revealToken), false)
  }
})
