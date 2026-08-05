/**
 * Litecoin, end to end through the service: mint an address, pin a treasury, sign a sweep.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE UNIT TESTS PROVE THE PARAMETERS ARE RIGHT. THIS PROVES THEY ARE USED.**
 *
 * Litecoin's `ChainFamily` is `'bitcoin'`, so every place that resolves network parameters from the
 * family alone is silently wrong for LTC — and there are two of them, in two files, reached at two
 * different times. `hd.ts` picks parameters to DERIVE and `signing.ts` picks them to SIGN, and the
 * two failures look nothing alike:
 *
 *   * derivation with Bitcoin's parameters mints a `bc1…` address published as a Litecoin deposit
 *     address, which loses whatever a user sends to it;
 *   * signing with Bitcoin's parameters refuses every Litecoin sweep, because `ECPair.fromWIF`
 *     throws on the version byte — funds arrive and can never leave.
 *
 * `hd.test.ts` catches the first by calling `deriveKey` directly. Nothing caught the second, because
 * every signing test called `signBitcoin` directly and so never exercised the CALL SITE that
 * chooses the chain. A mutation hard-coding `'bitcoin'` there survived the whole suite. This file
 * is that gap closed: it goes through `provisionAddress` and `signForAddress`, so the chain has to
 * travel from the stored row into the signer for anything here to pass.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import type postgres from 'postgres'
import * as bitcoin from 'bitcoinjs-lib'
import { bitcoinNetwork } from './chains.ts'
import { provisionAddress, signForAddress } from './keys.ts'
import { pinTreasury } from './store.ts'
import { enabled, harness, migrateTestDb, openDb, resetCustody, skip, type Harness } from './testsupport.ts'

const ALICE = '11111111-1111-4111-8111-111111111111'
const LTC_NETWORK = bitcoinNetwork('litecoin', 'testnet')

let sql: postgres.Sql
let h: Harness

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
})
after(async () => {
  if (enabled) await sql.end({ timeout: 5 })
})
beforeEach(async () => {
  if (!enabled) return
  await resetCustody(sql)
  h = await harness({ sql })
})

async function mintLitecoin(orderId: string, purpose: 'deposit' | 'treasury'): Promise<string> {
  const result = await provisionAddress(h.keys, {
    chain: 'litecoin',
    network: 'testnet',
    purpose,
    userId: purpose === 'treasury' ? 'cloudsforge:treasury' : ALICE,
    orderId,
    createdBy: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(result.ok, true, result.ok ? '' : result.error)
  return result.ok ? result.key.address : ''
}

/** A PSBT spending one output of `from`, paying `outputs`. Built under LITECOIN's parameters. */
function ltcPsbt(from: string, outputs: readonly string[]): string {
  const p = new bitcoin.Psbt({ network: LTC_NETWORK })
  p.addInput({
    hash: Buffer.alloc(32, 3),
    index: 0,
    witnessUtxo: { script: bitcoin.address.toOutputScript(from, LTC_NETWORK), value: 100_000 },
  })
  for (const address of outputs) {
    p.addOutput({
      script: bitcoin.address.toOutputScript(address, LTC_NETWORK),
      value: Math.floor(90_000 / outputs.length),
    })
  }
  return p.toBase64()
}

test('LITECOIN: an address minted through the service is a real Litecoin address', { skip }, async () => {
  const address = await mintLitecoin('o1', 'deposit')
  assert.ok(address.startsWith('tltc1'), `expected a tltc1… address, got ${address}`)
  // It decodes under Litecoin's parameters and NOT under Bitcoin's, which is the whole claim.
  assert.ok(bitcoin.address.toOutputScript(address, LTC_NETWORK))
  assert.throws(() => bitcoin.address.toOutputScript(address, bitcoinNetwork('bitcoin', 'testnet')))

  const rows = await sql<{ family: string; chain: string; derivation_path: string }[]>`
    select family, chain, derivation_path from custody_keys where address = ${address}
  `
  // The row records the FAMILY as bitcoin and the CHAIN as litecoin. Both are correct and the
  // distinction is the point — the signer must read the second, not the first.
  assert.equal(rows[0]!.family, 'bitcoin')
  assert.equal(rows[0]!.chain, 'litecoin')
  // Testnet is coin type 1 for every coin, which is the network-binding property.
  assert.equal(rows[0]!.derivation_path, "m/44'/1'/0'/0/0")
})

test('LITECOIN: a sweep signs, with the chain carried from the row into the signer', { skip }, async () => {
  const deposit = await mintLitecoin('o1', 'deposit')
  const treasury = await mintLitecoin('treasury:litecoin:testnet', 'treasury')
  const pinned = await pinTreasury(sql as never, {
    chain: 'litecoin',
    network: 'testnet',
    address: treasury,
    setBy: 'operator:test',
  })
  assert.ok(!('refusal' in pinned), `pinning refused: ${'refusal' in pinned ? pinned.refusal : ''}`)

  const outcome = await signForAddress(h.keys, {
    address: deposit,
    chain: 'litecoin',
    network: 'testnet',
    family: 'bitcoin',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o1',
    payload: ltcPsbt(deposit, [treasury]),
    actor: 'service:settlement',
    correlationId: 'c',
  })

  assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.error)
  if (!outcome.ok) return
  // A finalised raw transaction. Decoded back, so this cannot pass on an empty string.
  const tx = bitcoin.Transaction.fromHex(outcome.signedTx)
  assert.equal(tx.ins.length, 1)
  assert.ok(tx.ins[0]!.witness.length > 0, 'the input must carry a real witness')
  assert.equal(tx.outs.length, 1)
  assert.deepEqual(
    tx.outs[0]!.script,
    bitcoin.address.toOutputScript(treasury, LTC_NETWORK),
    'the one output must pay the pinned Litecoin treasury',
  )
})

test('LITECOIN: the pin is still the vault choice — a foreign output is refused', { skip }, async () => {
  const deposit = await mintLitecoin('o1', 'deposit')
  const treasury = await mintLitecoin('treasury:litecoin:testnet', 'treasury')
  const stranger = await mintLitecoin('o2', 'deposit')
  const pinned = await pinTreasury(sql as never, {
    chain: 'litecoin',
    network: 'testnet',
    address: treasury,
    setBy: 'operator:test',
  })
  assert.ok(!('refusal' in pinned), `pinning refused: ${'refusal' in pinned ? pinned.refusal : ''}`)

  const outcome = await signForAddress(h.keys, {
    address: deposit,
    chain: 'litecoin',
    network: 'testnet',
    family: 'bitcoin',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o1',
    payload: ltcPsbt(deposit, [stranger]),
    actor: 'service:settlement',
    correlationId: 'c',
  })
  assert.equal(outcome.ok, false)
  if (outcome.ok) return
  assert.match(outcome.error, /does not pay the treasury/)
})

test('LITECOIN: a Bitcoin deposit address and a Litecoin one are different keys', { skip }, async () => {
  /*
   * One user, one seed family (`bitcoin` serves both), two chains. The addresses must differ, and
   * they must differ because the COIN TYPE differs rather than merely because the index does — so
   * the derivation paths are asserted too. If they shared a path, a recovery phrase would restore
   * the Litecoin funds where no Litecoin wallet looks.
   */
  const ltc = await mintLitecoin('o1', 'deposit')
  const btcResult = await provisionAddress(h.keys, {
    chain: 'bitcoin',
    network: 'mainnet',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o2',
    createdBy: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(btcResult.ok, true, btcResult.ok ? '' : btcResult.error)
  const btc = btcResult.ok ? btcResult.key.address : ''

  assert.ok(ltc.startsWith('tltc1'))
  assert.ok(btc.startsWith('bc1'))
  assert.notEqual(ltc, btc)

  const paths = await sql<{ address: string; derivation_path: string }[]>`
    select address, derivation_path from custody_keys where address in (${ltc}, ${btc})
  `
  const byAddress = new Map(paths.map((r) => [r.address, r.derivation_path]))
  assert.equal(byAddress.get(btc), "m/44'/0'/0'/0/1", 'Bitcoin mainnet is coin type 0')
  assert.equal(byAddress.get(ltc), "m/44'/1'/0'/0/0", 'Litecoin TESTNET is coin type 1, like every testnet')
})
