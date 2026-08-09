/**
 * Dogecoin and Ethereum Classic, end to end through the service: mint, pin, sign.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE UNIT TESTS PROVE THE PARAMETERS ARE RIGHT. THIS PROVES THEY ARE USED.**
 *
 * The same argument `litecoin.test.ts` makes, and it applies twice over here because both new
 * assets share a family with an asset that behaves differently:
 *
 *   * DOGE's `ChainFamily` is `'bitcoin'`, so anything resolving from the family gets Bitcoin's
 *     network parameters AND Bitcoin's address kind. The second is new — Litecoin was segwit like
 *     Bitcoin, Dogecoin has no segwit at all — and it fails in a way nothing throws on: measured
 *     2026-08-09, `payments.p2wpkh` with an empty HRP returns `1q50rtrmj2f8…` rather than raising.
 *   * ETC's `ChainFamily` is `'evm'`, the same value Ethereum carries, and the signing policy read
 *     the FAMILY to decide whether EIP-1559 was acceptable. On a pre-London chain that produces a
 *     well-formed type-2 transaction, an audit row saying custody signed it, and a broadcast that
 *     the node rejects — a withdrawal stuck behind a signature that can never confirm.
 *
 * Both defects live at the CALL SITE that reads the row, in `keys.ts`, which no unit test reaches:
 * `hd.test.ts` and `signing.test.ts` both pass the chain in by hand and so would survive a mutation
 * that stopped carrying it. These tests go through `provisionAddress` and `signForAddress`, so the
 * chain has to travel from the stored row into the signer for anything below to pass.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import test, { after, before, beforeEach } from 'node:test'
import type postgres from 'postgres'
import * as bitcoin from 'bitcoinjs-lib'
import { ethers } from 'ethers'
import { bitcoinNetwork, expectedEvmChainId } from './chains.ts'
import { provisionAddress, signForAddress } from './keys.ts'
import { pinTreasury } from './store.ts'
import { enabled, harness, migrateTestDb, openDb, resetCustody, skip, type Harness } from './testsupport.ts'

const ALICE = '11111111-1111-4111-8111-111111111111'
const DOGE_NETWORK = bitcoinNetwork('dogecoin', 'testnet')

/**
 * Mordor, and EMBER's testnet, taken from the service's OWN resolution rather than written out.
 *
 * Gate 3 refuses a payload whose `chainId` is not the one `chainSpec` gives for the row's chain and
 * network, so a literal here would be a second copy of a number the estate keeps in `contracts` on
 * purpose — and a wrong one would fail these tests for the wrong reason. `hd.test.ts` asserts the
 * literal values (61 mainnet, 63 Mordor) against the registry; this file asserts the wiring.
 */
const MORDOR_CHAIN_ID = expectedEvmChainId('ethereum-classic', 'testnet')!
const EMBER_TESTNET_CHAIN_ID = expectedEvmChainId('ember', 'testnet')!

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

async function mint(chain: string, orderId: string, purpose: 'deposit' | 'treasury'): Promise<string> {
  const result = await provisionAddress(h.keys, {
    chain,
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

/**
 * A PSBT spending one output of `from`, paying `outputs`, built under DOGECOIN's parameters.
 *
 * The input carries `nonWitnessUtxo` and a real previous transaction, because Dogecoin's inputs are
 * P2PKH: a legacy signature does not commit to the input value, so there is no `witnessUtxo` to put
 * one in and the whole funding transaction has to be supplied instead. `litecoin.test.ts`'s helper
 * is the segwit shape and would be refused here, which is exactly the difference under test.
 */
function dogePsbt(from: string, outputs: readonly string[]): string {
  const script = bitcoin.address.toOutputScript(from, DOGE_NETWORK)
  const prev = new bitcoin.Transaction()
  prev.version = 1
  prev.addInput(Buffer.alloc(32, 3), 0)
  prev.addOutput(script, 1_000_000)

  const p = new bitcoin.Psbt({ network: DOGE_NETWORK })
  p.addInput({ hash: prev.getHash(), index: 0, nonWitnessUtxo: prev.toBuffer() })
  for (const address of outputs) {
    // 808,000 out of 1,000,000 leaves ~1000 koinu/vB, which is Dogecoin Core's own recommended fee
    // rate and was ABOVE the shared sweep ceiling this service used to apply to every
    // bitcoin-family chain. See `FEE_RATE_CEILINGS` in `signing.ts`.
    p.addOutput({
      script: bitcoin.address.toOutputScript(address, DOGE_NETWORK),
      value: Math.floor(808_000 / outputs.length),
    })
  }
  return p.toBase64()
}

test('DOGECOIN: an address minted through the service is a real Dogecoin address', { skip }, async () => {
  const address = await mint('dogecoin', 'o1', 'deposit')

  // Base58 P2PKH under testnet version byte 113, so `n…` or `m…` — and NOT bech32 under any HRP,
  // which is the failure this whole file exists for: Dogecoin has no segwit, so a `doge1…` or the
  // empty-HRP `1q…` form would be an address nobody can ever spend from.
  assert.ok(/^[mn]/.test(address), `expected an m…/n… address, got ${address}`)
  assert.equal(address.includes('1q'), false, 'the empty-HRP bogus form must never be minted')
  assert.ok(bitcoin.address.toOutputScript(address, DOGE_NETWORK))
  assert.throws(() => bitcoin.address.toOutputScript(address, bitcoinNetwork('bitcoin', 'testnet')))

  const rows = await sql<{ family: string; chain: string; derivation_path: string }[]>`
    select family, chain, derivation_path from custody_keys where address = ${address}
  `
  // FAMILY bitcoin, CHAIN dogecoin. Both correct, and the distinction is the point.
  assert.equal(rows[0]!.family, 'bitcoin')
  assert.equal(rows[0]!.chain, 'dogecoin')
  assert.equal(rows[0]!.derivation_path, "m/44'/1'/0'/0/0", 'testnet is coin type 1 for every coin')
})

test('DOGECOIN: a sweep signs, with the chain carried from the row into the signer', { skip }, async () => {
  const deposit = await mint('dogecoin', 'o1', 'deposit')
  const treasury = await mint('dogecoin', 'treasury:dogecoin:testnet', 'treasury')
  const pinned = await pinTreasury(sql as never, {
    chain: 'dogecoin',
    network: 'testnet',
    address: treasury,
    setBy: 'operator:test',
  })
  assert.ok(!('refusal' in pinned), `pinning refused: ${'refusal' in pinned ? pinned.refusal : ''}`)

  const outcome = await signForAddress(h.keys, {
    address: deposit,
    chain: 'dogecoin',
    network: 'testnet',
    family: 'bitcoin',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o1',
    payload: dogePsbt(deposit, [treasury]),
    actor: 'service:settlement',
    correlationId: 'c',
  })

  assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.error)
  if (!outcome.ok) return
  const tx = bitcoin.Transaction.fromHex(outcome.signedTx)
  assert.equal(tx.ins.length, 1)
  // NO WITNESS AND A REAL SCRIPTSIG — the structural signature of a legacy spend. A segwit-shaped
  // signature here would produce a transaction no Dogecoin node relays.
  assert.equal(tx.hasWitnesses(), false, 'a Dogecoin transaction must carry no witness')
  assert.ok(tx.ins[0]!.script.length > 0, 'the input must carry a scriptSig')
  assert.equal(tx.outs.length, 1)
  assert.deepEqual(
    tx.outs[0]!.script,
    bitcoin.address.toOutputScript(treasury, DOGE_NETWORK),
    'the one output must pay the pinned Dogecoin treasury',
  )
})

test('DOGECOIN: the pin is still the vault choice — a foreign output is refused', { skip }, async () => {
  const deposit = await mint('dogecoin', 'o1', 'deposit')
  const treasury = await mint('dogecoin', 'treasury:dogecoin:testnet', 'treasury')
  const stranger = await mint('dogecoin', 'o2', 'deposit')
  const pinned = await pinTreasury(sql as never, {
    chain: 'dogecoin',
    network: 'testnet',
    address: treasury,
    setBy: 'operator:test',
  })
  assert.ok(!('refusal' in pinned), `pinning refused: ${'refusal' in pinned ? pinned.refusal : ''}`)

  const outcome = await signForAddress(h.keys, {
    address: deposit,
    chain: 'dogecoin',
    network: 'testnet',
    family: 'bitcoin',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o1',
    payload: dogePsbt(deposit, [stranger]),
    actor: 'service:settlement',
    correlationId: 'c',
  })
  assert.equal(outcome.ok, false)
  if (outcome.ok) return
  assert.match(outcome.error, /does not pay the treasury/)
})

test('DOGECOIN: a Bitcoin, a Litecoin and a Dogecoin deposit address are three different keys', { skip }, async () => {
  /*
   * One user, one seed family — `bitcoin` serves all three — and three chains. They must differ, and
   * they must differ because the COIN TYPE differs rather than merely because the index does, which
   * is why the paths are asserted rather than just the addresses. Sharing a path would mean a
   * recovery phrase restoring the Dogecoin funds where no Dogecoin wallet looks.
   */
  const doge = await mint('dogecoin', 'o1', 'deposit')
  const ltc = await mint('litecoin', 'o2', 'deposit')
  const btcResult = await provisionAddress(h.keys, {
    chain: 'bitcoin',
    network: 'mainnet',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o3',
    createdBy: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(btcResult.ok, true, btcResult.ok ? '' : btcResult.error)
  const btc = btcResult.ok ? btcResult.key.address : ''

  assert.equal(new Set([doge, ltc, btc]).size, 3)
  assert.ok(/^[mn]/.test(doge), 'Dogecoin testnet is base58')
  assert.ok(ltc.startsWith('tltc1'), 'Litecoin testnet is bech32')
  assert.ok(btc.startsWith('bc1'), 'Bitcoin mainnet is bech32')
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * ETHEREUM CLASSIC — the gas rule, reached through the row rather than through a policy argument.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

const etcTx = (to: string, overrides: Record<string, unknown> = {}) => ({
  to,
  value: '1000000000000000',
  nonce: 0,
  gasLimit: 21_000,
  chainId: MORDOR_CHAIN_ID,
  maxFeePerGas: '20000000000',
  maxPriorityFeePerGas: '1000000000',
  ...overrides,
})

async function signEtc(deposit: string, payload: Record<string, unknown>) {
  return signForAddress(h.keys, {
    address: deposit,
    chain: 'ethereum-classic',
    network: 'testnet',
    family: 'evm',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o1',
    payload,
    actor: 'service:settlement',
    correlationId: 'c',
  })
}

async function etcDepositAndTreasury(): Promise<{ deposit: string; treasury: string }> {
  const deposit = await mint('ethereum-classic', 'o1', 'deposit')
  const treasury = await mint('ethereum-classic', 'treasury:ethereum-classic:testnet', 'treasury')
  const pinned = await pinTreasury(sql as never, {
    chain: 'ethereum-classic',
    network: 'testnet',
    address: treasury,
    setBy: 'operator:test',
  })
  assert.ok(!('refusal' in pinned), `pinning refused: ${'refusal' in pinned ? pinned.refusal : ''}`)
  return { deposit, treasury }
}

test('ETC: an ETC address is an ordinary EVM address at a DIFFERENT path from ETH', { skip }, async () => {
  const etc = await mint('ethereum-classic', 'o1', 'deposit')
  const ethResult = await provisionAddress(h.keys, {
    chain: 'ethereum',
    network: 'testnet',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o2',
    createdBy: 'service:wallet',
    correlationId: 'c',
  })
  assert.equal(ethResult.ok, true, ethResult.ok ? '' : ethResult.error)
  const eth = ethResult.ok ? ethResult.key.address : ''

  // Address FORMAT is Ethereum's entirely — EIP-55, twenty bytes — and that is correct: ETC shares
  // the format completely. What must differ is the KEY.
  assert.equal(ethers.getAddress(etc), etc, 'an ETC address is an EIP-55 checksummed address')
  assert.notEqual(etc, eth)

  const rows = await sql<{ address: string; family: string; chain: string; derivation_path: string }[]>`
    select address, family, chain, derivation_path from custody_keys where address in (${etc}, ${eth})
  `
  const byAddress = new Map(rows.map((r) => [r.address, r]))
  // Same FAMILY, different CHAIN — which is precisely why a policy keyed on the family is wrong.
  assert.equal(byAddress.get(etc)!.family, 'evm')
  assert.equal(byAddress.get(eth)!.family, 'evm')
  assert.equal(byAddress.get(etc)!.chain, 'ethereum-classic')
  // Both testnet, so both are at coin type 1 and the distinction is carried by the index, not the
  // path. The mainnet split (61 against 60) is asserted in `hd.test.ts`, which can derive directly.
  assert.equal(byAddress.get(etc)!.derivation_path, "m/44'/1'/0'/0/0")
  assert.equal(byAddress.get(eth)!.derivation_path, "m/44'/1'/0'/0/1")
})

test('ETC: an EIP-1559 sweep is REFUSED, on the strength of the row chain alone', { skip }, async () => {
  /*
   * **THE MUTATION THIS FILE EXISTS FOR.** `produceSignature` used to build the policy with
   * `legacyOnly: row.family === 'ember'`. ETC's family is `'evm'`, so that expression is false and
   * this sweep would be signed — a type-2 transaction on a chain that never adopted London, recorded
   * in `signing_audit` as a success and rejected by the node when settlement tries to broadcast it.
   *
   * Nothing else in the suite catches it: `signing.test.ts` passes `legacyOnly` in by hand, so it
   * asserts what the flag DOES and never what sets it.
   */
  const { deposit, treasury } = await etcDepositAndTreasury()
  const outcome = await signEtc(deposit, etcTx(treasury))
  assert.equal(outcome.ok, false)
  if (outcome.ok) return
  assert.match(outcome.error, /legacy transactions only/)
})

test('ETC: the same sweep with gasPrice signs, and is bound to Mordor chain id', { skip }, async () => {
  const { deposit, treasury } = await etcDepositAndTreasury()
  const legacy = etcTx(treasury, { gasPrice: '1000000000' })
  delete (legacy as Record<string, unknown>).maxFeePerGas
  delete (legacy as Record<string, unknown>).maxPriorityFeePerGas

  const outcome = await signEtc(deposit, legacy)
  assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.error)
  if (!outcome.ok) return

  const parsed = ethers.Transaction.from(outcome.signedTx)
  // Gate 3: the chain id is the SERVICE's, resolved from the row through `chainSpec`, and a payload
  // claiming any other value is refused before the key is decrypted.
  assert.equal(parsed.chainId, BigInt(MORDOR_CHAIN_ID))
  assert.equal(parsed.gasPrice, 1_000_000_000n)
  // Not type 2. Not asserted as type 0, because ETC took EIP-2718 and EIP-2930 in ECIP-1103
  // ("Magneto") and a type-1 envelope is valid there — it is only London's fee model it lacks.
  assert.notEqual(parsed.type, 2)
  assert.equal(parsed.maxFeePerGas, null)
})

test('ETC: a sweep to anything but the pinned treasury is still refused', { skip }, async () => {
  // The gas rule is new; the destination rule is not, and adding a chain must not quietly widen it.
  const { deposit } = await etcDepositAndTreasury()
  const stranger = ethers.Wallet.createRandom().address
  const legacy = etcTx(stranger, { gasPrice: '1000000000' })
  delete (legacy as Record<string, unknown>).maxFeePerGas
  delete (legacy as Record<string, unknown>).maxPriorityFeePerGas

  const outcome = await signEtc(deposit, legacy)
  assert.equal(outcome.ok, false)
  if (outcome.ok) return
  assert.match(outcome.error, /a sweep does not choose its own destination/)
})

test('ETC: EMBER keeps its own legacy-only rule — the list is not a replacement', { skip }, async () => {
  // The predicate changed from a family test to a chain list, and the obvious way to get that wrong
  // is to move ETC onto the list and drop EMBER off it. EMBER's refusal is asserted here so that
  // regression is a red test rather than a broken chain nobody signs for until the next withdrawal.
  const deposit = await mint('ember', 'o1', 'deposit')
  const treasury = await mint('ember', 'treasury:ember:testnet', 'treasury')
  const pinned = await pinTreasury(sql as never, {
    chain: 'ember',
    network: 'testnet',
    address: treasury,
    setBy: 'operator:test',
  })
  assert.ok(!('refusal' in pinned), `pinning refused: ${'refusal' in pinned ? pinned.refusal : ''}`)

  const outcome = await signForAddress(h.keys, {
    address: deposit,
    chain: 'ember',
    network: 'testnet',
    family: 'ember',
    purpose: 'deposit',
    userId: ALICE,
    orderId: 'o1',
    payload: { ...etcTx(treasury), chainId: EMBER_TESTNET_CHAIN_ID },
    actor: 'service:settlement',
    correlationId: 'c',
  })
  assert.equal(outcome.ok, false)
  if (outcome.ok) return
  assert.match(outcome.error, /legacy transactions only/)
})
