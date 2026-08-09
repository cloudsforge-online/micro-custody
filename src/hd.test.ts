/**
 * HD derivation, checked against the PUBLISHED vectors rather than against itself.
 *
 * A derivation suite that only asserts "the same seed gives the same address twice" proves the code
 * is deterministic and nothing else — it would pass just as happily against a wrong implementation,
 * and a wrong implementation here means a user's exported recovery phrase restores to addresses that
 * hold none of their coins. The vectors below are the ones the specifications publish, so passing
 * them means custody agrees with every other wallet in the world.
 *
 *   BIP-39   — the Trezor English vectors, passphrase "TREZOR".
 *   BIP-32   — test vector 1, the canonical `000102…0f` seed.
 *   BIP-44   — the "abandon…about" mnemonic at m/44'/60'/0'/0/0, which is the address every EVM
 *              wallet in existence produces for it.
 *   SLIP-0010— ed25519 test vector 1, because Solana's curve has its own derivation and BIP-32 does
 *              not apply to it at all.
 */

import assert from 'node:assert/strict'
import test from 'node:test'
import { HDKey } from '@scure/bip32'
import { mnemonicToSeedSync } from '@scure/bip39'
import * as bitcoin from 'bitcoinjs-lib'
import { deriveKey, derivationPath, coinTypeFor, isValidMnemonic, newMnemonic, seedFromMnemonic, slip10FromPath } from './hd.ts'
import {
  ECPair,
  assetForChain,
  bitcoinAddressKind,
  bitcoinNetwork,
  expectedEvmChainId,
  familyForChain,
  generateFlatRandom,
  isKnownChain,
  isLegacyGasOnlyChain,
} from './chains.ts'

/* ------------------------------------------------------------------ BIP-39 */

/** The first of the Trezor English vectors, which is the one every implementation quotes. */
const BIP39_VECTOR = {
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  seed:
    'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141' +
    '630c7a3c4ab7c81b2f001698e7463b04',
} as const

test('BIP-39: the published mnemonic-to-seed vector', () => {
  const seed = Buffer.from(mnemonicToSeedSync(BIP39_VECTOR.mnemonic, 'TREZOR')).toString('hex')
  assert.equal(seed, BIP39_VECTOR.seed)
})

test('BIP-39: this service derives with an EMPTY passphrase, and that is the documented rule', () => {
  // Stated as a test because it is the one thing a user restoring elsewhere must know. A
  // platform-held passphrase would be a second secret to back up that adds nothing an attacker who
  // has the first does not already have.
  const mnemonic = BIP39_VECTOR.mnemonic
  assert.equal(
    seedFromMnemonic(mnemonic).toString('hex'),
    Buffer.from(mnemonicToSeedSync(mnemonic, '')).toString('hex'),
  )
  assert.notEqual(seedFromMnemonic(mnemonic).toString('hex'), BIP39_VECTOR.seed)
})

test('BIP-39: a generated mnemonic is 24 words and validates', () => {
  const mnemonic = newMnemonic()
  assert.equal(mnemonic.split(' ').length, 24)
  assert.equal(isValidMnemonic(mnemonic), true)
  assert.equal(isValidMnemonic('not a mnemonic at all'), false)
})

/* ------------------------------------------------------------------ BIP-32 */

const BIP32_SEED = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')

test('BIP-32: test vector 1, chain m', () => {
  const master = HDKey.fromMasterSeed(new Uint8Array(BIP32_SEED))
  assert.equal(
    master.privateExtendedKey,
    'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
  )
  assert.equal(
    master.publicExtendedKey,
    'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
  )
})

test("BIP-32: test vector 1, chain m/0'", () => {
  const node = HDKey.fromMasterSeed(new Uint8Array(BIP32_SEED)).derive("m/0'")
  assert.equal(
    node.privateExtendedKey,
    'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
  )
})

/* ------------------------------------------------------------------ BIP-44 */

const ABANDON = BIP39_VECTOR.mnemonic

test("BIP-44: m/44'/60'/0'/0/0 of the abandon mnemonic is the address every EVM wallet produces", () => {
  const seed = seedFromMnemonic(ABANDON)
  const derived = deriveKey(seed, 'evm', 'mainnet', 0, 'ethereum')
  assert.equal(derived.derivationPath, "m/44'/60'/0'/0/0")
  assert.equal(derived.address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94')
})

test("BIP-44: m/44'/60'/0'/0/1 and /2 of the abandon mnemonic", () => {
  const seed = seedFromMnemonic(ABANDON)
  assert.equal(deriveKey(seed, 'evm', 'mainnet', 1, 'ethereum').address, '0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0')
  assert.equal(deriveKey(seed, 'evm', 'mainnet', 2, 'ethereum').address, '0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A')
})

test("BIP-44: bitcoin mainnet is coin type 0 and testnet is 1 — the published m/44'/0'/0'/0/0 P2WPKH", () => {
  const seed = seedFromMnemonic(ABANDON)
  const mainnet = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'bitcoin')
  assert.equal(mainnet.derivationPath, "m/44'/0'/0'/0/0")
  assert.equal(mainnet.address.startsWith('bc1'), true)
  const testnet = deriveKey(seed, 'bitcoin', 'testnet', 0, 'bitcoin')
  assert.equal(testnet.derivationPath, "m/44'/1'/0'/0/0")
  assert.equal(testnet.address.startsWith('tb1'), true)
})

/* ------------------------------------------------------------------ SLIP-0010 */

test('SLIP-0010 ed25519: test vector 1, chain m', () => {
  const node = slip10FromPath(BIP32_SEED, 'm')
  assert.equal(node.key.toString('hex'), '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7')
  assert.equal(node.chainCode.toString('hex'), '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb')
})

test("SLIP-0010 ed25519: test vector 1, chain m/0'", () => {
  const node = slip10FromPath(BIP32_SEED, "m/0'")
  assert.equal(node.key.toString('hex'), '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3')
  assert.equal(node.chainCode.toString('hex'), '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69')
})

test("SLIP-0010 ed25519: test vector 1, chain m/0'/1'/2'/2'/1000000000'", () => {
  const node = slip10FromPath(BIP32_SEED, "m/0'/1'/2'/2'/1000000000'")
  assert.equal(node.key.toString('hex'), '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793')
})

test('SLIP-0010 ed25519 refuses a non-hardened element, because the curve has no such derivation', () => {
  assert.throws(() => slip10FromPath(BIP32_SEED, 'm/0'), /not hardened/)
})

test("solana derives under SLIP-0010 at m/44'/501'/<index>'/0'", () => {
  const seed = seedFromMnemonic(ABANDON)
  const derived = deriveKey(seed, 'solana', 'mainnet', 0, 'solana')
  assert.equal(derived.derivationPath, "m/44'/501'/0'/0'")
  // The 64-byte secret key, base64 — the same storage form the legacy scheme uses, so `signing.ts`
  // never learns which scheme produced the key it was handed.
  assert.equal(Buffer.from(derived.privateKey, 'base64').length, 64)
  assert.notEqual(deriveKey(seed, 'solana', 'mainnet', 1, 'solana').address, derived.address)
})

/* ------------------------------------------------------------------ the XRP network fix */

test('THE XRP FIX: testnet and mainnet derive DIFFERENT accounts from one seed', () => {
  // SD-09's named defect is that XRP testnet and mainnet "share a seed and address, so one signed
  // Payment is submittable on either". BIP-44 assigns coin type 1 to testnet, so the two networks
  // are different accounts and a testnet Payment replayed on mainnet draws on an account that has
  // never existed there.
  const seed = seedFromMnemonic(ABANDON)
  const mainnet = deriveKey(seed, 'xrp', 'mainnet', 0, 'xrp')
  const testnet = deriveKey(seed, 'xrp', 'testnet', 0, 'xrp')
  assert.equal(mainnet.derivationPath, "m/44'/144'/0'/0/0")
  assert.equal(testnet.derivationPath, "m/44'/1'/0'/0/0")
  assert.notEqual(mainnet.address, testnet.address)
  assert.notEqual(mainnet.privateKey, testnet.privateKey)
})

/** Every (family, chain) pair this service mints under. The chain is the authority, not the family. */
const FAMILY_CHAINS = [
  ['evm', 'ethereum'],
  ['evm', 'ethereum-classic'],
  ['ember', 'ember'],
  ['bitcoin', 'bitcoin'],
  ['bitcoin', 'litecoin'],
  ['bitcoin', 'dogecoin'],
  ['solana', 'solana'],
  ['xrp', 'xrp'],
] as const

test('every family separates its two networks by coin type', () => {
  for (const [family, chain] of FAMILY_CHAINS) {
    assert.equal(coinTypeFor(family, 'testnet', chain), 1)
    assert.notEqual(coinTypeFor(family, 'mainnet', chain), 1)
    assert.notEqual(
      derivationPath(family, 'mainnet', 0, chain),
      derivationPath(family, 'testnet', 0, chain),
    )
  }
})

test('derivation is deterministic — the same seed and index always give the same address', () => {
  const seed = seedFromMnemonic(ABANDON)
  for (const [family, chain] of FAMILY_CHAINS) {
    assert.equal(
      deriveKey(seed, family, 'mainnet', 5, chain).address,
      deriveKey(seed, family, 'mainnet', 5, chain).address,
    )
    assert.notEqual(
      deriveKey(seed, family, 'mainnet', 5, chain).address,
      deriveKey(seed, family, 'mainnet', 6, chain).address,
    )
  }
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * LITECOIN — and the question is not "does this produce an address" but "is it a LITECOIN one".
 *
 * `ChainFamily` for LTC is `'bitcoin'`, which is correct: Litecoin genuinely shares Bitcoin's
 * transaction and script structure, which is why one settlement adapter and one PSBT signer serve
 * both. But it means the family CANNOT distinguish them, and before this change nothing did — so an
 * LTC deposit address was a `bc1…` Bitcoin address derived at Bitcoin's coin type.
 *
 * That failure mode is the reason these tests are structural rather than a single vector match. It
 * produces a well-formed address with a valid checksum, nothing throws, and the loss is discovered
 * either by a user whose deposit never arrives or by one restoring from a recovery phrase and
 * finding the funds at a path no Litecoin wallet looks in. So each property is asserted separately
 * and each is one an independent implementation could check:
 *
 *   1. the human-readable part is Litecoin's, not Bitcoin's;
 *   2. the WIF version byte is Litecoin's, so the key is stored as a Litecoin key;
 *   3. the BIP-44 coin type is SLIP-0044's 2, not Bitcoin's 0;
 *   4. the underlying key is a perfectly ordinary secp256k1 key — the SAME pubkey hash Bitcoin's
 *      parameters would encode — which is what proves only the ENCODING differs and no arithmetic
 *      was invented;
 *   5. the address does not decode under Bitcoin's parameters at all, and vice versa.
 *
 * The one published vector available is asserted too, from Trezor's own device tests.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/**
 * Trezor's default test mnemonic, and the address its firmware test pins for Litecoin BIP-44.
 *
 * `tests/device_tests/bitcoin/test_getaddress.py::test_ltc` in `trezor/trezor-firmware`, with the
 * mnemonic from `tests/conftest.py`. A PUBLISHED vector rather than one computed here, which is the
 * whole of its value: a vector this repository generated would agree with any mistake this
 * repository makes. It pins a LEGACY P2PKH address, so it is checked through the same derived key
 * rather than through `deriveKey`'s P2WPKH output — the key is the claim, the encoding is a choice.
 */
const TREZOR_ALL = 'all all all all all all all all all all all all'
const TREZOR_LTC_P2PKH = 'LcubERmHD31PWup1fbozpKuiqjHZ4anxcL'

test('LITECOIN: the published Trezor vector for m/44\'/2\'/0\'/0/0', () => {
  const node = HDKey.fromMasterSeed(new Uint8Array(seedFromMnemonic(TREZOR_ALL))).derive(
    "m/44'/2'/0'/0/0",
  )
  const pubkey = Buffer.from(node.publicKey!)
  const legacy = bitcoin.payments.p2pkh({ pubkey, network: bitcoinNetwork('litecoin', 'mainnet') })
  assert.equal(legacy.address, TREZOR_LTC_P2PKH)
  // And the same key under BITCOIN's parameters is a different address entirely, which is the
  // whole point: one key, two encodings, and only one of them is Litecoin.
  const asBitcoin = bitcoin.payments.p2pkh({ pubkey, network: bitcoinNetwork('bitcoin', 'mainnet') })
  assert.notEqual(asBitcoin.address, TREZOR_LTC_P2PKH)
  assert.ok(legacy.address!.startsWith('L'), 'a Litecoin P2PKH address begins with L')
  assert.ok(asBitcoin.address!.startsWith('1'), 'a Bitcoin P2PKH address begins with 1')
})

test('LITECOIN: the address this service mints is ltc1 on mainnet and tltc1 on testnet', () => {
  const seed = seedFromMnemonic(ABANDON)
  const mainnet = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'litecoin')
  const testnet = deriveKey(seed, 'bitcoin', 'testnet', 0, 'litecoin')

  assert.ok(mainnet.address.startsWith('ltc1'), `expected ltc1…, got ${mainnet.address}`)
  assert.ok(testnet.address.startsWith('tltc1'), `expected tltc1…, got ${testnet.address}`)
  // NOT Bitcoin's. Stated as its own assertion because `startsWith('ltc1')` would still pass if
  // the prefix were somehow both, and because this is the exact symptom of the bug being fixed.
  assert.equal(mainnet.address.startsWith('bc1'), false)
  assert.equal(testnet.address.startsWith('tb1'), false)
})

test('LITECOIN: the WIF carries Litecoin version byte, which IS the network binding', () => {
  const seed = seedFromMnemonic(ABANDON)
  const ltc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'litecoin')
  const btc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'bitcoin')

  // 176 (0xb0) → a compressed Litecoin WIF begins with 'T'. Bitcoin's 128 gives 'K' or 'L'.
  assert.ok(ltc.privateKey.startsWith('T'), `expected a T… WIF, got ${ltc.privateKey.slice(0, 1)}…`)
  assert.ok(/^[KL]/.test(btc.privateKey), 'a Bitcoin compressed WIF begins with K or L')

  // The binding is not decorative: importing one under the other's parameters THROWS, which is what
  // stops a Litecoin key ever being used to satisfy a Bitcoin request.
  assert.throws(() => ECPair.fromWIF(ltc.privateKey, bitcoinNetwork('bitcoin', 'mainnet')))
  assert.throws(() => ECPair.fromWIF(btc.privateKey, bitcoinNetwork('litecoin', 'mainnet')))
  // And each imports fine under its own.
  assert.ok(ECPair.fromWIF(ltc.privateKey, bitcoinNetwork('litecoin', 'mainnet')))
  assert.ok(ECPair.fromWIF(btc.privateKey, bitcoinNetwork('bitcoin', 'mainnet')))
})

test("LITECOIN: coin type is SLIP-0044's 2, so BTC and LTC are different keys from one seed", () => {
  const seed = seedFromMnemonic(ABANDON)
  const ltc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'litecoin')
  const btc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'bitcoin')

  assert.equal(ltc.derivationPath, "m/44'/2'/0'/0/0")
  assert.equal(btc.derivationPath, "m/44'/0'/0'/0/0")
  // DIFFERENT KEYS, not merely different encodings of one. This is what a recovery phrase depends
  // on: a wallet restoring the phrase looks under m/44'/2' for Litecoin and would find nothing if
  // the funds sat at Bitcoin's path.
  assert.notEqual(ltc.privateKey, btc.privateKey)
  assert.notEqual(ltc.address, btc.address)

  // Testnet is 1 for every coin, so LTC and BTC testnet SHARE a coin type — and that is correct
  // rather than a collision, because the address index is allocated per seed and never reused.
  assert.equal(deriveKey(seed, 'bitcoin', 'testnet', 0, 'litecoin').derivationPath, "m/44'/1'/0'/0/0")
  assert.equal(deriveKey(seed, 'bitcoin', 'testnet', 0, 'bitcoin').derivationPath, "m/44'/1'/0'/0/0")
})

test('LITECOIN: only the encoding differs — the pubkey hash is the same twenty bytes', () => {
  /*
   * The check that says no arithmetic was invented. Take ONE derived key and encode it under both
   * chains' parameters: the witness programs must be byte-identical, because a P2WPKH address is
   * just hash160(pubkey) wrapped in a chain-specific HRP. If these differed, something other than
   * the encoding would be chain-dependent, and that is the class of mistake that produces an
   * address nobody holds the key to.
   */
  const seed = seedFromMnemonic(ABANDON)
  const node = HDKey.fromMasterSeed(new Uint8Array(seed)).derive("m/44'/2'/0'/0/0")
  const pubkey = Buffer.from(node.publicKey!)

  const asLtc = bitcoin.payments.p2wpkh({ pubkey, network: bitcoinNetwork('litecoin', 'mainnet') })
  const asBtc = bitcoin.payments.p2wpkh({ pubkey, network: bitcoinNetwork('bitcoin', 'mainnet') })

  assert.deepEqual(asLtc.hash, asBtc.hash, 'the witness program must be the same twenty bytes')
  assert.notEqual(asLtc.address, asBtc.address, 'and the encodings must still differ')
  assert.ok(asLtc.address!.startsWith('ltc1q'))
  assert.ok(asBtc.address!.startsWith('bc1q'))
})

test('LITECOIN: an address of one chain does not decode as the other', () => {
  const seed = seedFromMnemonic(ABANDON)
  const ltc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'litecoin').address
  const btc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'bitcoin').address

  // `toOutputScript` is what `assertSweepOutputs` turns a treasury pin into. A pin from the wrong
  // chain must THROW there rather than silently matching nothing, so this is the property that
  // makes a cross-chain sweep pin a refusal instead of a sweep that pays nobody.
  assert.throws(() => bitcoin.address.toOutputScript(ltc, bitcoinNetwork('bitcoin', 'mainnet')))
  assert.throws(() => bitcoin.address.toOutputScript(btc, bitcoinNetwork('litecoin', 'mainnet')))
  assert.ok(bitcoin.address.toOutputScript(ltc, bitcoinNetwork('litecoin', 'mainnet')))
  assert.ok(bitcoin.address.toOutputScript(btc, bitcoinNetwork('bitcoin', 'mainnet')))
})

test('LITECOIN: a bitcoin-family chain with no parameters is refused, never defaulted to Bitcoin', () => {
  /*
   * The next chain added to `CHAIN_ASSET` without its own entry in `BITCOIN_FAMILY_CHAINS` must fail
   * loudly at derivation. A default of Bitcoin's parameters is exactly the bug this whole change
   * fixes, one family later, and it would be silent again.
   *
   * The stand-in used to be `dogecoin`, which stopped being a chain with no parameters when DOGE was
   * added — at which point this test would have passed only because Bitcoin Cash still has none. It
   * is `bitcoincash` now, and the next person to add that chain has to move this fixture again
   * rather than delete the assertion, because the assertion is the whole test.
   */
  assert.throws(() => bitcoinNetwork('bitcoincash', 'mainnet'), /no bitcoin-family network parameters/)
  const seed = seedFromMnemonic(ABANDON)
  assert.throws(() => deriveKey(seed, 'bitcoin', 'mainnet', 0, 'bitcoincash'), /no bitcoin-family/)
  assert.throws(() => generateFlatRandom('bitcoin', 'mainnet', 'bitcoincash'), /no bitcoin-family/)
})

test('LITECOIN: a flat-random key is Litecoin too, so the legacy scheme cannot mint a Bitcoin address', () => {
  // `flat_random` is reachable only by explicit request, but it IS reachable, and a scheme that
  // quietly minted a Bitcoin address under a Litecoin label would reintroduce the whole defect
  // through the one door nobody tests.
  const flat = generateFlatRandom('bitcoin', 'mainnet', 'litecoin')
  assert.ok(flat.address.startsWith('ltc1'), `expected ltc1…, got ${flat.address}`)
  assert.ok(flat.privateKey.startsWith('T'), 'the WIF must carry Litecoin version byte')
})

test('LITECOIN: custody accepts the chain, and resolves it to the bitcoin family', () => {
  /*
   * The registry entry itself, asserted because dropping it is a silent regression: `provisionAddress`
   * answers `unknown_chain` for a chain absent from `CHAIN_ASSET`, so removing this line turns every
   * LTC deposit-address request into a 400 that reads like a caller error rather than a missing
   * capability. Nothing else in this file would notice.
   */
  assert.equal(isKnownChain('litecoin'), true)
  assert.equal(assetForChain('litecoin'), 'LTC')
  // The FAMILY is bitcoin, and that is correct rather than a bug — Litecoin shares Bitcoin's
  // transaction and script structure, which is why one signer and one settlement adapter serve
  // both. It is also exactly why the family is not enough to derive with.
  assert.equal(familyForChain('litecoin'), 'bitcoin')
  assert.equal(familyForChain('bitcoin'), 'bitcoin')

  // And it has no EVM chain id, so a signing request for it can never be mistaken for one.
  assert.equal(expectedEvmChainId('litecoin', 'mainnet'), null)
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * DOGECOIN — the same question as Litecoin's, plus one Litecoin never raised: WHICH KIND OF
 * ADDRESS.
 *
 * Litecoin could be got wrong only in its bytes; the shape was Bitcoin's, so `p2wpkh` was right for
 * it. Dogecoin has no segwit at all, so a P2WPKH derivation is not merely encoded under the wrong
 * parameters — it is an address of a kind the chain has never had a consensus rule for. And it does
 * not fail: measured 2026-08-09 against the pinned `bitcoinjs-lib`, `payments.p2wpkh` with an empty
 * HRP returned `1q50rtrmj2f8vl9tem8qpfw36ylw5jg9j2jp6y70` rather than throwing. So "it produced a
 * string" proves nothing here and the assertions below are about the STRUCTURE of what it produced.
 *
 * Unlike Litecoin, a published key→address vector exists in the chain's OWN repository, so the
 * primary assertion is a vector match rather than a set of structural properties.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/**
 * Dogecoin Core's own key test vectors: `src/test/key_tests.cpp` in `dogecoin/dogecoin`, read at
 * `master` on 2026-08-09.
 *
 * `strSecret1C`/`addr1C` and `strSecret2C`/`addr2C` are the compressed pairs, `strSecret1`/`addr1`
 * the uncompressed one. They are a PUBLISHED vector from the chain being encoded for, which is the
 * whole of their value — a vector this repository computed would agree with any mistake this
 * repository makes, and the Litecoin block above had to fall back on structural properties for
 * exactly the want of one.
 *
 * They exercise both directions at once: `fromWIF` has to accept version byte 158, and the P2PKH
 * encoder has to emit version byte 30, or the address comes out wrong.
 */
const DOGE_CORE_VECTORS = [
  { wif: 'QP8WvtVMV2iU6y7LE27ksRspp4MAJizPWYovx88W71g1nfSdAhkV', address: 'D8jZ6R8uuyQwiybupiVs3eDCedKdZ5bYV3' },
  { wif: 'QTuro8Pwx5yaonvJmU4jbBfwuEmTViyAGNeNyfnG82o7HWJmnrLj', address: 'DP7rGcDbpAvMb1dKup981zNt1heWUuVLP7' },
  { wif: '6JFPe8b4jbpup7petSB98M8tcaqXCigji8fGrC8bEbbDQxQkQ68', address: 'DSpgzjPyfQB6ZzeSbMWpaZiTTxGf2oBCs4' },
] as const

test("DOGECOIN: Dogecoin Core's own published WIF-to-address vectors", () => {
  const net = bitcoinNetwork('dogecoin', 'mainnet')
  for (const { wif, address } of DOGE_CORE_VECTORS) {
    const pubkey = Buffer.from(ECPair.fromWIF(wif, net).publicKey)
    assert.equal(bitcoin.payments.p2pkh({ pubkey, network: net }).address, address)
  }
  // And none of those WIFs is importable under Bitcoin's or Litecoin's parameters, which is the
  // network binding: version byte 158 is neither 128 nor 176 and `fromWIF` compares it.
  for (const { wif } of DOGE_CORE_VECTORS) {
    assert.throws(() => ECPair.fromWIF(wif, bitcoinNetwork('bitcoin', 'mainnet')))
    assert.throws(() => ECPair.fromWIF(wif, bitcoinNetwork('litecoin', 'mainnet')))
  }
})

test('DOGECOIN: the address this service mints is base58 P2PKH, never bech32', () => {
  const seed = seedFromMnemonic(ABANDON)
  const mainnet = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'dogecoin')
  const testnet = deriveKey(seed, 'bitcoin', 'testnet', 0, 'dogecoin')

  // Version byte 30 → `D`, version byte 113 → `n` (or `m`). Both are asserted through a decode as
  // well as through the leading character, because the leading character alone is a property of the
  // first byte and the decode is a property of all twenty-five.
  assert.equal(bitcoinAddressKind('dogecoin'), 'p2pkh')
  assert.ok(mainnet.address.startsWith('D'), `expected a D… address, got ${mainnet.address}`)
  assert.ok(/^[mn]/.test(testnet.address), `expected an m…/n… address, got ${testnet.address}`)
  assert.ok(bitcoin.address.toOutputScript(mainnet.address, bitcoinNetwork('dogecoin', 'mainnet')))
  assert.ok(bitcoin.address.toOutputScript(testnet.address, bitcoinNetwork('dogecoin', 'testnet')))

  // THE ASSERTION THIS WHOLE BLOCK EXISTS FOR. A bech32 address on Dogecoin is unspendable, and the
  // failure is silent at derivation — it surfaces as a deposit nobody can move.
  assert.equal(mainnet.address.startsWith('doge1'), false)
  assert.equal(mainnet.address.startsWith('bc1'), false)
  assert.equal(testnet.address.startsWith('tb1'), false)
  assert.equal(mainnet.address.startsWith('1q'), false, 'the empty-HRP bogus form must never appear')
})

test('DOGECOIN: the flat-random scheme mints the same kind of address as derivation', () => {
  // Two code paths build an address and only one of them is exercised by the derivation tests. When
  // they were separate `p2wpkh` calls, adding a chain meant remembering both.
  const flat = generateFlatRandom('bitcoin', 'mainnet', 'dogecoin')
  assert.ok(flat.address.startsWith('D'), `expected a D… address, got ${flat.address}`)
  assert.ok(flat.privateKey.startsWith('Q'), 'a Dogecoin compressed WIF begins with Q')
  assert.ok(ECPair.fromWIF(flat.privateKey, bitcoinNetwork('dogecoin', 'mainnet')))
})

test("DOGECOIN: coin type is SLIP-0044's 3, so DOGE, BTC and LTC are three keys from one seed", () => {
  const seed = seedFromMnemonic(ABANDON)
  const doge = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'dogecoin')
  const btc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'bitcoin')
  const ltc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'litecoin')

  assert.equal(doge.derivationPath, "m/44'/3'/0'/0/0")
  assert.equal(coinTypeFor('bitcoin', 'mainnet', 'dogecoin'), 3)
  // Distinct KEYS, not merely distinct encodings — which is what a recovery phrase depends on. A
  // wallet restoring the phrase looks under m/44'/3' for Dogecoin and would find nothing there.
  assert.equal(new Set([doge.privateKey, btc.privateKey, ltc.privateKey]).size, 3)
})

test('DOGECOIN: only the encoding differs — the pubkey hash is the same twenty bytes as Bitcoin', () => {
  /*
   * The check that says no arithmetic was invented, in the form the P2PKH kind allows: take ONE
   * derived key and encode it under Dogecoin's and Bitcoin's parameters, and the hash160 must be
   * identical. If it were not, something other than the encoding would be chain-dependent, which is
   * the class of mistake that produces an address nobody holds the key to.
   */
  const node = HDKey.fromMasterSeed(new Uint8Array(seedFromMnemonic(ABANDON))).derive("m/44'/3'/0'/0/0")
  const pubkey = Buffer.from(node.publicKey!)

  const asDoge = bitcoin.payments.p2pkh({ pubkey, network: bitcoinNetwork('dogecoin', 'mainnet') })
  const asBtc = bitcoin.payments.p2pkh({ pubkey, network: bitcoinNetwork('bitcoin', 'mainnet') })

  assert.deepEqual(asDoge.hash, asBtc.hash, 'the pubkey hash must be the same twenty bytes')
  assert.notEqual(asDoge.address, asBtc.address, 'and the encodings must still differ')
  assert.ok(asDoge.address!.startsWith('D'))
  assert.ok(asBtc.address!.startsWith('1'))
})

test('DOGECOIN: an address of one chain does not decode as the other', () => {
  const seed = seedFromMnemonic(ABANDON)
  const doge = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'dogecoin').address
  const btc = deriveKey(seed, 'bitcoin', 'mainnet', 0, 'bitcoin').address

  // `toOutputScript` is what `assertSweepOutputs` turns a treasury pin into, so this is the property
  // that makes a cross-chain sweep pin a refusal instead of a sweep that pays nobody.
  assert.throws(() => bitcoin.address.toOutputScript(doge, bitcoinNetwork('bitcoin', 'mainnet')))
  assert.throws(() => bitcoin.address.toOutputScript(btc, bitcoinNetwork('dogecoin', 'mainnet')))
})

test('DOGECOIN: custody accepts the chain, and resolves it to the bitcoin family', () => {
  // The registry entry itself. Dropping it turns every DOGE deposit-address request into a 400 that
  // reads like a caller error rather than a missing capability, and nothing else here would notice.
  assert.equal(isKnownChain('dogecoin'), true)
  assert.equal(assetForChain('dogecoin'), 'DOGE')
  assert.equal(familyForChain('dogecoin'), 'bitcoin')
  // No EVM chain id, so a signing request for it can never be mistaken for one.
  assert.equal(expectedEvmChainId('dogecoin', 'mainnet'), null)
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * ETHEREUM CLASSIC — identical to Ethereum in every byte of its address format, and different in
 * the two things that decide whether a signature is valid: the chain id and the gas fields.
 *
 * There is nothing to derive differently, which is exactly why these tests exist. The failure here
 * is not a malformed address, it is a WELL-FORMED transaction that no ETC node will accept, or an
 * ETH key and an ETC key that turn out to be one key.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

test("ETC: coin type is SLIP-0044's 61, so an ETC key is not the user's ETH key", () => {
  const seed = seedFromMnemonic(ABANDON)
  const etc = deriveKey(seed, 'evm', 'mainnet', 0, 'ethereum-classic')
  const eth = deriveKey(seed, 'evm', 'mainnet', 0, 'ethereum')

  assert.equal(etc.derivationPath, "m/44'/61'/0'/0/0")
  assert.equal(eth.derivationPath, "m/44'/60'/0'/0/0")
  assert.equal(coinTypeFor('evm', 'mainnet', 'ethereum-classic'), 61)
  // Without the CHAIN_COIN_TYPE override these would be the same key, the same address and the same
  // private key, because the family is `'evm'` for both. A phrase exported from here would then
  // restore ETC funds into a wallet that shows them under Ethereum.
  assert.notEqual(etc.address, eth.address)
  assert.notEqual(etc.privateKey, eth.privateKey)

  // 61 here is SLIP-0044's coin type. That it equals ETC's EIP-155 chain id is a coincidence of two
  // separate registries, and the chain id is read from `chainSpec` and never from this path.
  assert.equal(expectedEvmChainId('ethereum-classic', 'mainnet'), 61)
  assert.equal(expectedEvmChainId('ethereum-classic', 'testnet'), 63)
})

test('ETC: testnet takes coin type 1 like every other chain', () => {
  // `ethereum-lists/chains` gives Mordor `"slip44": 1` in `eip155-63.json`, which is the same rule
  // `coinTypeFor` already applies to everything, so ETC needs no testnet special case. Asserted so
  // that adding one later is a visible decision.
  assert.equal(coinTypeFor('evm', 'testnet', 'ethereum-classic'), 1)
  const seed = seedFromMnemonic(ABANDON)
  assert.equal(deriveKey(seed, 'evm', 'testnet', 0, 'ethereum-classic').derivationPath, "m/44'/1'/0'/0/0")
})

test('ETC: custody accepts the chain, resolves it to the evm family, and marks it legacy-gas-only', () => {
  assert.equal(isKnownChain('ethereum-classic'), true)
  assert.equal(assetForChain('ethereum-classic'), 'ETC')
  assert.equal(familyForChain('ethereum-classic'), 'evm')

  // THE ONE THAT WOULD OTHERWISE BE WRONG. ETC's family is `'evm'`, the same as Ethereum's, and the
  // signing policy used to read the family — so ETC would have been told EIP-1559 was acceptable on
  // a chain that never adopted London (ECIP-1104 omits it explicitly). The refusal has to be keyed
  // by chain, and EMBER must keep its own.
  assert.equal(isLegacyGasOnlyChain('ethereum-classic'), true)
  assert.equal(isLegacyGasOnlyChain('ember'), true)
  assert.equal(isLegacyGasOnlyChain('ethereum'), false)
})
