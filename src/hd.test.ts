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
import { deriveKey, derivationPath, coinTypeFor, isValidMnemonic, newMnemonic, seedFromMnemonic, slip10FromPath } from './hd.ts'

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
  const derived = deriveKey(seed, 'evm', 'mainnet', 0)
  assert.equal(derived.derivationPath, "m/44'/60'/0'/0/0")
  assert.equal(derived.address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94')
})

test("BIP-44: m/44'/60'/0'/0/1 and /2 of the abandon mnemonic", () => {
  const seed = seedFromMnemonic(ABANDON)
  assert.equal(deriveKey(seed, 'evm', 'mainnet', 1).address, '0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0')
  assert.equal(deriveKey(seed, 'evm', 'mainnet', 2).address, '0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A')
})

test("BIP-44: bitcoin mainnet is coin type 0 and testnet is 1 — the published m/44'/0'/0'/0/0 P2WPKH", () => {
  const seed = seedFromMnemonic(ABANDON)
  const mainnet = deriveKey(seed, 'bitcoin', 'mainnet', 0)
  assert.equal(mainnet.derivationPath, "m/44'/0'/0'/0/0")
  assert.equal(mainnet.address.startsWith('bc1'), true)
  const testnet = deriveKey(seed, 'bitcoin', 'testnet', 0)
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
  const derived = deriveKey(seed, 'solana', 'mainnet', 0)
  assert.equal(derived.derivationPath, "m/44'/501'/0'/0'")
  // The 64-byte secret key, base64 — the same storage form the legacy scheme uses, so `signing.ts`
  // never learns which scheme produced the key it was handed.
  assert.equal(Buffer.from(derived.privateKey, 'base64').length, 64)
  assert.notEqual(deriveKey(seed, 'solana', 'mainnet', 1).address, derived.address)
})

/* ------------------------------------------------------------------ the XRP network fix */

test('THE XRP FIX: testnet and mainnet derive DIFFERENT accounts from one seed', () => {
  // SD-09's named defect is that XRP testnet and mainnet "share a seed and address, so one signed
  // Payment is submittable on either". BIP-44 assigns coin type 1 to testnet, so the two networks
  // are different accounts and a testnet Payment replayed on mainnet draws on an account that has
  // never existed there.
  const seed = seedFromMnemonic(ABANDON)
  const mainnet = deriveKey(seed, 'xrp', 'mainnet', 0)
  const testnet = deriveKey(seed, 'xrp', 'testnet', 0)
  assert.equal(mainnet.derivationPath, "m/44'/144'/0'/0/0")
  assert.equal(testnet.derivationPath, "m/44'/1'/0'/0/0")
  assert.notEqual(mainnet.address, testnet.address)
  assert.notEqual(mainnet.privateKey, testnet.privateKey)
})

test('every family separates its two networks by coin type', () => {
  for (const family of ['evm', 'ember', 'bitcoin', 'solana', 'xrp'] as const) {
    assert.equal(coinTypeFor(family, 'testnet'), 1)
    assert.notEqual(coinTypeFor(family, 'mainnet'), 1)
    assert.notEqual(derivationPath(family, 'mainnet', 0), derivationPath(family, 'testnet', 0))
  }
})

test('derivation is deterministic — the same seed and index always give the same address', () => {
  const seed = seedFromMnemonic(ABANDON)
  for (const family of ['evm', 'bitcoin', 'solana', 'xrp'] as const) {
    assert.equal(deriveKey(seed, family, 'mainnet', 5).address, deriveKey(seed, family, 'mainnet', 5).address)
    assert.notEqual(deriveKey(seed, family, 'mainnet', 5).address, deriveKey(seed, family, 'mainnet', 6).address)
  }
})
