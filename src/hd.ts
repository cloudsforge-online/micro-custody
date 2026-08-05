/**
 * Hierarchical-deterministic derivation: BIP-39 → BIP-32 / SLIP-0010 → BIP-44.
 *
 * WHY THIS EXISTS. Every address in the service custody supersedes is one flat random key with no
 * seed and no mnemonic (SD-07 context). That has two consequences and both are bad: a user cannot
 * be offered a recovery phrase, and a lost blob is a lost key with no derivation to recompute it
 * from. New addresses are derived from a per-(user, family) BIP-39 seed instead.
 *
 * TWO SCHEMES COEXIST PERMANENTLY. 04-domain-model §3.3, and SDR-08: legacy `flat_random` rows were
 * generated without a seed and cannot be retrofitted with one — deriving a new key would produce a
 * DIFFERENT address, so "migrating" a row means abandoning the coins at the old one. So they stay
 * flat, they stay signable, and every custody response states `scheme` because it is what decides
 * which export formats can honestly be offered.
 *
 * THE NETWORK IS IN THE PATH, AND THAT IS THE XRP FIX. BIP-44 assigns coin type 1 to the testnet of
 * every chain, so `m/44'/1'/…` and `m/44'/144'/…` are different keys and therefore different
 * accounts. SD-09 records that keyvault's XRP testnet and mainnet "share a seed and address, so one
 * signed Payment is submittable on either"; under HD they cannot, because the testnet account is
 * not an account the mainnet ledger has ever heard of. The same property falls out for every other
 * family for free.
 */

import { HDKey } from '@scure/bip32'
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'
import { createHmac } from 'node:crypto'
import { ethers } from 'ethers'
import { Keypair } from '@solana/web3.js'
import * as bitcoin from 'bitcoinjs-lib'
// xrpl is CommonJS and defines ECDSA with an Object.defineProperty getter, which the CJS module
// lexer in Node 22 cannot see — `import { ECDSA }` throws at import time there (Node 24's lexer
// finds it, which is why this only failed in CI). The default import is the module.exports object
// itself under Node's CJS interop in every version, so the getter is reached at property access.
import xrpl, { Wallet as XrplWallet } from 'xrpl'
import { ECPair, bitcoinNetwork, type GeneratedKey, type KeyFamily, type KeyNetwork } from './chains.ts'

/** 256 bits of entropy, so 24 words. A 12-word phrase is fine and this is a custody service. */
const ENTROPY_BITS = 256

/**
 * SLIP-0044 coin types. **Testnet is 1 for every chain**, which is the whole network-binding
 * property — see the file header.
 *
 * `ember` takes 60 because it is an EVM chain and its keys are EVM keys; SLIP-0044 has no entry for
 * it and inventing one would be a number this estate holds alone. Two chains sharing a coin type
 * cannot collide here because the address index is allocated per SEED and never reused, so an
 * `ethereum` row and an `ember` row of one user are always at different indices.
 */
const COIN_TYPE: Readonly<Record<KeyFamily, number>> = Object.freeze({
  evm: 60,
  ember: 60,
  bitcoin: 0,
  solana: 501,
  xrp: 144,
})

/**
 * Coin types that belong to a CHAIN rather than to a family, and override the family's.
 *
 * **LITECOIN IS SLIP-0044 COIN TYPE 2 AND ITS FAMILY IS `'bitcoin'`, WHICH IS 0.** Without this
 * table an LTC key derives at `m/44'/0'/0'/0/i` — Bitcoin's path — so a user's Litecoin key and
 * their Bitcoin key are drawn from one keyspace, and a recovery phrase exported from here restores
 * the Litecoin funds nowhere any Litecoin wallet would look for them. That is a silent loss on
 * restore rather than at derivation, which makes it the worse half of the bug: the address works,
 * the deposit arrives, the sweep signs, and only a user recovering from their phrase finds out.
 *
 * Keyed by CHAIN NAME and consulted before the family, so adding a bitcoin-family chain without
 * its own coin type is a decision somebody has to make rather than a default they inherit.
 */
const CHAIN_COIN_TYPE: Readonly<Record<string, number>> = Object.freeze({
  litecoin: 2,
})

const TESTNET_COIN_TYPE = 1

/** Families whose keys are ed25519 and therefore derive under SLIP-0010, not BIP-32. */
function isEd25519(family: KeyFamily): boolean {
  return family === 'solana'
}

export function coinTypeFor(family: KeyFamily, network: KeyNetwork, chain: string): number {
  // Testnet is 1 for EVERY coin — SLIP-0044's own entry — and that is the network-binding property
  // the file header describes, so it is checked before anything chain-specific.
  if (network !== 'mainnet') return TESTNET_COIN_TYPE
  return CHAIN_COIN_TYPE[chain] ?? COIN_TYPE[family]
}

/**
 * The BIP-44 path for one address.
 *
 * ed25519 has no public-key derivation, so SLIP-0010 permits hardened children only — which is why
 * the Solana path ends `…/<index>'/0'` rather than `…/0'/0/<index>`. That is the shape the Solana
 * CLI and every Solana wallet already use, so an exported phrase restores where a user expects.
 */
export function derivationPath(
  family: KeyFamily,
  network: KeyNetwork,
  index: number,
  chain: string,
): string {
  const coin = coinTypeFor(family, network, chain)
  if (isEd25519(family)) return `m/44'/${coin}'/${index}'/0'`
  return `m/44'/${coin}'/0'/0/${index}`
}

export function newMnemonic(): string {
  return generateMnemonic(wordlist, ENTROPY_BITS)
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist)
}

/**
 * BIP-39 mnemonic → 64-byte seed.
 *
 * The passphrase is deliberately empty. A platform-held passphrase is a second secret that must be
 * backed up alongside the first and adds nothing an attacker who has the first does not already
 * have; a user-held one cannot exist, because the user does not see the phrase until export.
 */
export function seedFromMnemonic(mnemonic: string): Buffer {
  return Buffer.from(mnemonicToSeedSync(mnemonic))
}

/* ------------------------------------------------------------------ SLIP-0010 (ed25519) */

const ED25519_CURVE = 'ed25519 seed'
const HARDENED = 0x8000_0000

interface Slip10Node {
  readonly key: Buffer
  readonly chainCode: Buffer
}

/**
 * SLIP-0010 ed25519 derivation, implemented here rather than pulled in.
 *
 * It is eighteen lines and it is HMAC-SHA512 in a loop; the alternative is another dependency in
 * the one service where every dependency is a key-exfiltration opportunity. It is checked against
 * the published SLIP-0010 test vectors in `hd.test.ts`, which is the only reason writing it by hand
 * is acceptable at all.
 */
export function slip10MasterKey(seed: Buffer): Slip10Node {
  const I = createHmac('sha512', ED25519_CURVE).update(seed).digest()
  return { key: I.subarray(0, 32), chainCode: I.subarray(32) }
}

export function slip10Derive(node: Slip10Node, index: number): Slip10Node {
  if (index < HARDENED) {
    // Not a limitation to work around: ed25519 has no public-parent-to-public-child derivation, so
    // a non-hardened index is not a thing that exists.
    throw new Error('SLIP-0010 ed25519 derivation supports hardened indices only')
  }
  const data = Buffer.alloc(1 + 32 + 4)
  data[0] = 0
  node.key.copy(data, 1)
  data.writeUInt32BE(index >>> 0, 33)
  const I = createHmac('sha512', node.chainCode).update(data).digest()
  return { key: I.subarray(0, 32), chainCode: I.subarray(32) }
}

/** Walk a `m/a'/b'/…` path. Every element must be hardened. */
export function slip10FromPath(seed: Buffer, path: string): Slip10Node {
  let node = slip10MasterKey(seed)
  for (const element of path.split('/').slice(1)) {
    if (!element.endsWith("'") && !element.endsWith('h')) {
      throw new Error(`SLIP-0010 path element '${element}' is not hardened`)
    }
    node = slip10Derive(node, Number(element.slice(0, -1)) + HARDENED)
  }
  return node
}

/* ------------------------------------------------------------------ derivation */

export interface DerivedKey extends GeneratedKey {
  readonly derivationPath: string
}

/**
 * Derive the address at one index of a seed.
 *
 * The stored private-key FORM is identical to the legacy scheme's in every family — 0x-hex for EVM,
 * base64 of the 64-byte secret key for Solana, WIF for Bitcoin, a family seed for XRP — so
 * `signing.ts` never learns which scheme produced the key it was handed. That is deliberate: a
 * signer that branches on provenance is a signer with two policies.
 */
export function deriveKey(
  seed: Buffer,
  family: KeyFamily,
  network: KeyNetwork,
  index: number,
  /**
   * The chain NAME. Two families read it and both would be silently wrong without it.
   *
   * `bitcoin` needs it to pick network parameters — Litecoin's family is `'bitcoin'`, so the family
   * alone cannot distinguish `ltc1q…` from `bc1q…`. The BIP-44 coin type needs it for the same
   * reason: LTC is 2 and BTC is 0, and a shared family would have shared a keyspace.
   */
  chain: string,
): DerivedKey {
  const path = derivationPath(family, network, index, chain)

  if (isEd25519(family)) {
    const node = slip10FromPath(seed, path)
    const kp = Keypair.fromSeed(new Uint8Array(node.key))
    return {
      address: kp.publicKey.toBase58(),
      privateKey: Buffer.from(kp.secretKey).toString('base64'),
      derivationPath: path,
    }
  }

  const node = HDKey.fromMasterSeed(new Uint8Array(seed)).derive(path)
  const priv = node.privateKey
  if (!priv) throw new Error(`derivation of ${path} produced no private key`)
  const privBuf = Buffer.from(priv)

  switch (family) {
    case 'evm':
    case 'ember': {
      const w = new ethers.Wallet(ethers.hexlify(privBuf))
      return { address: w.address, privateKey: w.privateKey, derivationPath: path }
    }
    case 'bitcoin': {
      const net = bitcoinNetwork(chain, network)
      const keyPair = ECPair.fromPrivateKey(privBuf, { network: net })
      const { address } = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(keyPair.publicKey), network: net })
      return { address: address!, privateKey: keyPair.toWIF(), derivationPath: path }
    }
    case 'xrp': {
      // XRP's secret is a base58 FAMILY SEED carrying 16 bytes of entropy, not a 32-byte private
      // key, so there is no standard that maps a BIP-32 node onto one. The rule used here — the
      // first 16 bytes of the derived private key, as secp256k1 entropy — is OURS, it is
      // deterministic, and it is written down in the README because a recovery phrase that only
      // restores under an undocumented rule is not a recovery phrase.
      const w = XrplWallet.fromEntropy(Array.from(privBuf.subarray(0, 16)), { algorithm: xrpl.ECDSA.secp256k1 })
      return { address: w.classicAddress, privateKey: w.seed!, derivationPath: path }
    }
    default:
      throw new Error(`no HD derivation is defined for family '${family as string}'`)
  }
}
