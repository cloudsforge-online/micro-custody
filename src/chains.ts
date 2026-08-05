/**
 * Chains, families and flat-random key generation.
 *
 * EVERY CHAIN ID AND EVERY FAMILY COMES FROM `@cloudsforge/contracts-chain`, and nothing here
 * redefines one. That package is exact-pinned precisely so custody, wallet, settlement and the
 * indexer cannot disagree — a chain id held in two places is a signature bound to the wrong
 * network the first time one of the copies is edited. forge-keyvault held its own
 * `EMBER_CHAIN_IDS = { mainnet: 7411, testnet: 7412 }`; that constant is not reproduced, it is
 * imported.
 *
 * The `chain` request parameter stays the lowercase chain NAME rather than becoming the asset code,
 * for two reasons. It is what the rows in the service custody supersedes already carry, so an
 * adoption is a copy rather than a rewrite; and one of its values — the generic `'evm'` — has no
 * asset code by design, because it is the value that must be REFUSED at signing time (SD-09 gate
 * 3). Deleting it at creation would look tidier and would move the refusal to a place where nobody
 * would ever see it fire.
 */

import { ethers } from 'ethers'
import { Keypair } from '@solana/web3.js'
import * as bitcoin from 'bitcoinjs-lib'
import { ECPairFactory } from 'ecpair'
import * as ecc from 'tiny-secp256k1'
import { Wallet as XrplWallet } from 'xrpl'
import { chainSpec, type AssetCode, type ChainFamily, type Network } from '@cloudsforge/contracts-chain'

export type KeyFamily = ChainFamily
export type KeyNetwork = Network

export const ECPair = ECPairFactory(ecc)

/**
 * The chain names custody accepts, mapped to the asset whose spec governs them.
 *
 * `'evm'` maps to null: it names "some EVM chain, unspecified", which is a perfectly good thing for
 * an address to be minted as and an impossible thing to sign for.
 */
const CHAIN_ASSET: Readonly<Record<string, AssetCode | null>> = Object.freeze({
  ethereum: 'ETH',
  bitcoin: 'BTC',
  litecoin: 'LTC',
  solana: 'SOL',
  xrp: 'XRP',
  ember: 'EMBER',
  evm: null,
})

export function isKnownChain(chain: string): boolean {
  return Object.hasOwn(CHAIN_ASSET, chain)
}

export function assetForChain(chain: string): AssetCode | null {
  return CHAIN_ASSET[chain] ?? null
}

/** The key family for a chain name, or null if the chain is not one custody holds keys for. */
export function familyForChain(chain: string): KeyFamily | null {
  if (!isKnownChain(chain)) return null
  const asset = assetForChain(chain)
  // The generic 'evm' has no asset, and secp256k1 is the only thing that could be meant by it.
  return asset ? chainSpec(asset).family : 'evm'
}

/** Families whose keys are secp256k1 and whose payload is an EVM transaction object. */
export function isEvmFamily(family: string): boolean {
  return family === 'evm' || family === 'ember'
}

/**
 * The numeric EIP-155 chain id a signed transaction must declare, or null when there is none.
 *
 * A NULL IS NOT PERMISSION TO SKIP THE CHECK. A transaction with no bound chain id is valid on
 * every EVM network, so an address minted under the generic `'evm'` is refused outright at /sign —
 * SD-09 gate 3, carried forward from forge-keyvault, where this was the fix for a signed creation
 * being replayable on every chain the deployer happened to hold funds on.
 */
export function expectedEvmChainId(chain: string, network: KeyNetwork): number | null {
  const asset = assetForChain(chain)
  if (!asset) return null
  return chainSpec(asset).chainId?.[network] ?? null
}

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * LITECOIN'S NETWORK PARAMETERS. **A WRONG BYTE HERE LOSES CUSTOMER MONEY SILENTLY.**
 *
 * `bitcoinjs-lib` ships `networks.bitcoin` and `networks.testnet` and nothing else, so a
 * Litecoin address derived with Bitcoin's parameters is a `bc1…` address that a user is told to
 * send LTC to. That is the failure mode this whole block exists to prevent, and it is the worst
 * kind: the address is well-formed, the checksum is valid, nothing errors, and the WIF the key is
 * stored under carries Bitcoin's version byte so the sweep cannot be signed either.
 *
 * Every value below is from `litecoin-project/litecoin`, `src/chainparams.cpp`, and each is
 * commented with what it produces so a reader can check it against an address rather than against
 * a memory.
 *
 * **TWO CORRECTIONS TO WHAT "EVERYONE KNOWS", both verified against Core rather than assumed:**
 *
 *  1. **The BIP-32 version bytes are Bitcoin's**, `0x0488b21e` / `0x0488ade4` — `xpub` and `xprv`.
 *     The widely-quoted `Ltub`/`Ltpv` pair (`0x019da462` / `0x019d9cfe`) is **SLIP-0132**, a wallet
 *     DISPLAY convention, and Litecoin Core has used `xpub`/`xprv` in every tag from v0.13.2 to
 *     v0.21.4. It makes no difference to a derived address — these bytes only appear when an
 *     extended key is serialised, which this service never does — but putting SLIP-0132's values
 *     here would make any future xpub export disagree with Core.
 *  2. **Litecoin has TWO P2SH prefixes.** `SCRIPT_ADDRESS` is 5 (`3…`, shared with Bitcoin) and
 *     `SCRIPT_ADDRESS2` is 50 (`M…`). `key_io.cpp` ENCODES with 50 and DECODES both, so 50 is the
 *     right value to generate under. It is recorded for completeness only: this service derives
 *     P2WPKH and never a P2SH address.
 *
 * Native segwit is safe to derive: Litecoin activated segwit at block 1,201,536 (May 2017) and
 * Core's `DEFAULT_ADDRESS_TYPE` is `OutputType::BECH32`, so `ltc1q…` is what a Litecoin wallet
 * produces by default and what every major exchange accepts.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const LITECOIN_MAINNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Litecoin Signed Message:\n',
  // xpub / xprv — Core's, not SLIP-0132's Ltub/Ltpv. See the note above.
  bip32: { public: 0x0488b21e, private: 0x0488ade4 },
  /** `ltc1q…`. The HRP is the single most visible difference from Bitcoin's `bc1q…`. */
  bech32: 'ltc',
  /** 48 → a legacy address beginning `L`. */
  pubKeyHash: 0x30,
  /** 50 → `M`. Core encodes with this and decodes 5 as well. Unused here; P2WPKH only. */
  scriptHash: 0x32,
  /** 176 → a compressed WIF beginning `T`. Bitcoin's 128 gives `K`/`L`, so a mix-up is visible. */
  wif: 0xb0,
})

const LITECOIN_TESTNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Litecoin Signed Message:\n',
  // tpub / tprv — Core's. SLIP-0132's `ttub` pair is 0x0436f6e1 / 0x0436ef7d.
  bip32: { public: 0x043587cf, private: 0x04358394 },
  /** `tltc1q…` — distinct from Bitcoin testnet's `tb1q…`. */
  bech32: 'tltc',
  pubKeyHash: 0x6f,
  /** 58 → the SCRIPT_ADDRESS2 value; Core also decodes 196. */
  scriptHash: 0x3a,
  wif: 0xef,
})

const BITCOIN_FAMILY_NETWORKS: Readonly<Record<string, Readonly<Record<KeyNetwork, bitcoin.Network>>>> =
  Object.freeze({
    bitcoin: { mainnet: bitcoin.networks.bitcoin, testnet: bitcoin.networks.testnet },
    litecoin: { mainnet: LITECOIN_MAINNET, testnet: LITECOIN_TESTNET },
  })

/**
 * bitcoinjs network for a (chain, network). The WIF carries it, so it is checked on decrypt.
 *
 * **THE CHAIN IS A PARAMETER AND IT USED NOT TO BE**, which is the whole of the Litecoin fix.
 * `ChainFamily` for LTC is `'bitcoin'` — Litecoin really does share Bitcoin's transaction and
 * script structure, which is why one adapter serves both — so a function taking only the family
 * cannot tell them apart and answered Bitcoin's parameters for Litecoin. The result was a `bc1…`
 * address published as a Litecoin deposit address.
 *
 * **IT THROWS FOR AN UNKNOWN CHAIN RATHER THAN DEFAULTING TO BITCOIN.** A default here is the exact
 * bug being fixed, one family later: the next Bitcoin-derived chain added to `CHAIN_ASSET` would
 * silently mint Bitcoin addresses under its own name, and nothing would fail until somebody sent
 * money. Failing at derivation time costs an obvious error; failing silently costs the deposit.
 */
export function bitcoinNetwork(chain: string, network: KeyNetwork): bitcoin.Network {
  const params = BITCOIN_FAMILY_NETWORKS[chain]
  if (!params) {
    throw new Error(
      `no bitcoin-family network parameters are defined for '${chain}' — refusing to derive an ` +
        'address with another chain parameters, which would be a valid address on the wrong chain',
    )
  }
  return params[network]
}

export interface GeneratedKey {
  readonly address: string
  /** Secret material, encrypted immediately by the caller and never returned over the API. */
  readonly privateKey: string
}

/**
 * A flat random keypair — the LEGACY scheme.
 *
 * Kept, and kept working, because 04-domain-model §3.3 says the two schemes coexist permanently:
 * addresses minted before HD derivation existed have no seed and no derivation path, cannot be
 * retrofitted with one (SDR-08), and must still be signable and exportable. This function is what
 * makes "not migratable" a supported state rather than an outage.
 *
 * New addresses do not come from here — see `hd.ts`. This is reachable only when a caller asks for
 * `scheme: 'flat_random'` explicitly, which exists so the legacy path is exercised by tests rather
 * than only by rows nobody can create any more.
 */
export function generateFlatRandom(
  family: KeyFamily,
  network: KeyNetwork,
  /**
   * The CHAIN, not just the family, and only the bitcoin family reads it.
   *
   * Litecoin's family is `'bitcoin'`, so the family alone cannot select its network parameters —
   * see `bitcoinNetwork`. Required rather than optional: a default would be Bitcoin's, which is
   * precisely the wrong answer for every bitcoin-family chain that is not Bitcoin.
   */
  chain: string,
): GeneratedKey {
  switch (family) {
    case 'evm':
    case 'ember': {
      const w = ethers.Wallet.createRandom()
      return { address: w.address, privateKey: w.privateKey }
    }
    case 'solana': {
      const kp = Keypair.generate()
      return {
        address: kp.publicKey.toBase58(),
        privateKey: Buffer.from(kp.secretKey).toString('base64'),
      }
    }
    case 'bitcoin': {
      const net = bitcoinNetwork(chain, network)
      const keyPair = ECPair.makeRandom({ network: net })
      const { address } = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(keyPair.publicKey), network: net })
      // The WIF carries the network flag, so a later decrypt-and-sign stays unambiguous: a mainnet
      // key presented for a testnet request throws at `fromWIF` rather than signing.
      return { address: address!, privateKey: keyPair.toWIF() }
    }
    case 'xrp': {
      // XRP HAS NO NETWORK BYTE. A family seed generated here is valid on testnet and mainnet
      // alike, and so is the classic address it produces — which is the defect SD-09 names, and
      // which this scheme CANNOT fix: a flat random seed has nothing to fold the network into.
      // The fix lives in `hd.ts`, where the network is a BIP-44 coin type and the two networks
      // therefore produce different addresses. Legacy XRP rows keep the residual, and `signing.ts`
      // compensates with an explicit NetworkID rule.
      const w = XrplWallet.generate()
      return { address: w.classicAddress, privateKey: w.seed! }
    }
  }
}
