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

/** bitcoinjs network for a key network. The WIF carries this, so it is checked on decrypt. */
export function bitcoinNetwork(network: KeyNetwork): bitcoin.Network {
  return network === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet
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
export function generateFlatRandom(family: KeyFamily, network: KeyNetwork): GeneratedKey {
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
      const net = bitcoinNetwork(network)
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
