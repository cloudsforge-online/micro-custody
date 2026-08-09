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
  dogecoin: 'DOGE',
  solana: 'SOL',
  xrp: 'XRP',
  ember: 'EMBER',
  // Hyphenated, not `etc` and not `ethereumclassic`. The keys here are chain NAMES (see the file
  // header), and the rest of the estate already spells this one out with a hyphen: the node datadir
  // in `docs/ecosystem/36-multi-chain-and-mining-pool.md` is `/data/chains/ethereum-classic` and
  // pricing's CoinGecko id in `pricing/src/sources.ts` is `ethereum-classic`. wallet's URL slug is
  // the short `etc` because that side keys on the lowercased asset code; the translation between
  // the two conventions is wallet's `CUSTODY_CHAIN` table, and it is the only place they meet.
  'ethereum-classic': 'ETC',
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
 * EVM chains that accept LEGACY (type 0) transactions ONLY — no EIP-1559, no `maxFeePerGas`.
 *
 * **THIS IS KEYED BY CHAIN AND IT USED TO BE KEYED BY FAMILY.** `keys.ts` built the signing policy
 * with `legacyOnly: row.family === 'ember'`, which was correct while EMBER was the only pre-London
 * EVM chain custody held keys for. `ChainFamily` for ETC is `'evm'`, the same value Ethereum
 * carries, so the family test answers "1559 is fine" for a chain on which a type-2 transaction is
 * not a valid transaction at all.
 *
 * The failure that would cause is worth spelling out, because it is not a rejected signature. The
 * five gates would pass, the key would decrypt, ethers would happily produce a well-formed type-2
 * envelope, custody would write a signing audit row saying it had signed, and the broadcast would
 * fail at the node — leaving the platform with a recorded signature for a transaction that can
 * never confirm and a treasury withdrawal stuck behind it.
 *
 * **ETC did not adopt London.** ECIP-1104 ("Mystique", mainnet block 14,525,000, 2022-02-13)
 * activates exactly two of London's changes, EIP-3529 and EIP-3541, and its "Not Included" list
 * names EIP-1559, EIP-3198 and EIP-3228 explicitly. Verified 2026-08-09 against the ECIP texts at
 * `ethereumclassic/ECIPs`; `contracts/packages/chain` says the same thing in its ETC spec comment,
 * which is where this requirement reached custody.
 *
 * **"LEGACY-ONLY" MEANS "NOT EIP-1559", NOT "NOT TYPED".** ETC did take Berlin: ECIP-1103
 * ("Magneto", mainnet block 13,189,133, 2021-07-21) activates EIP-2718 and EIP-2930, so a type-1
 * access-list transaction is perfectly valid there. What this flag forbids is the type-2 fee model,
 * because there is no base fee for `maxFeePerGas` to be measured against. The distinction matters
 * because ethers infers type 1 for a `gasPrice` transaction unless the caller states `type: 0`, so a
 * flag that meant "type 0 only" would be describing something this service does not enforce.
 *
 * A chain that is NOT listed here is not thereby asserted to be post-London — it is only asserted
 * to accept EIP-1559, which every EVM chain does whether or not it has a base fee. The list is the
 * refusals, so adding a chain and forgetting it costs a legacy transaction on a 1559 chain (valid,
 * merely overpriced) rather than a 1559 transaction on a legacy chain (invalid, unbroadcastable).
 */
const LEGACY_GAS_ONLY_CHAINS: ReadonlySet<string> = Object.freeze(
  new Set(['ember', 'ethereum-classic']),
)

/** Whether a signed EVM transaction for this chain must be type 0. See `LEGACY_GAS_ONLY_CHAINS`. */
export function isLegacyGasOnlyChain(chain: string): boolean {
  return LEGACY_GAS_ONLY_CHAINS.has(chain)
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

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * DOGECOIN'S NETWORK PARAMETERS. **DOGECOIN HAS NO SEGWIT AND THEREFORE NO BECH32 ADDRESS.**
 *
 * Every byte below is from `dogecoin/dogecoin`, `src/chainparams.cpp`, read at `master` on
 * 2026-08-09. The mainnet block sets PUBKEY_ADDRESS 30, SCRIPT_ADDRESS 22, SECRET_KEY 158; the
 * testnet block sets 113, 196, 241. **There is no `bech32_hrp` line anywhere in that file** — not
 * for main, test or regtest — because SegWit was never activated: it exists only as a BIP-9
 * deployment whose timeout is 0, i.e. permanently off. That is not a gap in this table that someone
 * should later fill in; there is no value to fill in.
 *
 * Two differences from the Litecoin block above, both checked rather than assumed:
 *
 *  1. **The BIP-32 version bytes are Dogecoin's own**, `0x02facafd` / `0x02fac398` — `dgub`/`dgpv`.
 *     This is the opposite of Litecoin, whose Core uses Bitcoin's `xpub`/`xprv` and where the
 *     distinct `Ltub` pair is only SLIP-0132's display convention. Here Core itself carries the
 *     distinct bytes, so `dgub` is what an export would have to say to agree with the node. As with
 *     Litecoin these bytes never appear in a derived address and this service never serialises an
 *     extended key; they are correct so that a future export is correct.
 *  2. **There is no `SCRIPT_ADDRESS2`.** Litecoin has two P2SH prefixes; Dogecoin has one.
 *
 * Testnet reuses Bitcoin's `tpub`/`tprv` bytes (`0x043587cf` / `0x04358394`) — that is what the file
 * says, and it is a real collision rather than a transcription error, so it is recorded as read.
 * Note also that Dogecoin's regtest prefixes (111 / 196 / 239) are NOT its testnet ones; custody
 * has no regtest network, and this comment exists so that nobody adds one by copying these values.
 *
 * WHAT THE BYTES PRODUCE, measured 2026-08-09 by deriving with this table under the
 * `bitcoinjs-lib` version this service pins: mainnet P2PKH `DL54i6msdfchWaR7NHFA41HxSiYciTwhqW`
 * (a `D…`), mainnet P2SH `9ypNxDW…` (a `9…`), mainnet compressed WIF `QNrHeEx…` (a `Q…`), testnet
 * P2PKH `nj88S7W…` (an `n…`), testnet compressed WIF `ceyd6dr…` (a `c…`).
 *
 * **THE TESTNET WIF IS NOT VISUALLY DISTINCT FROM BITCOIN'S.** Bitcoin testnet's 239 and Dogecoin
 * testnet's 241 both yield compressed WIFs beginning `c`, so unlike the mainnet case a mix-up
 * cannot be caught by eye. It is caught instead by `ECPair.fromWIF(wif, net)`, which compares the
 * byte and throws — which is why `signing.ts` passes the chain's network in rather than decoding
 * the WIF unbound.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const DOGECOIN_MAINNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Dogecoin Signed Message:\n',
  /** dgub / dgpv — Dogecoin Core's own, unlike Litecoin. See the note above. */
  bip32: { public: 0x02facafd, private: 0x02fac398 },
  /**
   * EMPTY BECAUSE DOGECOIN HAS NO BECH32 HRP, not because one is missing. `bitcoin.Network` makes
   * the field required, so the absence has to be spelled some way, and the empty string is the only
   * value that cannot be mistaken for a real HRP.
   *
   * It is NOT a safety net. Measured 2026-08-09: `bitcoin.payments.p2wpkh` with `bech32: ''` does
   * not throw — it returned `1q50rtrmj2f8vl9tem8qpfw36ylw5jg9j2jp6y70`, a well-formed-looking string
   * that is not an address on any chain. That is why the address KIND is an explicit per-chain
   * choice below rather than something inferred from this field being blank.
   */
  bech32: '',
  /** 30 → a legacy P2PKH address beginning `D`. This is the only address kind Dogecoin has. */
  pubKeyHash: 0x1e,
  /** 22 → `9` or `A`. Recorded for completeness; this service derives P2PKH and never P2SH. */
  scriptHash: 0x16,
  /** 158 → a compressed WIF beginning `Q`. Bitcoin's 128 gives `K`/`L`, so a mix-up is visible. */
  wif: 0x9e,
})

const DOGECOIN_TESTNET: bitcoin.Network = Object.freeze({
  messagePrefix: '\x19Dogecoin Signed Message:\n',
  // tpub / tprv — Bitcoin's bytes, which is what Dogecoin Core's testnet block actually sets.
  bip32: { public: 0x043587cf, private: 0x04358394 },
  /** Still empty, and for the same reason: there is no segwit on any Dogecoin network. */
  bech32: '',
  /** 113 → an `n…`. */
  pubKeyHash: 0x71,
  /** 196 → a `2…`. Shared with Bitcoin testnet; unused here. */
  scriptHash: 0xc4,
  /** 241 → a compressed WIF beginning `c`, indistinguishable by eye from Bitcoin testnet's 239. */
  wif: 0xf1,
})

/**
 * The address kind a chain's keys are derived as.
 *
 * **THIS EXISTS BECAUSE THE FAMILY DOES NOT DETERMINE IT.** Every bitcoin-family chain custody held
 * before DOGE was segwit-capable, so `p2wpkh` was hard-coded at all three sites that build an
 * address — `generateFlatRandom` here, `deriveKey` in `hd.ts`, and the ownership check in
 * `signBitcoin`. Dogecoin has no segwit at all, so those three had to stop guessing and start
 * agreeing, which is what `bitcoinPayment` below is for: one function, three callers, so a chain
 * cannot be derived as one kind and then verified as another.
 *
 * The kind is not merely cosmetic. It decides what a PSBT input must carry (`witnessUtxo` for
 * P2WPKH, `nonWitnessUtxo` for P2PKH), which is why `signing.ts` reads it too.
 */
export type BitcoinAddressKind = 'p2wpkh' | 'p2pkh'

interface BitcoinFamilyChain {
  readonly kind: BitcoinAddressKind
  readonly networks: Readonly<Record<KeyNetwork, bitcoin.Network>>
}

const BITCOIN_FAMILY_CHAINS: Readonly<Record<string, BitcoinFamilyChain>> = Object.freeze({
  bitcoin: {
    kind: 'p2wpkh',
    networks: { mainnet: bitcoin.networks.bitcoin, testnet: bitcoin.networks.testnet },
  },
  litecoin: {
    kind: 'p2wpkh',
    networks: { mainnet: LITECOIN_MAINNET, testnet: LITECOIN_TESTNET },
  },
  // P2PKH is not a legacy preference here, it is the only option Dogecoin offers.
  dogecoin: {
    kind: 'p2pkh',
    networks: { mainnet: DOGECOIN_MAINNET, testnet: DOGECOIN_TESTNET },
  },
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
  return bitcoinFamilyChain(chain).networks[network]
}

/** The address kind for a bitcoin-family chain. Throws for an unknown chain, as `bitcoinNetwork` does. */
export function bitcoinAddressKind(chain: string): BitcoinAddressKind {
  return bitcoinFamilyChain(chain).kind
}

function bitcoinFamilyChain(chain: string): BitcoinFamilyChain {
  const params = BITCOIN_FAMILY_CHAINS[chain]
  if (!params) {
    throw new Error(
      `no bitcoin-family network parameters are defined for '${chain}' — refusing to derive an ` +
        'address with another chain parameters, which would be a valid address on the wrong chain',
    )
  }
  return params
}

/**
 * A chain name NEITHER registry in this file contains, DERIVED rather than chosen.
 *
 * ── WHY A FUNCTION SHIPS FOR SOMETHING ONLY TESTS CALL ────────────────────────────────────────
 *
 * Two assertions here need an example of "a chain this service does not hold keys for": the 400 on
 * `POST /v1/addresses` in `server.test.ts`, and the refusal-rather-than-default in `hd.test.ts`
 * that is the entire Litecoin fix. Both named a chain by hand, and both have already been edited
 * once for that reason — `dogecoin` stood in each of them until DOGE was added, at which point
 * `hd.test.ts` would have gone on passing for the wrong reason and `server.test.ts` would have
 * asserted a 400 on a chain that is now perfectly mintable. `bitcoincash` replaced it, and its own
 * comment admitted the problem: "the next person to add that chain has to move this fixture again".
 *
 * micro-org#290 adopts the derived form as the estate's answer: ask the registries at run time
 * rather than predict them at authoring time. Collision is the loop's exit condition, so there is
 * no chain this can collide with, now or ever.
 *
 * ── WHAT IT CANNOT DERIVE, WHICH IS ITSELF THE POINT ─────────────────────────────────────────
 *
 * `hd.test.ts` would ideally use a stronger fixture still: a chain that IS in `CHAIN_ASSET`, IS of
 * the bitcoin family, and has no `BITCOIN_FAMILY_CHAINS` entry — the exact shape of the next
 * mistake. No such chain can be derived, because none exists: bitcoin, litecoin and dogecoin all
 * carry their parameters. That absence is the invariant the assertion defends, so a fixture that
 * could be derived would mean the defect was already present. What is asserted instead is the
 * mechanism — `bitcoinFamilyChain` throws for a name it does not hold rather than returning
 * Bitcoin's — which is the thing that makes the stronger case fail loudly the day it can occur.
 */
export function chainOutsideEveryRegistry(): string {
  let candidate = 'aaa'
  while (isKnownChain(candidate) || Object.hasOwn(BITCOIN_FAMILY_CHAINS, candidate)) candidate += 'x'
  return candidate
}

/**
 * The single place a bitcoin-family address is built from a public key.
 *
 * Derivation (`hd.ts`), legacy generation (`generateFlatRandom`) and the ownership check in
 * `signBitcoin` all route through here, so the address a deposit is published under and the address
 * a signature is refused against are produced by the same code. When they were three separate
 * `payments.p2wpkh` calls, adding a chain meant remembering three edits, and forgetting the third
 * meant a key that mints an address it can never prove it owns.
 *
 * The `bech32` guard is defence in depth against a measured failure rather than a hypothetical one:
 * `payments.p2wpkh` with an empty HRP returns a bogus address instead of throwing (see
 * `DOGECOIN_MAINNET`), so a chain wrongly marked `p2wpkh` would otherwise mint garbage silently.
 */
export function bitcoinPayment(
  pubkey: Buffer,
  chain: string,
  network: KeyNetwork,
): { readonly address: string; readonly output: Buffer; readonly network: bitcoin.Network } {
  const { kind, networks } = bitcoinFamilyChain(chain)
  const net = networks[network]
  if (kind === 'p2wpkh' && !net.bech32) {
    throw new Error(`chain '${chain}' is marked segwit but has no bech32 HRP — refusing to derive`)
  }
  const payment =
    kind === 'p2wpkh'
      ? bitcoin.payments.p2wpkh({ pubkey, network: net })
      : bitcoin.payments.p2pkh({ pubkey, network: net })
  return { address: payment.address!, output: payment.output!, network: net }
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
      // Not `p2wpkh` directly: the kind is the chain's, and Dogecoin's is P2PKH. See `bitcoinPayment`.
      const { address } = bitcoinPayment(Buffer.from(keyPair.publicKey), chain, network)
      // The WIF carries the network flag, so a later decrypt-and-sign stays unambiguous: a mainnet
      // key presented for a testnet request throws at `fromWIF` rather than signing.
      return { address, privateKey: keyPair.toWIF() }
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
