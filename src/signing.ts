/**
 * What this service will put a signature on.
 *
 * CARRIED FORWARD, ALMOST UNCHANGED, from `forge-keyvault/src/signing.ts`. SD-09 calls it the
 * best-designed component in the estate and the reason the shared-token weakness (SD-05) has not
 * already been catastrophic: even holding the token, a caller cannot make a deposit key send funds
 * anywhere except the pinned treasury. It is a POLICY, not a signing oracle, and that distinction
 * is the whole of custody's defensibility.
 *
 * Every function here takes a decrypted key and a caller-supplied payload and refuses anything it
 * cannot fully account for. Two rules run through all four families:
 *
 *   1. The transaction must be FROM the address it was requested for. The caller's restated binding
 *      is a claim; the payload's own origin field is evidence. EVM binds the chain id, Solana the
 *      fee payer, Bitcoin every input script, XRP the Account.
 *   2. Anything not needed by a caller in this estate is refused rather than tolerated. An
 *      unexpected field is a signature nobody asked for.
 *
 * A refusal is a `SignRefused`, which the /sign route turns into 403 with a named reason and an
 * audit row. Any other throw is a real fault and reaches the error handler as a 500.
 *
 * WHY IT IS NOT MOVED TO THE POLICY SERVICE (SD-09, AD-09). A signing policy enforced by a remote
 * call is a signing policy an attacker bypasses by reaching the signer directly, or by making the
 * policy service unavailable and hoping for fail-open. The gate must be co-located with the key.
 */

import { ethers } from 'ethers'
import { Keypair, PublicKey, Transaction as SolanaTransaction, type TransactionInstruction } from '@solana/web3.js'
import * as bitcoin from 'bitcoinjs-lib'
import { Wallet as XrplWallet, type Transaction as XrplTransaction } from 'xrpl'
import { ECPair, bitcoinNetwork, type KeyNetwork } from './chains.ts'

export class SignRefused extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SignRefused'
  }
}

function refuse(message: string): never {
  throw new SignRefused(message)
}

/** Caller-supplied strings end up in error bodies, audit rows and logs — keep them short. */
function short(value: unknown): string {
  return String(value).slice(0, 64)
}

function asRecord(payload: unknown, what: string): Record<string, unknown> {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    refuse(`${what} must be an object`)
  }
  return payload as Record<string, unknown>
}

function onlyFields(obj: Record<string, unknown>, allowed: ReadonlySet<string>, what: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) refuse(`${what} carries a field this service does not sign: '${short(key)}'`)
  }
}

function parseBigInt(value: string): bigint | null {
  try {
    return BigInt(value)
  } catch {
    return null
  }
}

/** Quantities arrive as decimal strings, hex strings or numbers. All three are exact here. */
function quantity(value: unknown, field: string): bigint {
  if (typeof value === 'bigint') return value
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) refuse(`${field} is not a non-negative integer`)
    return BigInt(value)
  }
  if (typeof value === 'string' && value.length > 0) {
    const parsed = parseBigInt(value)
    if (parsed === null || parsed < 0n) refuse(`${field} is not a non-negative quantity`)
    return parsed
  }
  refuse(`${field} is required`)
}

// ── EVM ─────────────────────────────────────────────────────────────────────

const EVM_FIELDS: ReadonlySet<string> = new Set([
  'to',
  'data',
  'value',
  'nonce',
  'gasLimit',
  'chainId',
  'type',
  'maxFeePerGas',
  'maxPriorityFeePerGas',
  'gasPrice',
])

/** EIP-3860's initcode ceiling. Larger is not a contract anyone can deploy. */
const MAX_INITCODE_BYTES = 49_152
/** A real ERC-20 creation is 1–3M gas. Well above that is not a deploy, it is a gas burn. */
const MAX_DEPLOY_GAS = 8_000_000n
/**
 * A value transfer with empty calldata costs exactly 21,000 intrinsic gas, so this ceiling looks
 * absurdly generous for one. It is not: rollups fold the L1 calldata cost into the L2 gasLimit, so
 * a plain transfer on Arbitrum is quoted well above 21,000 and a hard equality here would refuse
 * every one of them. The fee ceiling below is the bound that actually bites.
 */
const MAX_TRANSFER_GAS = 200_000n
/**
 * `gasLimit × maxFee` — the most this signature can possibly cost the address it is signed for.
 * Deliberately loose: it bounds a griefing attack, it does not price a transaction. Native units
 * differ per chain (1 ETH and 1 EMBER are both "1e18 wei" here) and the looser of the two is the
 * one that matters.
 */
const MAX_FEE_WEI = 2n * 10n ** 18n
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

/**
 * The one EVM transaction shape an address of a given purpose may produce. SD-09 gate 1.
 *
 *   deployer → 'creation'. A zero-value contract creation with bounded initcode, and nothing else.
 *   treasury → 'transfer'. The platform's payout address, and nothing else.
 *   deposit  → 'sweep'.    A transfer whose destination THIS SERVICE chooses.
 *
 * The three shapes are disjoint and no address holds two of them. That is what makes `purpose`
 * load-bearing rather than cosmetic labelling: it selects a signing policy, so mislabelling an
 * address is a refusal, not a wider signature.
 *
 * WHY THE CREATION RULE IS NOT SIMPLY RELAXED. "to must be null, value must be zero" was once the
 * whole EVM policy, and it is also the reason no EVM coin could ever leave the platform — a
 * withdrawal is `to != null` with `value > 0`, precisely the shape that rule forbids. The fix is
 * not to widen it: a deployer that can also transfer value is a deployer whose whole balance is one
 * signature away. It is to make the shape a property of what the address is FOR.
 */
export type EvmShape = 'creation' | 'transfer' | 'sweep'

interface EvmPolicyBase {
  /**
   * Resolved by the caller from the address's own row and never null — an address with no chain id
   * to bind to is refused before it gets here, because a chain-id-less signature is replayable on
   * every EVM network. SD-09 gate 3.
   */
  readonly chainId: number
  /**
   * Refuse EIP-1559 outright. Ember v1 accepts legacy (type 0) transactions only and its node has
   * no type-2 decoder — a 1559 transaction signed for it is not a transaction the network rejects,
   * it is bytes nothing on that chain can even parse.
   */
  readonly legacyOnly?: boolean
}

/**
 * A discriminated union rather than one interface with an optional pin, so that `shape: 'sweep'`
 * without a pin does not compile. The pin is the entire security property of the sweep shape; a
 * caller that forgets it must fail at build time, not fall through to a runtime default.
 */
export type EvmPolicy =
  | (EvmPolicyBase & { readonly shape: 'creation' | 'transfer' })
  | (EvmPolicyBase & {
      readonly shape: 'sweep'
      /** The treasury THIS SERVICE pinned for the source address's (chain, network). */
      readonly treasuryPin: string
    })

/** EVM: sign an unsigned transaction object → serialised signed transaction hex. */
export async function signEvm(privateKey: string, payload: unknown, policy: EvmPolicy): Promise<string> {
  const tx = asRecord(payload, 'evm payload')
  onlyFields(tx, EVM_FIELDS, 'evm payload')

  if (Number(tx.chainId) !== policy.chainId) refuse(`chainId must be ${policy.chainId}`)

  const gasLimit =
    policy.shape === 'creation'
      ? assertCreation(tx)
      : policy.shape === 'sweep'
        ? assertSweep(tx, policy.treasuryPin)
        : assertTransfer(tx)

  if (!Number.isSafeInteger(tx.nonce) || (tx.nonce as number) < 0) {
    refuse('`nonce` must be a non-negative integer')
  }

  // Exactly one fee model, and `type` must agree with it. A transaction carrying both is ambiguous,
  // and ethers would silently pick one.
  const eip1559 = tx.maxFeePerGas != null || tx.maxPriorityFeePerGas != null
  const legacy = tx.gasPrice != null
  if (eip1559 === legacy) {
    refuse('set exactly one of `gasPrice` or `maxFeePerGas`+`maxPriorityFeePerGas`')
  }
  let maxFeePerGas: bigint
  if (eip1559) {
    if (policy.legacyOnly) refuse('this chain accepts legacy transactions only — use `gasPrice`')
    if (tx.type != null && Number(tx.type) !== 2) refuse('`type` must be 2 for an EIP-1559 transaction')
    maxFeePerGas = quantity(tx.maxFeePerGas, '`maxFeePerGas`')
    const tip = quantity(tx.maxPriorityFeePerGas, '`maxPriorityFeePerGas`')
    if (tip > maxFeePerGas) refuse('`maxPriorityFeePerGas` exceeds `maxFeePerGas`')
  } else {
    if (tx.type != null && Number(tx.type) !== 0) refuse('`type` must be 0 for a legacy transaction')
    maxFeePerGas = quantity(tx.gasPrice, '`gasPrice`')
  }
  if (gasLimit * maxFeePerGas > MAX_FEE_WEI) {
    refuse("the transaction's maximum fee exceeds what this service will sign")
  }

  const wallet = new ethers.Wallet(privateKey)
  return wallet.signTransaction(tx as ethers.TransactionRequest)
}

/** A zero-value contract creation with bounded initcode. Returns the gas limit. */
function assertCreation(tx: Record<string, unknown>): bigint {
  if (tx.to != null) refuse('deployer addresses may only sign contract creations — `to` must be null')

  const data = typeof tx.data === 'string' ? tx.data : ''
  if (!/^0x([0-9a-fA-F]{2})+$/.test(data)) refuse('`data` must be non-empty 0x-hex creation bytecode')
  if ((data.length - 2) / 2 > MAX_INITCODE_BYTES) {
    refuse(`creation bytecode exceeds the ${MAX_INITCODE_BYTES}-byte initcode limit`)
  }

  // Value on a creation funds the new contract out of the customer's deployer. Nothing in the
  // estate does that, so it is not a shape this service signs.
  if (quantity(tx.value ?? 0, '`value`') !== 0n) refuse('`value` must be zero on a contract creation')

  const gasLimit = quantity(tx.gasLimit, '`gasLimit`')
  if (gasLimit < 21_000n || gasLimit > MAX_DEPLOY_GAS) {
    refuse(`\`gasLimit\` must be between 21000 and ${MAX_DEPLOY_GAS}`)
  }
  return gasLimit
}

/**
 * A plain native-value transfer out of the treasury. Returns the gas limit.
 *
 * `data` must be EMPTY, which is the whole difference between this and a signing oracle. With
 * calldata the same transaction is an arbitrary contract call — `approve(attacker, 2^256-1)` on
 * every ERC-20 the treasury holds is `to != null, value = 0` and 68 bytes, and would otherwise pass
 * every other check here. Sweeping an ERC-20 out of the treasury is a real future need and it does
 * NOT get met by widening this; it gets its own shape, whose allowlist is a
 * `transfer(address,uint256)` selector and nothing else.
 */
function assertTransfer(tx: Record<string, unknown>): bigint {
  if (typeof tx.to !== 'string' || !ethers.isAddress(tx.to)) {
    refuse('`to` must be a valid address for a value transfer')
  }
  // Not a judgement about the destination's worth — this service has no view on that — but 0x0 is
  // the one address from which nothing can ever be recovered, and no caller here means to send
  // there.
  if (tx.to.toLowerCase() === ZERO_ADDRESS) refuse('`to` must not be the zero address')

  const data = tx.data == null ? '0x' : tx.data
  if (data !== '0x' && data !== '') refuse('`data` must be empty on a value transfer')

  // NO CEILING on `value`, deliberately: a withdrawal may legitimately move the treasury's whole
  // balance, and a cap here would be a limit nobody could state a number for. The fee bound is what
  // protects against griefing; the destination is the caller's business.
  //
  // AMOUNTS PAST 2^53 MUST ARRIVE AS STRINGS. EMBER has 18 decimals, so one whole EMBER is 1e18 of
  // the smallest unit and a JS number cannot carry it exactly. `quantity` refuses a non-safe-integer
  // number rather than rounding it, which is the fail-closed half of this: a silently-rounded amount
  // is a signature over the wrong number, and nothing downstream would ever notice.
  if (quantity(tx.value, '`value`') <= 0n) refuse('`value` must be positive on a transfer')

  const gasLimit = quantity(tx.gasLimit, '`gasLimit`')
  if (gasLimit < 21_000n || gasLimit > MAX_TRANSFER_GAS) {
    refuse(`\`gasLimit\` must be between 21000 and ${MAX_TRANSFER_GAS} for a value transfer`)
  }
  return gasLimit
}

/**
 * A sweep of a customer deposit address INTO the treasury. Returns the gas limit. SD-09 gate 4.
 *
 * This is `transfer`'s rules verbatim — it literally delegates to them — plus one that is stricter
 * than anything else in this file: THE DESTINATION IS NOT THE CALLER'S TO CHOOSE. `to` must equal
 * the treasury address this service pinned for the source address's own (chain, network), read from
 * `custody_treasuries` under an administrator credential and never from the sign request. It is the
 * only shape here whose destination is chosen by the VAULT rather than by the caller, and that is
 * where its safety comes from.
 *
 * WHY IT CANNOT BE "ANY treasury-purpose ADDRESS". That is the obvious version of this feature and
 * it is a total-loss vulnerability. A caller that can mint addresses can mint one with
 * `purpose: 'treasury'`, and it chooses chain, network, orderId and family — so it restates the
 * binding for an address it minted itself perfectly, and the binding check offers zero protection
 * for such an address. Mint T′, sweep every customer deposit into T′, transfer T′ out. Three calls.
 * The pin removes the redirect: it names one address per (chain, network), it can only ever name an
 * address this service already holds the key to, and no signing credential can write it.
 *
 * WHY EMPTY CALLDATA IS STILL REQUIRED — the `approve` test, applied. The tempting argument is that
 * calldata is harmless HERE because `to` is pinned to an address this service generated as an EOA,
 * and an EOA has no `approve` to call. That argument is probably true and it is the wrong reason to
 * allow it: it depends on the pinned address never gaining code, and EIP-7702 lets an EOA delegate
 * to code. Nothing needs calldata on a sweep anyway. So it is REFUSED BECAUSE IT IS UNNECESSARY,
 * NOT BECAUSE IT IS PROVABLY SAFE — the weaker claim, and the one that stays true when the chain
 * changes underneath it.
 *
 * THE RESIDUAL, SAID PLAINLY, and it is SDR-05. A holder of `custody:sign:treasury` can still drain
 * the treasury, because a withdrawal must be payable to an address a user names. The pin does not
 * reduce that; it removes the redirect class entirely and leaves exactly the exposure the treasury
 * already had. Bounding the rest is treasury float policy, not a signing rule.
 */
function assertSweep(tx: Record<string, unknown>, treasuryPin: string): bigint {
  // Not caller-supplied — this is the service's own pin — so a missing or unusable one is a fault
  // in here rather than in the request. It still fails CLOSED, as a refusal: an unpinned chain must
  // sign nothing at all.
  if (typeof treasuryPin !== 'string' || !ethers.isAddress(treasuryPin)) {
    refuse('no usable treasury is pinned for this address — a sweep has nowhere it may go')
  }
  if (typeof tx.to !== 'string') {
    refuse('`to` must be the pinned treasury address on a sweep')
  }
  if (tx.to !== treasuryPin) {
    // Same account, different spelling. Split out so the one refusal an honest caller can trip
    // reads as what it is: EVM addresses have three valid spellings, and this service compares the
    // one it minted, character for character.
    if (tx.to.toLowerCase() === treasuryPin.toLowerCase()) {
      refuse('`to` names the pinned treasury in a different case — echo the pin exactly as it is published')
    }
    refuse(
      '`to` must be the treasury address pinned for this chain and network — ' +
        'a sweep does not choose its own destination',
    )
  }
  // Everything else about the shape is `transfer`, deliberately by delegation rather than by copy:
  // empty calldata, positive value with no ceiling, the [21,000, 200,000] gas band and the
  // zero-address refusal. A rule that stops applying to transfers must stop applying here too.
  return assertTransfer(tx)
}

// ── Solana ──────────────────────────────────────────────────────────────────

// Program ids as literals rather than via @solana/spl-token: this service has no use for the
// library's builders, only for recognising what it is being asked to sign, and an unused SPL
// dependency is unused attack surface in the one service where that matters most.
const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111'
const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'

// SystemProgram instruction tag: u32 little-endian at offset 0. 0 = CreateAccount. (1 = Assign,
// 2 = Transfer, 3 = CreateAccountWithSeed, 4 = AdvanceNonceAccount — none of which any caller in
// this estate emits, all of which move or reassign what the address holds.)
const SYSTEM_IX_CREATE_ACCOUNT = 0
const SYSTEM_CREATE_ACCOUNT_LEN = 52
// SPL Token instruction tag: one byte at offset 0.
const TOKEN_IX_MINT_TO = 7
const TOKEN_IX_INITIALIZE_MINT2 = 20
const SPL_MINT_ACCOUNT_BYTES = 82n
// Rent exemption for 82 bytes is ~0.00146 SOL. This ceiling is far above that so a rent-parameter
// change cannot break deploys, and far below a balance worth stealing — lamports parked in a mint
// account cannot be recovered.
const MAX_CREATE_ACCOUNT_LAMPORTS = 50_000_000n
// An SPL deploy is exactly four instructions. A few more is fine; a hundred is somebody batching
// something else through this service's signature.
const MAX_SOLANA_INSTRUCTIONS = 8

/**
 * Solana: add the payer signature to a base64 transaction → fully-signed base64 transaction.
 *
 * The instruction ALLOWLIST is the policy: createAccount (as an SPL mint account only),
 * initializeMint2, mintTo, and associated-token-account creation. SD-09 names what it must refuse
 * and this is where that happens — Transfer, Approve, SetAuthority, Burn and CloseAccount are every
 * way to move or reassign what the address holds, and none of them is signable here.
 *
 * SOL HAS NO TRANSFER SHAPE, AND THEREFORE NO SWEEP. Specified here, not built. When SOL
 * withdrawals are wanted the shape has the same structure as `EvmPolicy`: `deployer` keeps the
 * instruction set below byte for byte; `treasury` permits exactly one System Transfer (tag 2,
 * 12-byte data) with `keys[0]` the vault address, `keys[1]` unconstrained and no other instruction
 * in the transaction; `deposit` is the same with `keys[1]` required to equal the pinned SOL
 * treasury. It does not widen the program allowlist and does not touch the SPL tag allowlist, so
 * the `approve` test is passed by the allowlists that already exist.
 *
 * WHAT IS LOAD-BEARING UNTIL THEN: a `deposit`-purpose SOL address must never reach this function.
 * `purposeGate` refuses it (`SWEEPABLE_FAMILIES`). Without that gate, admitting `deposit` would
 * hand a signing credential the instruction set below over every customer's SOL deposit key —
 * createAccount can park up to 50,000,000 lamports in a mint account that nothing in this estate
 * can ever recover. That is a silent re-opening of the "unconstrained signing oracle" finding by
 * the back door.
 */
export function signSolana(secretKeyBase64: string, payload: unknown, address: string): string {
  if (typeof payload !== 'string') refuse('solana payload must be a base64 transaction')
  const kp = Keypair.fromSecretKey(new Uint8Array(Buffer.from(secretKeyBase64, 'base64')))
  if (kp.publicKey.toBase58() !== address) {
    throw new Error(`decrypted solana key does not match ${address}`)
  }

  const tx = decodeSolanaTx(payload)
  if (!tx.feePayer?.equals(kp.publicKey)) refuse('solana fee payer must be the vault address')
  if (tx.instructions.length === 0) refuse('solana transaction has no instructions')
  if (tx.instructions.length > MAX_SOLANA_INSTRUCTIONS) {
    refuse(`solana transaction has more than ${MAX_SOLANA_INSTRUCTIONS} instructions`)
  }
  for (const ix of tx.instructions) {
    const program = ix.programId.toBase58()
    if (program === SYSTEM_PROGRAM_ID) assertCreatesMintAccount(ix, kp.publicKey)
    else if (program === TOKEN_PROGRAM_ID) assertTokenMintInstruction(ix, kp.publicKey)
    else if (program === ASSOCIATED_TOKEN_PROGRAM_ID) assertAtaCreation(ix, kp.publicKey)
    else refuse(`solana program ${short(program)} is not one this service signs for`)
  }

  tx.partialSign(kp)
  return tx.serialize().toString('base64')
}

function decodeSolanaTx(base64Tx: string): SolanaTransaction {
  try {
    return SolanaTransaction.from(Buffer.from(base64Tx, 'base64'))
  } catch {
    refuse('solana payload is not a decodable transaction')
  }
}

function assertCreatesMintAccount(ix: TransactionInstruction, payer: PublicKey): void {
  if (ix.data.length !== SYSTEM_CREATE_ACCOUNT_LEN || ix.data.readUInt32LE(0) !== SYSTEM_IX_CREATE_ACCOUNT) {
    refuse('the only system-program instruction this service signs is createAccount')
  }
  const lamports = ix.data.readBigUInt64LE(4)
  const space = ix.data.readBigUInt64LE(12)
  const owner = new PublicKey(ix.data.subarray(20, SYSTEM_CREATE_ACCOUNT_LEN)).toBase58()
  if (space !== SPL_MINT_ACCOUNT_BYTES) refuse('createAccount may only allocate an SPL mint account')
  if (owner !== TOKEN_PROGRAM_ID) refuse('createAccount must assign the new account to the SPL token program')
  if (lamports > MAX_CREATE_ACCOUNT_LAMPORTS) refuse('createAccount funds the new account far above rent exemption')
  if (!ix.keys[0]?.pubkey.equals(payer)) refuse('createAccount must be funded by the vault address')
}

function assertTokenMintInstruction(ix: TransactionInstruction, payer: PublicKey): void {
  const tag = ix.data[0]
  if (tag !== TOKEN_IX_INITIALIZE_MINT2 && tag !== TOKEN_IX_MINT_TO) {
    // Notably excludes Transfer(3), Approve(4), SetAuthority(6), Burn(8) and CloseAccount(9) —
    // every way to move or reassign what this address holds. SD-09 names all five.
    refuse(`SPL token instruction ${tag} is not one this service signs for`)
  }
  // mintTo is [mint, destination, authority]; the authority is the signature being asked for, so it
  // must be us and not somebody else's mint.
  if (tag === TOKEN_IX_MINT_TO && !ix.keys[2]?.pubkey.equals(payer)) {
    refuse('mintTo authority must be the vault address')
  }
}

function assertAtaCreation(ix: TransactionInstruction, payer: PublicKey): void {
  // Create is encoded as empty data (legacy) or [0]; CreateIdempotent is [1]. RecoverNested is [2]
  // and moves somebody else's tokens — not signed here.
  const tag = ix.data.length === 0 ? 0 : ix.data[0]
  if (ix.data.length > 1 || (tag !== 0 && tag !== 1)) {
    refuse('the only associated-token instruction this service signs is account creation')
  }
  if (!ix.keys[0]?.pubkey.equals(payer)) refuse('ATA creation must be funded by the vault address')
}

// ── Bitcoin ─────────────────────────────────────────────────────────────────

/**
 * Bitcoin: sign a base64 PSBT → finalised raw transaction hex.
 *
 * A PSBT rather than a raw transaction because a segwit signature commits to the VALUE of each
 * input, and only the PSBT carries it: handed a bare transaction this service would be signing
 * amounts it cannot see. Every input must be a P2WPKH output of this very address, so it can only
 * ever spend its own coins — the destination is the caller's business, the source is not.
 *
 * SIGHASH_ALL ONLY. Anything else leaves part of the transaction unsigned and therefore editable
 * after the signature is handed back.
 *
 * BITCOIN'S SWEEP OUTPUT POLICY: specified here, not built. For a `deposit`-purpose PSBT the
 * destination stops being the caller's business exactly as it does for EVM: EVERY output must pay
 * the pinned BTC treasury for the row's (chain, network) — including any change output, since a
 * sweep leaves nothing behind — and a PSBT carrying an output to anything else is refused whole
 * rather than partially signed, because `signAllInputs` would otherwise pay for one foreign output
 * with a signature over all of them. Until that has a caller, `purposeGate` refuses a
 * `deposit`-purpose bitcoin address outright: the fail-closed half of "specified, not built".
 */
export function signBitcoin(wif: string, payload: unknown, address: string, network: KeyNetwork): string {
  if (typeof payload !== 'string') refuse('bitcoin payload must be a base64 PSBT')
  const net = bitcoinNetwork(network)

  // fromWIF throws when the WIF's network byte disagrees, which IS the network binding: a mainnet
  // key can never be used to satisfy a testnet request.
  const keyPair = ECPair.fromWIF(wif, net)
  const pubkey = Buffer.from(keyPair.publicKey)
  const own = bitcoin.payments.p2wpkh({ pubkey, network: net })
  if (own.address !== address) throw new Error(`decrypted bitcoin key does not match ${address}`)

  const psbt = decodePsbt(payload, net, network)
  if (psbt.inputCount === 0) refuse('psbt has no inputs')
  if (psbt.txOutputs.length === 0) refuse('psbt has no outputs')
  psbt.data.inputs.forEach((input, i) => {
    if (input.finalScriptSig || input.finalScriptWitness) refuse(`psbt input ${i} is already finalized`)
    const witnessUtxo = input.witnessUtxo
    if (!witnessUtxo) refuse(`psbt input ${i} has no witnessUtxo — its value is unknown`)
    if (!witnessUtxo.script.equals(own.output!)) refuse(`psbt input ${i} does not spend this vault address`)
    if (input.sighashType != null && input.sighashType !== bitcoin.Transaction.SIGHASH_ALL) {
      refuse(`psbt input ${i} asks for sighash ${input.sighashType}; only SIGHASH_ALL is signed`)
    }
  })

  psbt.signAllInputs(keyPair, [bitcoin.Transaction.SIGHASH_ALL])
  const valid = psbt.validateSignaturesOfAllInputs((pk, msghash, signature) =>
    ECPair.fromPublicKey(pk).verify(msghash, signature),
  )
  if (!valid) throw new Error(`bitcoin signature verification failed for ${address}`)
  psbt.finalizeAllInputs()
  // extractTransaction's default 5000 sat/vB ceiling is left ON. A PSBT whose inputs dwarf its
  // outputs is not a payment, it is a donation to a miner.
  return psbt.extractTransaction().toHex()
}

function decodePsbt(payload: string, net: bitcoin.Network, network: KeyNetwork): bitcoin.Psbt {
  try {
    return bitcoin.Psbt.fromBase64(payload, { network: net })
  } catch {
    refuse(`bitcoin payload is not a valid ${network} PSBT`)
  }
}

// ── XRP ─────────────────────────────────────────────────────────────────────

const XRP_FIELDS: ReadonlySet<string> = new Set([
  'TransactionType',
  'Account',
  'Destination',
  'DestinationTag',
  'SourceTag',
  'Amount',
  'Fee',
  'Sequence',
  'LastLedgerSequence',
  'Flags',
  'Memos',
])
/** 1 XRP. Real fees are ~10 drops; this is a burn ceiling, not an estimate. */
const XRP_MAX_FEE_DROPS = 1_000_000n
/** tfPartialPayment — lets the delivered amount be less than `Amount`. */
const XRP_TF_PARTIAL_PAYMENT = 0x0002_0000

/**
 * Which XRP payments an address of a given purpose may produce. The same split as `EvmShape`, and
 * for the same reason — XRP is withdrawable, so it must be sweepable, and a sweep may not name its
 * own destination.
 *
 * A union rather than an optional field so that `shape: 'sweep'` without a pin does not compile, and
 * a REQUIRED parameter so a new call site has to state which one it means. A default would have to
 * be `'payment'`, the wider of the two: an unconsidered caller would silently get the shape that
 * pays anywhere.
 */
export type XrpPolicy = { readonly shape: 'payment' } | { readonly shape: 'sweep'; readonly treasuryPin: string }

/**
 * XRP: sign an unsigned transaction object → the `tx_blob` hex to submit.
 *
 * Only a plain XRP Payment from this account. The field allowlist is what keeps that true:
 * SetRegularKey, SignerListSet and AccountSet(asfDisableMaster) all hand the account to someone else
 * permanently, and Paths/SendMax turn a payment into a cross-currency order.
 *
 * THE NETWORK BINDING, AND WHAT IT ACTUALLY IS. SD-09 records the defect: XRP testnet and mainnet
 * share a seed and an address, so one signed Payment is submittable on either. There is no field in
 * a Payment that fixes this — `NetworkID` is defined only for networks whose id exceeds 1024, and
 * both XRPL mainnet (0) and testnet (1) are below it, so a correct Payment for either MUST omit it.
 * Presenting it is therefore refused here (it would make the blob invalid on both), and it is not
 * the fix.
 *
 * The fix is derivational and it lives in `hd.ts`: BIP-44 assigns coin type 1 to testnet, so a
 * user's testnet XRP account and their mainnet XRP account are DIFFERENT ACCOUNTS with different
 * addresses. A testnet Payment replayed on mainnet then draws on an account that does not exist
 * there. `POST /v1/addresses` refuses to mint a flat-random XRP key for exactly this reason, so
 * every XRP key this service creates has the property. Adopted legacy XRP rows keep the residual,
 * bounded by the fact that both networks' funds sit under one seed this service holds — a replay
 * misplaces coins, it does not lose them.
 */
export function signXrp(seed: string, payload: unknown, address: string, policy: XrpPolicy): string {
  const tx = asRecord(payload, 'xrp payload')
  const wallet = XrplWallet.fromSeed(seed)
  if (wallet.classicAddress !== address) throw new Error(`decrypted xrp key does not match ${address}`)

  onlyFields(tx, XRP_FIELDS, 'xrp payload')
  if (tx.TransactionType !== 'Payment') refuse('the only XRP transaction this service signs is a Payment')
  if (tx.Account !== address) refuse('XRP `Account` must be the vault address')
  if (typeof tx.Destination !== 'string' || tx.Destination.length === 0) refuse('XRP `Destination` is required')
  if (policy.shape === 'sweep') {
    // The service's own value, not the caller's — an unpinned chain signs nothing.
    if (typeof policy.treasuryPin !== 'string' || policy.treasuryPin.length === 0) {
      refuse('no usable treasury is pinned for this address — a sweep has nowhere it may go')
    }
    if (tx.Destination !== policy.treasuryPin) {
      // Base58 is case-SENSITIVE, so exact string equality is the only comparison there is here;
      // there is no EVM-style three-spellings problem to accommodate.
      refuse(
        'XRP `Destination` must be the treasury address pinned for this chain and network — ' +
          'a sweep does not choose its own destination',
      )
    }
  }
  // A string Amount is drops of XRP; an object Amount is an issued currency, which this service has
  // no business moving.
  if (typeof tx.Amount !== 'string' || !/^[1-9][0-9]{0,17}$/.test(tx.Amount)) {
    refuse('XRP `Amount` must be a positive drops string')
  }
  if (typeof tx.Fee !== 'string' || !/^[0-9]{1,17}$/.test(tx.Fee)) refuse('XRP `Fee` must be a drops string')
  if (BigInt(tx.Fee) > XRP_MAX_FEE_DROPS) refuse(`XRP \`Fee\` exceeds ${XRP_MAX_FEE_DROPS} drops`)
  if (!Number.isSafeInteger(tx.Sequence) || (tx.Sequence as number) < 0) refuse('XRP `Sequence` is required')
  if (!Number.isSafeInteger(tx.LastLedgerSequence) || (tx.LastLedgerSequence as number) <= 0) {
    // Without it the signed blob stays submittable for ever, so a request the caller abandoned can
    // still be replayed into a ledger months later.
    refuse('XRP `LastLedgerSequence` is required')
  }
  if (tx.Flags !== undefined) {
    if (!Number.isSafeInteger(tx.Flags) || (tx.Flags as number) < 0) refuse('XRP `Flags` must be an integer')
    if ((tx.Flags as number) & XRP_TF_PARTIAL_PAYMENT) refuse('XRP tfPartialPayment is not signed')
  }

  return wallet.sign(tx as unknown as XrplTransaction).tx_blob
}
