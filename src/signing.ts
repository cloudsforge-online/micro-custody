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

/**
 * `BigInt` is not a parser and must not be used as one without this guard.
 *
 * `BigInt('')` is `0n` and so is `BigInt('   ')` — it does not throw, it treats an empty or
 * whitespace-only string as zero. The `length > 0` check in `quantity` catches the first spelling
 * and not the second, so a `value` of `'  '` used to arrive here and leave as a perfectly good
 * zero. Today every shape that permits a zero requires one, so nothing is exploitable; the reason
 * to fix it anyway is that "a field the caller left blank silently means zero" is a property no
 * future shape should have to know it is inheriting.
 */
function parseBigInt(value: string): bigint | null {
  if (value.trim().length === 0) return null
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
 *   deployer → 'creation'.     A zero-value contract creation with bounded initcode, and nothing else.
 *   treasury → 'transfer'.     The platform's payout address, and nothing else.
 *   deposit  → 'sweep' or 'token_sweep'. A movement whose RECIPIENT THIS SERVICE CHOOSES.
 *
 * The shapes are disjoint and no address holds two of them **except `deposit`, which holds the two
 * sweeps** — and that exception is the subject of the next paragraph, because it is the one place
 * this file's original rule was widened.
 *
 * WHY THE CREATION RULE IS NOT SIMPLY RELAXED. "to must be null, value must be zero" was once the
 * whole EVM policy, and it is also the reason no EVM coin could ever leave the platform — a
 * withdrawal is `to != null` with `value > 0`, precisely the shape that rule forbids. The fix is
 * not to widen it: a deployer that can also transfer value is a deployer whose whole balance is one
 * signature away. It is to make the shape a property of what the address is FOR.
 *
 * ## Why `deposit` now carries two shapes, and why that is not the thing the rule forbade
 *
 * An ERC-20 balance at a deposit address cannot be moved by `sweep`: an ERC-20 transfer's `to` is
 * the token CONTRACT and its real recipient lives inside the calldata, so `assertSweep`'s pin —
 * which compares `tx.to` to the treasury — refuses it, and `assertTransfer`'s empty-calldata rule
 * refuses it again. Both refusals are correct and neither is relaxed here. `token_sweep` is a
 * SECOND closed shape, not a loosening of the first.
 *
 * The property the one-shape-per-purpose rule was protecting is not the count. It is:
 *
 *     **a deposit address's signature can only ever move value to the treasury this service
 *     pinned, and the caller never names the recipient.**
 *
 * Both sweeps have that property; they differ only in WHERE the recipient is read from. `sweep`
 * reads it from `tx.to`. `token_sweep` reads it from the first ABI argument of the calldata. So
 * the union of the two admissible sets still contains no transaction whose beneficiary the caller
 * chose, which is the only invariant that was ever load-bearing.
 *
 * WHICH SHAPE APPLIES IS DERIVED FROM THE PAYLOAD, NOT REQUESTED. There is deliberately no new
 * field on the sign request naming the shape. A `deposit` payload with empty calldata is a `sweep`
 * and one with calldata is a `token_sweep`, and each is then held to its own rules in full. A
 * caller-supplied selector would be a caller-supplied choice between two policies, which is a
 * smaller version of exactly the thing this file exists to refuse — and it would be a new way to be
 * wrong for no capability in return, because the two sets are already disjoint on the payload.
 */
export type EvmShape = 'creation' | 'transfer' | 'sweep' | 'token_sweep'

/**
 * The shapes a PURPOSE may select. `token_sweep` is deliberately absent.
 *
 * It is refined out of `sweep` by the payload inside `signEvm` and is not reachable from any
 * purpose, which is what stops `gates.ts` from ever mapping an address type onto it directly. The
 * distinction is a type rather than a comment because a comment does not fail a build.
 */
export type EvmPurposeShape = Exclude<EvmShape, 'token_sweep'>

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
      /**
       * The ERC-20 contracts an OPERATOR has registered for this (chain, network), lower-cased.
       *
       * Empty is the correct default and the one every chain starts at: with no registered token,
       * `token_sweep` is unreachable and a deposit address signs native sweeps only. A token
       * becomes sweepable when an administrator puts it in `custody_token_contracts` and never as a
       * side effect of anything a signing caller does.
       */
      readonly tokenAllowlist: ReadonlySet<string>
    })

/**
 * EVM: sign an unsigned transaction object → the serialised signed transaction and the shape that
 * actually admitted it.
 *
 * The shape is RETURNED rather than assumed by the caller because `deposit` now has two of them and
 * only this function knows which one ran. `signing_audit.shape` has to record the policy a
 * signature actually went through — that column exists to answer exactly that question in a dispute
 * — and a caller that guessed 'sweep' for every deposit would be writing an audit trail that is
 * confidently wrong about half of them.
 */
export async function signEvm(
  privateKey: string,
  payload: unknown,
  policy: EvmPolicy,
): Promise<{ readonly signedTx: string; readonly shape: EvmShape }> {
  const tx = asRecord(payload, 'evm payload')
  onlyFields(tx, EVM_FIELDS, 'evm payload')

  if (Number(tx.chainId) !== policy.chainId) refuse(`chainId must be ${policy.chainId}`)

  // Which of the two sweeps a deposit payload is, decided by the payload and never by the caller.
  // `data` absent or '0x' is a native sweep; anything else is a token sweep and is held to
  // `assertTokenSweep` in full. Neither branch can fall through to the other: a native sweep still
  // requires empty calldata and a token sweep still requires exactly 68 bytes of it.
  let shape: EvmShape
  let gasLimit: bigint
  if (policy.shape === 'sweep') {
    const carriesCalldata = tx.data != null && tx.data !== '0x' && tx.data !== ''
    if (carriesCalldata) {
      shape = 'token_sweep'
      gasLimit = assertTokenSweep(tx, policy.treasuryPin, policy.tokenAllowlist)
    } else {
      shape = 'sweep'
      gasLimit = assertSweep(tx, policy.treasuryPin)
    }
  } else if (policy.shape === 'creation') {
    shape = 'creation'
    gasLimit = assertCreation(tx)
  } else {
    shape = 'transfer'
    gasLimit = assertTransfer(tx)
  }

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
  return { signedTx: await wallet.signTransaction(tx as ethers.TransactionRequest), shape }
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

/**
 * `transfer(address,uint256)` — the first four bytes of its keccak-256 hash.
 *
 * Written as a literal and CHECKED against `ethers.id` in the tests rather than computed here, so
 * that the constant this file admits is a constant a reader can see, and a typo in it fails a test
 * instead of silently admitting a different function. There is no `transferFrom` here and there
 * must never be: `transferFrom(from,to,amount)` moves somebody ELSE's balance, which is not a sweep
 * of this address and is not a thing a deposit key has any business signing.
 */
const ERC20_TRANSFER_SELECTOR = 'a9059cbb'

/** 4-byte selector + a 32-byte address word + a 32-byte amount word. Nothing before, nothing after. */
const ERC20_TRANSFER_CALLDATA_BYTES = 68

/**
 * An ERC-20 sweep of a customer deposit address INTO the treasury. Returns the gas limit.
 *
 * ## Why this shape has to exist at all
 *
 * A USDT transfer to a per-user deposit address succeeds — the sender pays the gas — and the
 * platform then holds a token balance at an address whose native balance is zero. Moving it is an
 * `transfer(address,uint256)` call sent TO THE TOKEN CONTRACT, so `tx.to` is the contract and not
 * the treasury, and the calldata is 68 bytes rather than empty. `assertSweep` refuses it on the
 * first count and `assertTransfer` on the second. Without this shape a token deposit is money the
 * platform has custody of and can never move, which is worse than not accepting it.
 *
 * ## Where the safety comes from, since it cannot come from `tx.to`
 *
 * `assertSweep`'s whole security property is that the VAULT chooses the destination. That property
 * is preserved exactly, by moving the pin from the `to` FIELD into the ABI DECODE:
 *
 *   * `tx.to` must be a contract an OPERATOR registered in `custody_token_contracts` for this
 *     address's own (chain, network). It is an allowlist and it refuses by default, so the set of
 *     contracts a deposit key can be made to call is a set no signing credential can add to.
 *   * The calldata must be EXACTLY `transfer(<pin>, <amount>)`. The recipient word is compared to
 *     the treasury pin, which is read from `custody_treasuries` by the row's own chain and network
 *     and never from the request — the identical source `assertSweep` uses.
 *   * `value` must be ZERO. Native value sent alongside a token transfer is not part of the
 *     transfer; on most ERC-20s it reverts and on the rest it is burnt at the contract.
 *
 * So a caller holding `custody:sign:deposit` can make this key call `transfer` on a registered
 * token, paying the pinned treasury, and nothing else. That is the same sentence as `assertSweep`'s
 * with one more noun in it.
 *
 * ## The gas that pays for this transaction, and why no shape here provides it
 *
 * A deposit address that has only ever received USDT holds no ETH, so it cannot pay for the very
 * transaction this function signs. That is the famous half of the trap and it is NOT solved here,
 * deliberately — it is solved by the treasury sending gas to the deposit address first, which is a
 * plain native transfer to a caller-named destination and is therefore the `transfer` shape the
 * treasury already has. No new shape, no widening, and nothing in this file changes.
 *
 * The direction matters and it is the whole reason this is safe. The treasury's transfer already
 * admits ANY destination (that is SDR-05, stated in `assertTransfer`), so aiming one at a deposit
 * address adds no capability that a holder of `custody:sign:treasury` did not already have. Solving
 * it the other way round — a shape letting the DEPOSIT key pull or move native value — would have
 * created one, over a customer's key, to save a transaction.
 *
 * Three rules for the caller that orchestrates it, none of which this service can enforce and all
 * of which cost money if they are missed:
 *
 *   1. **Fund on demand, never in advance.** Gas parked at deposit addresses is dust that must
 *      itself be swept later, at a fee, from thousands of addresses.
 *   2. **Fund once.** The top-up and the sweep are two transactions with a confirmation between
 *      them; a planner that does not treat the top-up as in-flight will fund the same address on
 *      every tick until it confirms.
 *   3. **The leftover is not an error.** The top-up funds `gasLimit × maxFee` and the transaction
 *      spends less, so a little native value remains at the address afterwards. It is swept by the
 *      ordinary native path or left as dust; it is not a reconciliation break.
 *
 * ## Why the calldata is decoded by hand rather than by `ethers.AbiCoder`
 *
 * A decoder's job is to be permissive about encodings that mean the same thing; this function's job
 * is the opposite. Non-zero bytes in an address word's twelve-byte left pad, or trailing bytes
 * after the second word, are things a decoder may discard and a token contract may not. The
 * comparison here is over the exact byte string that will be broadcast, so anything the signature
 * covers is either checked or refused, and "the decoder ignored it" is never an answer.
 */
function assertTokenSweep(
  tx: Record<string, unknown>,
  treasuryPin: string,
  tokenAllowlist: ReadonlySet<string>,
): bigint {
  // A fault in here rather than in the request, and it still fails CLOSED — exactly as `assertSweep`
  // treats an unpinned chain.
  if (typeof treasuryPin !== 'string' || !ethers.isAddress(treasuryPin)) {
    refuse('no usable treasury is pinned for this address — a sweep has nowhere it may go')
  }

  // The token contract: an allowlist, checked before anything is decoded.
  if (typeof tx.to !== 'string' || !ethers.isAddress(tx.to)) {
    refuse('`to` must be the address of a registered token contract on a token sweep')
  }
  if (!tokenAllowlist.has(tx.to.toLowerCase())) {
    refuse(
      "`to` is not a token contract registered for this address's chain and network — " +
        'an administrator must register a token before a deposit key will call it',
    )
  }

  // Native value alongside a token transfer is never intended and is usually unrecoverable.
  if (quantity(tx.value ?? 0, '`value`') !== 0n) refuse('`value` must be zero on a token sweep')

  const data = typeof tx.data === 'string' ? tx.data : ''
  if (!/^0x[0-9a-fA-F]+$/.test(data)) refuse('`data` must be 0x-hex calldata on a token sweep')
  const body = data.slice(2)
  if (body.length !== ERC20_TRANSFER_CALLDATA_BYTES * 2) {
    refuse(
      `\`data\` must be exactly ${ERC20_TRANSFER_CALLDATA_BYTES} bytes — ` +
        'a `transfer(address,uint256)` call and nothing appended to it',
    )
  }
  if (body.slice(0, 8).toLowerCase() !== ERC20_TRANSFER_SELECTOR) {
    refuse('`data` must call `transfer(address,uint256)` — no other function is signable here')
  }

  // The recipient word. The twelve-byte left pad must be zero: a token contract reads the low 20
  // bytes regardless, so dirty high bytes change nothing on-chain and would only ever be here to
  // make this comparison read differently from what executes.
  const recipientWord = body.slice(8, 72)
  if (!/^0{24}[0-9a-fA-F]{40}$/.test(recipientWord)) {
    refuse("`data`'s recipient argument is not a left-padded 20-byte address")
  }
  const recipient = `0x${recipientWord.slice(24).toLowerCase()}`

  // THE PIN, inside the calldata. Compared lower-cased rather than character for character, which
  // is the opposite of `assertSweep` and is right for the opposite reason: `tx.to` there is a
  // string the caller echoed and its casing is a real EIP-55 checksum worth insisting on, whereas
  // an ABI word has no casing at all — it is twenty raw bytes that hex-encoding has to spell
  // somehow. Insisting on a spelling here would refuse correct calldata for a cosmetic reason.
  if (recipient !== treasuryPin.toLowerCase()) {
    refuse(
      "`data` pays an address that is not the treasury pinned for this chain and network — " +
        'a sweep does not choose its own destination',
    )
  }

  // A signature is permanent and a zero-amount transfer is not a sweep of anything. Refusing it
  // costs a caller nothing it wanted and removes a signed no-op from ever existing.
  const amount = parseBigInt(`0x${body.slice(72)}`)
  if (amount === null || amount <= 0n) refuse('`data` must transfer a positive amount')

  // An ERC-20 `transfer` is 21,000 intrinsic plus roughly 14k–50k of storage work; USDT is near the
  // top of that band. The ceiling is `transfer`'s, deliberately shared: a token sweep that wants
  // more gas than the treasury's own transfers is not a token sweep.
  const gasLimit = quantity(tx.gasLimit, '`gasLimit`')
  if (gasLimit < 21_000n || gasLimit > MAX_TRANSFER_GAS) {
    refuse(`\`gasLimit\` must be between 21000 and ${MAX_TRANSFER_GAS} for a token sweep`)
  }
  return gasLimit
}

// ── Solana ──────────────────────────────────────────────────────────────────

// Program ids as literals rather than via @solana/spl-token: this service has no use for the
// library's builders, only for recognising what it is being asked to sign, and an unused SPL
// dependency is unused attack surface in the one service where that matters most.
const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111'
const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'

// SystemProgram instruction tag: u32 little-endian at offset 0. 0 = CreateAccount, 2 = Transfer.
// (1 = Assign, 3 = CreateAccountWithSeed, 4 = AdvanceNonceAccount — none of which any caller in
// this estate emits, all of which reassign what the address holds or move it by a second route.)
const SYSTEM_IX_CREATE_ACCOUNT = 0
const SYSTEM_IX_TRANSFER = 2
/** Transfer's data is exactly the u32 tag and a u64 lamports. A longer one is not a Transfer. */
const SYSTEM_TRANSFER_LEN = 12
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
 * Which Solana transaction an address of a given purpose may produce. The same split as `EvmShape`,
 * built to the specification that used to sit in this docstring as "specified, not built".
 *
 *   deployer → 'mint'.     The SPL mint-creation instruction set, byte for byte as it always was.
 *   treasury → 'transfer'. Exactly one System Transfer, to an address the caller names.
 *   deposit  → 'sweep'.    Exactly one System Transfer, to the address THIS SERVICE pinned.
 *
 * THE THREE ARE DISJOINT, WHICH IS A NARROWING AS WELL AS A WIDENING. Before this existed, EVERY
 * signable purpose got the mint-creation set, treasury included — `createAccount` can park up to
 * 50,000,000 lamports in an account nothing in this estate can recover, and the only caller that
 * ever needed it (`mint`, via `families.ts`) mints under `purpose: 'deployer'`. A treasury address
 * now signs transfers and nothing else, and a deployer address still cannot move a lamport by
 * Transfer. Neither the program allowlist nor the SPL tag allowlist is widened by any of this, so
 * the `approve` test is still passed by the allowlists that were already here.
 *
 * A union rather than an optional pin, and a REQUIRED parameter, for the reason `XrpPolicy` gives:
 * `shape: 'sweep'` without a pin must not compile, and a new call site must state which shape it
 * means rather than inherit the widest one by default.
 */
export type SolanaPolicy =
  | { readonly shape: 'mint' }
  | { readonly shape: 'transfer' }
  | { readonly shape: 'sweep'; readonly treasuryPin: string }

/**
 * Solana: add the payer signature to a base64 transaction → fully-signed base64 transaction.
 *
 * The instruction ALLOWLIST is the policy. For `mint` it is createAccount (as an SPL mint account
 * only), initializeMint2, mintTo, and associated-token-account creation. SD-09 names what it must
 * refuse and this is where that happens — Approve, SetAuthority, Burn and CloseAccount are every
 * way to reassign what the address holds, and none of them is signable under any shape here.
 *
 * SPL Transfer (tag 3) IS STILL REFUSED EVERYWHERE, and that is not an oversight now that SOL
 * moves. `transfer` and `sweep` admit exactly ONE instruction, the SYSTEM program's Transfer, which
 * moves native lamports out of the vault address itself. SPL Transfer moves somebody's token
 * balance out of a token account, has a different risk and has no caller in this estate; it does
 * not come along for the ride.
 *
 * WHAT CARRIES THE SAFETY PROPERTY FOR A DEPOSIT ADDRESS. It used to be `purposeGate`, which
 * refused a `deposit`-purpose SOL address outright because there was no shape whose destination
 * this service chose. It is now the `sweep` shape's pin: `keys[1]` — the Transfer's destination —
 * must equal the treasury pinned for the row's own (chain, network), read from `custody_treasuries`
 * under an administrator credential and never from the sign request. The pin is why "mint a
 * treasury of my own, sweep every deposit into it" is not three calls; see `assertSweep` for the
 * long form of that argument, which applies here unchanged.
 */
export function signSolana(
  secretKeyBase64: string,
  payload: unknown,
  address: string,
  policy: SolanaPolicy,
): string {
  if (typeof payload !== 'string') refuse('solana payload must be a base64 transaction')
  const kp = Keypair.fromSecretKey(new Uint8Array(Buffer.from(secretKeyBase64, 'base64')))
  if (kp.publicKey.toBase58() !== address) {
    throw new Error(`decrypted solana key does not match ${address}`)
  }

  const tx = decodeSolanaTx(payload)
  if (!tx.feePayer?.equals(kp.publicKey)) refuse('solana fee payer must be the vault address')
  if (tx.instructions.length === 0) refuse('solana transaction has no instructions')

  if (policy.shape === 'mint') {
    // The mint shape legitimately needs a SECOND signer: `createAccount`'s new account signs for its
    // own creation, and the caller pre-signs with that keypair. That is why `partialSign` is used
    // here at all, and why the signer count is only constrained on the transfer shapes below.
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
  } else {
    // EXACTLY ONE, not "at most MAX_SOLANA_INSTRUCTIONS". A batch is what makes a Solana signature
    // dangerous: `partialSign` signs the whole message, so a second instruction riding alongside a
    // legitimate Transfer is signed by the same signature and cannot be separated from it after the
    // fact. The mint shape tolerates a handful because an SPL deploy is genuinely four
    // instructions; a transfer is one, so anything more is somebody batching.
    if (tx.instructions.length !== 1) {
      refuse('a solana transfer must be exactly one instruction — nothing may ride alongside it')
    }
    const destination = assertSystemTransfer(tx.instructions[0]!, kp.publicKey)
    if (policy.shape === 'sweep') assertSolanaSweepDestination(destination, policy.treasuryPin)
    // EXACTLY ONE REQUIRED SIGNER, AND IT MUST BE US. A System Transfer needs the source account's
    // signature and no other, so a message declaring a second required signer is not the transaction
    // it claims to be — and this service must not hand back a half-signed one, which is a blob a
    // caller can complete later with a counterparty of its choosing. It is checked HERE, as a
    // refusal, rather than being left to `serialize()` below: `serialize()` throws a plain Error,
    // which reaches the route as a 500 with NO AUDIT ROW, and an unaudited path is one a caller can
    // probe in a loop without the rate limiter — which counts audit rows — ever seeing it.
    //
    // LAST of the three, deliberately. Every shape above it produces a more specific message for the
    // same transaction: a `createAccount` needs its new account to sign, and a Transfer out of
    // somebody else's account needs theirs, so both would otherwise be reported as a signer-count
    // problem when the real fault is the instruction.
    const signers = tx.signatures
    if (signers.length !== 1 || !signers[0]?.publicKey.equals(kp.publicKey)) {
      refuse('a solana transfer must require exactly one signature, and it must be the vault address')
    }
  }

  tx.partialSign(kp)
  // `serialize()` DEFAULTS ARE LOAD-BEARING AND MUST NOT BE RELAXED. `partialSign` recompiles the
  // message from `tx.instructions` when the decoded signature count disagrees with the wire header,
  // so the bytes returned are not necessarily the bytes inspected above. `verifySignatures: true`
  // — the default — is what makes any such divergence fail here rather than ship. Passing
  // `{ requireAllSignatures: false }` to quiet an error would switch that off; the signer check
  // above is the reason no one ever needs to.
  return tx.serialize().toString('base64')
}

/**
 * One SystemProgram Transfer out of the vault address. Returns its DESTINATION, so the caller can
 * pin it without re-parsing.
 *
 * `keys[0]` is the funding account and it must be this address: the whole of rule 1 at the top of
 * this file is that a signature only ever spends what the address it was requested for holds. A
 * Transfer whose `keys[0]` is somebody else is a transaction this service is being asked to pay the
 * FEE for while another account is drained — which the fee-payer check above would already catch
 * for the common case, and which is checked here too because the two are different accounts in the
 * instruction and only one of them is the one being spent.
 */
function assertSystemTransfer(ix: TransactionInstruction, payer: PublicKey): PublicKey {
  // TYPED NON-NULL, ACTUALLY NULLABLE. `Transaction.from` resolves an instruction's program from
  // `accountKeys[programIdIndex]` without range-checking the index, so a hand-rolled message with an
  // out-of-range index yields `undefined` here and a bare TypeError — a 500 with no audit row —
  // where a refusal is what belongs.
  if (!(ix.programId instanceof PublicKey)) refuse('solana instruction names no program')
  if (ix.programId.toBase58() !== SYSTEM_PROGRAM_ID) {
    refuse(`solana program ${short(ix.programId.toBase58())} is not one this service signs transfers for`)
  }
  if (ix.data.length !== SYSTEM_TRANSFER_LEN || ix.data.readUInt32LE(0) !== SYSTEM_IX_TRANSFER) {
    // Notably this refuses createAccount (tag 0, 52 bytes) under the transfer and sweep shapes, and
    // Assign, CreateAccountWithSeed and AdvanceNonceAccount under all three.
    refuse('the only system-program instruction a solana transfer signs is Transfer')
  }
  const from = ix.keys[0]?.pubkey
  const to = ix.keys[1]?.pubkey
  if (!from || !to) refuse('a solana Transfer must name a source and a destination')
  if (!from.equals(payer)) refuse('a solana Transfer must be funded by the vault address')
  // NO CEILING on lamports, for `assertTransfer`'s reason: a withdrawal may legitimately move the
  // whole balance and there is no number anyone could state for the cap. Zero is refused because it
  // is a fee burn with no effect, which no caller here means to ask for.
  if (ix.data.readBigUInt64LE(4) === 0n) refuse('a solana Transfer of zero lamports is not signed')
  if (to.equals(payer)) refuse('a solana Transfer to the vault address itself is not signed')
  return to
}

/**
 * The pinned destination. SD-09 gate 4, for Solana.
 *
 * Base58 is case-SENSITIVE and a `PublicKey` has one canonical encoding, so exact equality is the
 * only comparison there is here — there is no EVM-style three-spellings problem to accommodate.
 * The pin is compared as a decoded key rather than as a string so that a pin stored with stray
 * whitespace refuses rather than silently never matching.
 */
function assertSolanaSweepDestination(destination: PublicKey, treasuryPin: string): void {
  // The service's own value, not the caller's — a chain with no pin signs nothing at all.
  if (typeof treasuryPin !== 'string' || treasuryPin.length === 0) {
    refuse('no usable treasury is pinned for this address — a sweep has nowhere it may go')
  }
  let pinned: PublicKey
  try {
    pinned = new PublicKey(treasuryPin)
  } catch {
    refuse('no usable treasury is pinned for this address — a sweep has nowhere it may go')
  }
  if (!destination.equals(pinned)) {
    refuse(
      'a solana sweep must pay the treasury address pinned for this chain and network — ' +
        'a sweep does not choose its own destination',
    )
  }
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
 * Which Bitcoin PSBT an address of a given purpose may sign. The same split as `XrpPolicy`.
 *
 *   payment → the destination is the caller's business. A treasury paying a user's withdrawal.
 *   sweep   → EVERY output must pay the pinned treasury. A customer deposit address, emptied.
 *
 * A union rather than an optional pin so a `sweep` with no pin does not compile, and a REQUIRED
 * parameter so a new call site states which one it means. A default would have to be `'payment'`,
 * the wider of the two.
 */
export type BitcoinPolicy = { readonly shape: 'payment' } | { readonly shape: 'sweep'; readonly treasuryPin: string }

/**
 * Fee-rate ceilings, in satoshis per virtual byte. Burn ceilings, not estimates — the same kind of
 * number as `XRP_MAX_FEE_DROPS`, set far above any real fee and far below a loss worth causing.
 *
 * **THE SWEEP CEILING IS THE TIGHTER ONE, AND IT IS THERE BECAUSE THE PIN ALONE IS NOT ENOUGH.**
 * Pinning the destination stops a sweep paying an attacker. It does NOT stop a sweep paying the
 * miner: a PSBT with the customer's whole deposit on the input side and a single 546-satoshi output
 * to the pin satisfies every rule above, and the remainder is fee. That is not theft, it is
 * destruction, and it is available to any holder of `custody:sign:deposit` — the credential the
 * pin was introduced to make harmless. bitcoinjs's own default of 5000 would bound it at roughly
 * 0.005 BTC per sweep, which is not a bound worth having.
 *
 * 1000 is above every sustained mainnet fee rate on record — the 2023 spikes peaked around 500 —
 * and a sweep is a background job that can simply wait for a cheaper block, so a stall here is
 * self-healing in a way a burn is not. THE COUPLING IS DELIBERATE AND WORTH KNOWING ABOUT:
 * `micro-settlement` bounds its own estimate at `MAX_SAT_PER_VB = 5_000`, so during an event above
 * 1000 sat/vB it is THIS number that stops the sweep, and it stops it by refusing rather than by
 * signing something regrettable.
 *
 * The payment ceiling stays at bitcoinjs's default. A `payment` spends a TREASURY, whose residual
 * is stated in `assertSweep` and accepted as SDR-05: a holder of `custody:sign:treasury` can move
 * treasury funds to an address a user names, so bounding what it may pay a miner bounds nothing that
 * is not already unbounded. Tightening it would only refuse a legitimate high-fee withdrawal during
 * congestion — a real cost for no gain, and a withdrawal, unlike a sweep, has a user waiting.
 */
const MAX_SWEEP_FEE_RATE = 1_000
const MAX_PAYMENT_FEE_RATE = 5_000

/**
 * Bitcoin: sign a base64 PSBT → finalised raw transaction hex.
 *
 * A PSBT rather than a raw transaction because a segwit signature commits to the VALUE of each
 * input, and only the PSBT carries it: handed a bare transaction this service would be signing
 * amounts it cannot see. Every input must be a P2WPKH output of this very address, so it can only
 * ever spend its own coins — under `payment` the destination is the caller's business, the source
 * never is.
 *
 * SIGHASH_ALL ONLY. Anything else leaves part of the transaction unsigned and therefore editable
 * after the signature is handed back.
 *
 * BITCOIN'S SWEEP OUTPUT POLICY, which used to be specified here and not built. For a
 * `deposit`-purpose PSBT the destination stops being the caller's business exactly as it does for
 * EVM: EVERY output must pay the pinned BTC treasury for the row's (chain, network) — INCLUDING ANY
 * CHANGE OUTPUT, since a sweep leaves nothing behind — and a PSBT carrying an output to anything
 * else is refused WHOLE rather than partially signed, because `signAllInputs` would otherwise pay
 * for one foreign output with a signature over all of them. That last clause is why the output
 * check runs before `signAllInputs` and not per-output inside it.
 */
export function signBitcoin(
  wif: string,
  payload: unknown,
  address: string,
  network: KeyNetwork,
  policy: BitcoinPolicy,
  /**
   * The chain NAME, from the row — `bitcoin` or `litecoin`.
   *
   * **NOT DERIVABLE FROM THE FAMILY**, which is `'bitcoin'` for both. It selects the network
   * parameters, and getting it wrong is not a subtle mispricing: `ECPair.fromWIF` throws outright
   * when the WIF's version byte disagrees (Litecoin's 176 against Bitcoin's 128), so a Litecoin key
   * presented under Bitcoin's parameters refuses rather than signing something regrettable. That
   * throw is the network binding doing its job, and it is why this parameter is required rather
   * than defaulted.
   */
  chain: string,
): string {
  if (typeof payload !== 'string') refuse('bitcoin payload must be a base64 PSBT')
  const net = bitcoinNetwork(chain, network)

  // fromWIF throws when the WIF's network byte disagrees, which IS the network binding: a mainnet
  // key can never be used to satisfy a testnet request.
  const keyPair = ECPair.fromWIF(wif, net)
  const pubkey = Buffer.from(keyPair.publicKey)
  const own = bitcoin.payments.p2wpkh({ pubkey, network: net })
  if (own.address !== address) throw new Error(`decrypted bitcoin key does not match ${address}`)

  const psbt = decodePsbt(payload, net, network)
  if (psbt.inputCount === 0) refuse('psbt has no inputs')
  if (psbt.txOutputs.length === 0) refuse('psbt has no outputs')
  if (policy.shape === 'sweep') assertSweepOutputs(psbt, policy.treasuryPin, net)
  psbt.data.inputs.forEach((input, i) => {
    if (input.finalScriptSig || input.finalScriptWitness) refuse(`psbt input ${i} is already finalized`)
    const witnessUtxo = input.witnessUtxo
    if (!witnessUtxo) refuse(`psbt input ${i} has no witnessUtxo — its value is unknown`)
    if (!witnessUtxo.script.equals(own.output!)) refuse(`psbt input ${i} does not spend this vault address`)
    if (input.sighashType != null && input.sighashType !== bitcoin.Transaction.SIGHASH_ALL) {
      refuse(`psbt input ${i} asks for sighash ${input.sighashType}; only SIGHASH_ALL is signed`)
    }
  })

  // The ceiling bitcoinjs would enforce inside `extractTransaction`, kept in step with the explicit
  // check below so the library's own guard stays a live backstop rather than a stale default.
  const ceiling = policy.shape === 'sweep' ? MAX_SWEEP_FEE_RATE : MAX_PAYMENT_FEE_RATE
  psbt.setMaximumFeeRate(ceiling)

  psbt.signAllInputs(keyPair, [bitcoin.Transaction.SIGHASH_ALL])
  const valid = psbt.validateSignaturesOfAllInputs((pk, msghash, signature) =>
    ECPair.fromPublicKey(pk).verify(msghash, signature),
  )
  if (!valid) throw new Error(`bitcoin signature verification failed for ${address}`)
  psbt.finalizeAllInputs()

  // CHECKED HERE RATHER THAN LEFT TO `extractTransaction`, which enforces the same number by
  // throwing a plain Error. That would reach the route as a 500 with NO AUDIT ROW — and the rate
  // limiter counts audit rows, so an unaudited path is one a caller can probe in a loop without ever
  // being limited. It is the caller's PSBT that is out of bounds, so it is a refusal. `getFeeRate`
  // also throws when the outputs exceed the inputs, which is the same kind of caller error.
  let feeRate: number
  try {
    feeRate = psbt.getFeeRate()
  } catch {
    refuse('this psbt spends more than its inputs hold')
  }
  if (feeRate >= ceiling) {
    refuse(
      `this psbt pays ${feeRate} sat/vB in fee, above the ${ceiling} this service will sign away — ` +
        'check its output values',
    )
  }
  return psbt.extractTransaction().toHex()
}

/**
 * Every output of a sweep pays the pin. SD-09 gate 4, for Bitcoin.
 *
 * COMPARED AS A SCRIPT, NOT AS AN ADDRESS STRING. `txOutputs[i].address` is undefined for any
 * output bitcoinjs cannot render as an address — an OP_RETURN, a bare multisig, a future witness
 * version — so a string comparison would have to decide what to do about `undefined` and the safe
 * answer is not obvious to a later reader. The output SCRIPT is defined for all of them, and
 * comparing the bytes the pin's address encodes to is exactly the question being asked: does this
 * output pay the treasury.
 *
 * The pin is turned into a script under the ROW's own network, so a mainnet address pinned against
 * a testnet chain throws in `toOutputScript` and is refused rather than matching nothing.
 */
function assertSweepOutputs(psbt: bitcoin.Psbt, treasuryPin: string, net: bitcoin.Network): void {
  // The service's own value, not the caller's — a chain with no pin signs nothing at all.
  if (typeof treasuryPin !== 'string' || treasuryPin.length === 0) {
    refuse('no usable treasury is pinned for this address — a sweep has nowhere it may go')
  }
  let pinned: Buffer
  try {
    pinned = bitcoin.address.toOutputScript(treasuryPin, net)
  } catch {
    refuse('no usable treasury is pinned for this address — a sweep has nowhere it may go')
  }
  psbt.txOutputs.forEach((output, i) => {
    if (!output.script.equals(pinned)) {
      refuse(
        `psbt output ${i} does not pay the treasury address pinned for this chain and network — ` +
          'every output of a sweep pays the pin, change included',
      )
    }
  })
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
