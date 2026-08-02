/**
 * The gates, in the order they run. SD-09.
 *
 *   1. Purpose gate          — what this address is FOR, and therefore the one shape it may produce.
 *   2. Binding check         — five fields, restated by the caller, compared to the stored row.
 *   3. Chain-id resolution   — a generic `evm` is refused, because a signature with no chain id is
 *                              valid on EVERY EVM chain.
 *   4. Treasury pin          — for a deposit sweep, the destination is chosen by the VAULT.
 *   5. Only then is the key decrypted.
 *
 * **THE ORDER IS THE DESIGN AND IT DOES NOT CHANGE.** Every gate that can fail closed runs before
 * anything is decrypted, so a refused request never causes a private key to exist in this process's
 * memory at all. Moving the decrypt earlier would not change a single refusal's outcome and would
 * change what an attacker gets from a crash dump taken during one.
 *
 * These functions are pure and live away from the route for one reason: every one of them is a
 * negative test, and a negative test that needs a database, a JWKS and a keypair to express is a
 * negative test somebody deletes when it goes red.
 */

import { isEvmFamily, expectedEvmChainId, type KeyNetwork } from './chains.ts'
import type { BitcoinPolicy, EvmShape, SolanaPolicy } from './signing.ts'

/**
 * Purposes /sign will act on.
 *
 * `deposit` IS PRESENT, and the property its absence used to protect is preserved by a different
 * mechanism: a deposit address's only signable shape has a destination this service chooses, not the
 * caller. Admitting it here without that shape would be the whole of the vulnerability.
 *
 * `user` is NOT present. A user-purpose wallet exists so the customer can hold and export it; the
 * platform signs nothing on their behalf, and giving it a shape would make custody a signing oracle
 * for keys whose owner never asked it to sign anything.
 */
const SIGNABLE_PURPOSES: ReadonlySet<string> = new Set(['deployer', 'treasury', 'deposit'])

/** The one EVM shape each signable purpose may produce. See `EvmPolicy` in signing.ts. */
const EVM_SHAPE_FOR_PURPOSE: Readonly<Record<string, EvmShape>> = Object.freeze({
  deployer: 'creation',
  treasury: 'transfer',
  deposit: 'sweep',
})

/**
 * The shape, including the fallback, as one testable answer.
 *
 * `purposeGate` has already excluded anything not in the map, so the fallback is unreachable. It is
 * 'creation' because that is the NARROWEST of the three: a creation cannot move value, so an
 * unforeseen purpose fails toward the shape that cannot spend the balance. Deliberately not
 * 'sweep', which despite its pinned destination still moves money.
 */
export function evmShapeForPurpose(purpose: string): EvmShape {
  return EVM_SHAPE_FOR_PURPOSE[purpose] ?? 'creation'
}

/** The one Solana shape each signable purpose may produce. See `SolanaPolicy` in signing.ts. */
const SOLANA_SHAPE_FOR_PURPOSE: Readonly<Record<string, SolanaPolicy['shape']>> = Object.freeze({
  deployer: 'mint',
  treasury: 'transfer',
  deposit: 'sweep',
})

/**
 * The Solana shape, including the fallback, as one testable answer.
 *
 * The fallback is 'sweep', which reads like the WIDER choice and is in fact the narrowest available
 * here: a sweep must name the pinned destination, and `keys.ts` resolves a pin only for
 * `purpose = 'deposit'`. So an unforeseen purpose reaching this fallback is handed an empty pin and
 * `signSolana` refuses it outright — the fallback can sign NOTHING. 'mint' would not have that
 * property: `createAccount` can park up to 50,000,000 lamports in an account nothing in this estate
 * can recover, so failing toward it would be failing toward a shape that still moves money.
 */
export function solanaShapeForPurpose(purpose: string): SolanaPolicy['shape'] {
  return SOLANA_SHAPE_FOR_PURPOSE[purpose] ?? 'sweep'
}

/** The one Bitcoin shape each signable purpose may produce. See `BitcoinPolicy` in signing.ts. */
const BITCOIN_SHAPE_FOR_PURPOSE: Readonly<Record<string, BitcoinPolicy['shape']>> = Object.freeze({
  deployer: 'payment',
  treasury: 'payment',
  deposit: 'sweep',
})

/**
 * The Bitcoin shape, including the fallback, as one testable answer.
 *
 * Only `deposit` gets the pinned one; a `treasury` pays a user's withdrawal to an address the user
 * supplied, and a `deployer` has no meaning on Bitcoin at all but is a signable purpose, so it gets
 * the same shape a treasury does rather than a special case nobody would maintain.
 *
 * The fallback is 'sweep' for `solanaShapeForPurpose`'s reason: with no pin resolved for a
 * non-deposit purpose, it signs nothing at all.
 */
export function bitcoinShapeForPurpose(purpose: string): BitcoinPolicy['shape'] {
  return BITCOIN_SHAPE_FOR_PURPOSE[purpose] ?? 'sweep'
}

/**
 * Families in which a `deposit` address is signable AT ALL — that is, families where a
 * pinned-destination shape EXISTS AND IS BUILT.
 *
 * **This is an allowlist and it stays one even though it now names every family custody holds keys
 * for.** It reads as vacuous and it is not: `SIGNABLE_PURPOSES` contains `deposit`, so the day a
 * sixth family is added to `chains.ts` its deposit addresses become signable the moment
 * `keys.ts` learns to dispatch them — with whatever shape that family's signer happens to offer,
 * which for a new signer is usually "whatever the caller asked for". Listing the families whose
 * sweep shape has actually been WRITTEN is what makes that a refusal instead.
 *
 * The history, because the entries earn their place differently. `evm`, `ember` and `xrp` were here
 * from the start. `bitcoin` and `solana` were refused because their sweep output policies were
 * specified in `signing.ts` and not built — the fail-closed half of "specified, not built". They are
 * built now (`BitcoinPolicy`, `SolanaPolicy`), and the property this gate was standing in for has
 * moved to where it belongs: for Bitcoin, every PSBT output must pay the pinned treasury; for
 * Solana, the single Transfer's destination must be it. In both cases the destination is chosen by
 * the VAULT, from `custody_treasuries`, keyed by the ROW's own chain and network, and never read
 * from the sign request.
 */
const SWEEPABLE_FAMILIES: ReadonlySet<string> = new Set(['evm', 'ember', 'xrp', 'bitcoin', 'solana'])

/** Just enough of a stored row to decide whether /sign may proceed at all. */
export interface RowIdentity {
  readonly address: string
  readonly purpose: string
  readonly family: string
  readonly chain: string
  readonly network: string
  readonly userId: string
  readonly orderId: string
  readonly status: string
}

export type GateResult = { readonly ok: true } | { readonly ok: false; readonly gate: string; readonly error: string }

/** Gate 1. What a purpose may sign for at all, in this family, in this lifecycle state. */
export function purposeGate(row: Pick<RowIdentity, 'purpose' | 'family' | 'status'>): GateResult {
  if (row.status !== 'active') {
    // SD-07 gate 9: once a key is exported the platform stops treating it as custodial and stops
    // sweeping it into treasury. This is where "stops" is enforced rather than merely documented —
    // an exported key is a key two parties hold, and a platform that kept signing sweeps out of one
    // would be moving a customer's self-custodied coins into its own treasury.
    return {
      ok: false,
      gate: 'purpose',
      error: `this address is '${row.status}' and is no longer signed for by this service`,
    }
  }
  if (!SIGNABLE_PURPOSES.has(row.purpose)) {
    return { ok: false, gate: 'purpose', error: 'this address carries a purpose this service does not sign for' }
  }
  if (row.purpose === 'deposit' && !SWEEPABLE_FAMILIES.has(row.family)) {
    return {
      ok: false,
      gate: 'purpose',
      error: `deposit addresses on '${row.family}' have no sweep shape and may not be signed for`,
    }
  }
  return { ok: true }
}

/**
 * Gate 2. The restated binding, compared field for field.
 *
 * SD-09 names the five: `address`, `chain`, `network`, `userId`, `orderId`. **`userId` is the one
 * that is new.** In forge-keyvault `row.userId` was compared to nothing at all — the code comment
 * at `routes/vault.ts:303` said so — because the only credential reaching /sign was a shared service
 * token that could not distinguish one user from another. With scoped service identity (SD-05) the
 * caller now states whose key it is acting on, so the field that was decorative becomes a check: a
 * caller that has learned one address cannot sign for it while claiming a different customer, and a
 * user token can only ever act for itself.
 *
 * `purpose` and `family` are compared too, which is two more than SD-09 lists. They are carried
 * forward from forge-keyvault rather than dropped: they cost nothing, and a caller that restates
 * `purpose: 'treasury'` for a deposit row is a caller whose model of this address is wrong in
 * exactly the way that precedes an incident.
 */
export function bindingMatches(row: RowIdentity, claim: RowIdentity): boolean {
  return (
    row.address === claim.address &&
    row.chain === claim.chain &&
    row.network === claim.network &&
    row.userId === claim.userId &&
    row.orderId === claim.orderId &&
    row.purpose === claim.purpose &&
    row.family === claim.family
  )
}

/** Which of the five fields disagreed. For the audit row and the log line; never for the caller. */
export function bindingMismatches(row: RowIdentity, claim: RowIdentity): string[] {
  const fields: (keyof RowIdentity)[] = ['address', 'chain', 'network', 'userId', 'orderId', 'purpose', 'family']
  return fields.filter((field) => row[field] !== claim[field])
}

/**
 * Gate 3. The chain id a signature must declare, or a refusal.
 *
 * Resolved BEFORE anything is decrypted, because it can fail closed. An address minted under the
 * generic `'evm'` chain has no chain id to bind a signature to, and in forge-keyvault this check was
 * skipped entirely for exactly those addresses — leaving a signed creation replayable on every EVM
 * network the deployer happened to hold funds on.
 */
export function resolveChainId(
  row: Pick<RowIdentity, 'family' | 'chain'>,
  network: KeyNetwork,
): { readonly ok: true; readonly chainId: number } | { readonly ok: false; readonly gate: string; readonly error: string } {
  if (!isEvmFamily(row.family)) return { ok: true, chainId: 0 }
  const expected = expectedEvmChainId(row.chain, network)
  if (expected === null) {
    return {
      ok: false,
      gate: 'chain_id',
      error:
        `no chain id is defined for '${row.chain}' ${network} — a signature with no chain id is ` +
        'valid on every EVM chain, so this address cannot be signed for',
    }
  }
  return { ok: true, chainId: expected }
}

/** The scope a signing request must carry, chosen by the ROW's purpose. SD-05. */
export function signScopeFor(purpose: string): string {
  return `custody:sign:${purpose}`
}
