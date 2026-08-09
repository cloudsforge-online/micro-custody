/**
 * Provisioning an address, and signing with one.
 *
 * The two operations that touch key material, kept together and kept away from the HTTP layer so
 * that the order of the gates is readable in one place and cannot be reordered by editing a route.
 */

import { createHash, randomUUID } from 'node:crypto'
import type { Logger } from '@cloudsforge/telemetry'
import type { Keyring } from './crypto.ts'
import {
  familyForChain,
  generateFlatRandom,
  isEvmFamily,
  isLegacyGasOnlyChain,
  type KeyFamily,
  type KeyNetwork,
} from './chains.ts'
import { deriveKey, newMnemonic, seedFromMnemonic } from './hd.ts'
import {
  bindingMatches,
  bindingMismatches,
  bitcoinShapeForPurpose,
  evmShapeForPurpose,
  purposeGate,
  resolveChainId,
  solanaShapeForPurpose,
  type RowIdentity,
} from './gates.ts'
import {
  SignRefused,
  signBitcoin,
  signEvm,
  signSolana,
  signXrp,
  type BitcoinPolicy,
  type EvmPolicy,
  type SolanaPolicy,
} from './signing.ts'
import { withOutbox, type Db, type Tx } from './outbox.ts'
import {
  findKeyByBinding,
  findKeyByIdempotencyKey,
  getKey,
  getTreasuryPin,
  getTokenAllowlist,
  insertKey,
  insertSeed,
  insertSigningAudit,
  findSeed,
  takeNextIndex,
  toKeyRecord,
  type CustodyKeyRecord,
  type CustodyKeyRow,
  type Purpose,
  type Scheme,
} from './store.ts'
import { seedSlot, type Vault } from './vault.ts'

export interface KeyDeps {
  readonly sql: Db
  readonly vault: Vault
  readonly keyring: Keyring
  readonly logger: Logger
  readonly producer: string
}

/** SHA-256 of a stable rendering of the payload. Never the payload, and never the signature. */
export function digestOf(value: unknown): string {
  return createHash('sha256').update(stableStringify(value)).digest('hex')
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`
}

/* ------------------------------------------------------------------ provisioning */

export interface ProvisionRequest {
  readonly chain: string
  readonly network: KeyNetwork
  readonly purpose: Purpose
  readonly userId: string
  readonly orderId: string
  /** Defaults to `hd_bip44`. `flat_random` exists so the legacy path stays exercised. */
  readonly scheme?: Scheme
  readonly createdBy: string
  readonly correlationId: string
  /**
   * What the caller calls this request, from the `idempotency-key` header. Absent is supported and
   * is not the same as "mint another one" — see `findReplay`.
   */
  readonly idempotencyKey?: string
}

export type ProvisionResult =
  | {
      readonly ok: true
      readonly key: CustodyKeyRecord
      /** True when nothing was created and this is the address an earlier request already got. */
      readonly reused: boolean
    }
  | { readonly ok: false; readonly status: number; readonly code: string; readonly error: string }

/**
 * The purposes whose binding names exactly one address, and may therefore be deduplicated by it.
 *
 * `deposit` and `deployer` take their `orderId` from a row the caller creates once per address it
 * intends to exist — wallet's deposit assignment id (`wallet/src/deposits.ts`) and mint's token
 * id (`mint/src/deploy.ts`). A second key under one of those bindings is a duplicate mint by
 * definition, and a rotation is safe because a rotation is a new assignment with a new id.
 *
 * `treasury` is excluded and its exclusion is the load-bearing half: `treasuryBinding`
 * (`store.ts`) derives the binding from (chain, network) alone, so a rotation candidate is minted
 * under the SAME binding on purpose. Deduplicating it would leave a pinned treasury with nowhere to
 * rotate to.
 */
const BINDING_NAMES_ONE_ADDRESS: ReadonlySet<Purpose> = new Set<Purpose>(['deposit', 'deployer'])

/**
 * The two unique indexes migration 6 added. Named here so the race handler below can tell a
 * duplicate provision apart from a duplicate ADDRESS, which is a derivation collision and must
 * never be swallowed.
 */
const IDEMPOTENCY_CONSTRAINTS: ReadonlySet<string> = new Set([
  'custody_keys_idempotency_uniq',
  'custody_keys_binding_uniq',
])

const CONFLICT: ProvisionResult = {
  ok: false,
  status: 409,
  code: 'idempotency_conflict',
  // Says nothing about the request it collided with. Same caller or not, an error message is not a
  // read surface, and the binding's entropy is the thing this service refuses to hand out.
  error:
    'this idempotency key has already been used for a different request — a different request ' +
    'needs a different key',
}

/**
 * Mint an address, or hand back the one an earlier identical request already got.
 *
 * ── THE ORDER OF THE WRITES IS A CORRECTNESS PROPERTY, NOT A STYLE ───────────────────────────
 *
 * The encrypted blob reaches the disk BEFORE the row that names it is committed. The two failure
 * windows are not symmetrical:
 *
 *   crash after the blob, before the commit — an orphan blob at an address no row references.
 *     Costs one file. Nothing can ever be sent there, because the address was never published.
 *   crash after the commit, before the blob — a row naming an address whose key does not exist.
 *     The address IS published, a customer deposits to it, and the coins are unrecoverable.
 *
 * So the cheap failure is the one this ordering chooses, every time. A provision that loses the
 * race below takes exactly that cheap failure — it has already written a blob when the insert is
 * refused — and that is the right trade for the same reason.
 *
 * ── AND THE LOOKUP IS NOT THE IDEMPOTENCY ────────────────────────────────────────────────────
 *
 * `findReplay` runs first because answering a retry without deriving a key is worth doing, but it
 * cannot be what makes this safe: two concurrent provisions both read a table with nothing in it.
 * Migration 6's unique indexes are the invariant; this function's job is to turn their 23505 into
 * the address the winner got.
 */
export async function provisionAddress(deps: KeyDeps, input: ProvisionRequest): Promise<ProvisionResult> {
  const family = familyForChain(input.chain)
  if (!family) {
    return {
      ok: false,
      status: 400,
      code: 'unknown_chain',
      error: `'${input.chain}' is not a chain this service holds keys for`,
    }
  }

  const scheme: Scheme = input.scheme ?? 'hd_bip44'

  const replay = await findReplay(deps, input)
  if (replay) return replay

  if (scheme === 'flat_random' && family === 'xrp') {
    // THE XRP NETWORK-BINDING FIX, ENFORCED AT THE ONLY PLACE IT CAN BE. A flat random XRP family
    // seed produces one classic address that is valid on testnet and mainnet alike, so a signed
    // Payment is submittable on either — SD-09's named defect. HD derivation fixes it by putting the
    // network in the BIP-44 coin type, and the fix only holds if there is no path left that mints
    // an XRP key without it. Adopted legacy rows keep the residual; nothing minted here adds one.
    return {
      ok: false,
      status: 400,
      code: 'scheme_refused',
      error:
        'XRP addresses are HD-derived only — a flat-random family seed produces one address valid ' +
        'on both networks, so a signed Payment would be submittable on either',
    }
  }

  let generated: CustodyKeyRow
  try {
    generated = await deps.sql
      .begin(async (tx) => {
        let seedId: string | null = null
        let derivationPath: string | null = null
        let address: string
        let privateKey: string

        if (scheme === 'hd_bip44') {
          const seed = await ensureSeed(deps, tx, input.userId, family)
          const index = await takeNextIndex(tx, seed.id)
          const mnemonic = deps.keyring.decrypt(seedSlot(seed.id), await deps.vault.read(seedSlot(seed.id)))
          const derived = deriveKey(seedFromMnemonic(mnemonic), family, input.network, index, input.chain)
          seedId = seed.id
          derivationPath = derived.derivationPath
          address = derived.address
          privateKey = derived.privateKey
        } else {
          const flat = generateFlatRandom(family, input.network, input.chain)
          address = flat.address
          privateKey = flat.privateKey
        }

        // Encrypted immediately; the plaintext key only ever lived in this closure.
        const blob = deps.keyring.encrypt(address, privateKey)
        const storage = await deps.vault.write(address, blob)

        const row = await insertKey(tx, {
          address,
          chain: input.chain,
          family,
          purpose: input.purpose,
          network: input.network,
          userId: input.userId,
          orderId: input.orderId,
          scheme,
          derivationPath,
          seedId,
          keyVersion: deps.keyring.writeVersion,
          storage,
          createdBy: input.createdBy,
          idempotencyKey: input.idempotencyKey ?? null,
        })
        return { row: [row] }
      })
      .then((r) => r.row[0]!)
  } catch (err) {
    const raced = await afterLosingTheRace(deps, input, err)
    if (raced) return raced
    throw err
  }

  // The event is emitted in its own transaction rather than inside the one above, because the one
  // above holds a row lock on the seed for the whole of a scrypt derivation. Keeping the outbox
  // write out of it keeps the lock as short as the work that needs it.
  //
  // It is also the reason a replay returns BEFORE here rather than after: an event is a downstream
  // effect — an indexer registration, a ledger entry, a notification — and emitting a second
  // `custody.address.created` for an address that was not created is the duplicate mint arriving
  // by another route.
  await withOutbox(deps.sql, deps.producer, async (_tx, emit) => {
    emit({
      topic: 'custody.address.created',
      key: generated.address,
      payload: {
        address: generated.address,
        chain: generated.chain,
        network: generated.network,
        purpose: generated.purpose,
        scheme: generated.scheme,
        userId: generated.user_id,
      },
      actor: input.createdBy,
      correlationId: input.correlationId,
    })
  })

  return { ok: true, key: toKeyRecord(generated), reused: false }
}

/**
 * The address an earlier request already got, if this request is that request again.
 *
 * TWO IDENTITIES, IN THIS ORDER.
 *
 * The caller's own key first, because it is the caller's statement about its own intent and it is
 * the only one that can cover a request whose binding is deliberately fresh. Then the binding, for
 * the purposes where a binding names one address by construction, because that catches the retry
 * that carried no key at all.
 *
 * ── AND A KEY THAT MATCHES A DIFFERENT REQUEST IS A CONFLICT, NOT A REPLAY ───────────────────
 *
 * This is the case where being helpful would be dangerous. `orderId` is one of SD-09's five
 * binding fields (`gates.ts`) and settlement must restate it character for character to sweep
 * the address — "a guessed binding is a sweep refused every tick for ever"
 * (`settlement/src/server.ts`). Handing back an address bound to a DIFFERENT order because the
 * caller reused a key would file that address under a binding this service never stored, and every
 * sweep of it would be refused for the life of the platform. The 409 costs a caller one retry.
 */
async function findReplay(deps: KeyDeps, input: ProvisionRequest): Promise<ProvisionResult | null> {
  if (input.idempotencyKey !== undefined) {
    const prior = await findKeyByIdempotencyKey(deps.sql, input.createdBy, input.idempotencyKey)
    if (prior) {
      return sameRequest(prior, input) ? { ok: true, key: toKeyRecord(prior), reused: true } : CONFLICT
    }
  }
  if (BINDING_NAMES_ONE_ADDRESS.has(input.purpose)) {
    const prior = await findKeyByBinding(deps.sql, {
      chain: input.chain,
      network: input.network,
      purpose: input.purpose,
      userId: input.userId,
      orderId: input.orderId,
    })
    if (prior) return { ok: true, key: toKeyRecord(prior), reused: true }
  }
  return null
}

/**
 * "The same request" — and `scheme` is deliberately not part of it.
 *
 * These five fields are what the row is derived from and what a signature is later bound to. A
 * scheme is a preference about HOW to derive, and the reply states the one that was actually used,
 * so a caller that asked for a different one is told the truth rather than given a second address
 * for a binding that must only ever name one.
 */
function sameRequest(row: CustodyKeyRow, input: ProvisionRequest): boolean {
  return (
    row.chain === input.chain &&
    row.network === input.network &&
    row.purpose === input.purpose &&
    row.user_id === input.userId &&
    row.order_id === input.orderId
  )
}

/**
 * What to do when the database refused the insert because somebody else got there first.
 *
 * ONLY the two idempotency indexes are treated this way, by name. A 23505 on `custody_keys_pkey`
 * is a second row for one ADDRESS — a derivation collision or a repeated index — and swallowing it
 * would return a key belonging to somebody else; it is re-thrown so the caller gets a 500 and an
 * operator gets a page.
 *
 * The loser has already written an encrypted blob for an address no row will ever name. That is the
 * orphan-blob failure this file chooses on purpose everywhere else: one unreferenced file, at an
 * address that was never published and that nothing can be sent to. It is NOT deleted — this
 * service does not remove key material on an error path, because "the address was never published"
 * is an inference and an unrecoverable deletion is not the place to be inferring.
 */
async function afterLosingTheRace(
  deps: KeyDeps,
  input: ProvisionRequest,
  err: unknown,
): Promise<ProvisionResult | null> {
  const violation = err as { code?: unknown; constraint_name?: unknown }
  if (violation.code !== '23505') return null
  const constraint = violation.constraint_name
  if (typeof constraint !== 'string' || !IDEMPOTENCY_CONSTRAINTS.has(constraint)) return null

  const winner = await findReplay(deps, input)
  if (!winner) {
    // Unreachable unless the winner was rolled back between the violation and this read, which
    // cannot happen: the violation proves it committed. Loud rather than silent, because the
    // alternative to knowing is minting a second address.
    throw new Error(`provisioning lost a race to ${constraint} but the winning row could not be read back`)
  }
  deps.logger.info('provisioning replayed a request that raced itself', {
    audit: 'provision_raced',
    constraint,
    actor: input.createdBy,
    purpose: input.purpose,
  })
  return winner
}

/**
 * The seed for one (user, family), created on first use.
 *
 * The mnemonic is generated, encrypted and written to disk INSIDE the transaction that claims the
 * seed row, for the same reason the address blob is: a committed seed row whose secret is not on
 * disk is a user whose every future address is underivable.
 */
async function ensureSeed(deps: KeyDeps, tx: Tx, userId: string, family: KeyFamily): Promise<{ id: string }> {
  const existing = await findSeed(tx, userId, family)
  if (existing) return existing

  const created = await insertSeed(tx, { userId, family, keyVersion: deps.keyring.writeVersion })
  if (!created) {
    // Lost the race. The winner's row is committed or committing; re-read rather than invent a
    // second seed, because two seeds for one (user, family) means two mnemonics and a user who can
    // only ever recover half their addresses.
    const raced = await findSeed(tx, userId, family)
    if (!raced) throw new Error('custody seed vanished between insert and read')
    return raced
  }

  const mnemonic = newMnemonic()
  const slot = seedSlot(created.id)
  await deps.vault.write(slot, deps.keyring.encrypt(slot, mnemonic))
  return created
}

/* ------------------------------------------------------------------ signing */

export interface SignRequest {
  readonly address: string
  readonly chain: string
  readonly network: string
  readonly family: string
  readonly purpose: string
  readonly userId: string
  readonly orderId: string
  readonly payload: unknown
  readonly actor: string
  readonly correlationId: string
}

export type SignOutcome =
  | { readonly ok: true; readonly signedTx: string; readonly auditId: string }
  | { readonly ok: false; readonly status: number; readonly code: string; readonly gate: string; readonly error: string }

const NOT_FOUND: SignOutcome = {
  ok: false,
  status: 404,
  code: 'not_found',
  gate: 'lookup',
  error: 'address not found',
}

/**
 * The gate pipeline, in the order SD-09 fixes.
 *
 * Read the sequence of `return refused(...)` statements below as the specification: purpose, then
 * binding, then chain id, then pin, and only then `keyring.decrypt`. Every one of those refusals
 * happens with no private key in this process's memory.
 */
export async function signForAddress(deps: KeyDeps, request: SignRequest): Promise<SignOutcome> {
  const row = await getKey(deps.sql, request.address)
  if (!row) return NOT_FOUND

  const identity = rowIdentity(row)
  const claim: RowIdentity = {
    address: request.address,
    chain: request.chain,
    network: request.network,
    userId: request.userId,
    orderId: request.orderId,
    purpose: request.purpose,
    family: request.family,
    status: row.status,
  }
  const payloadDigest = digestOf(request.payload)
  const shape = shapeForRow(row.family, row.purpose)
  // The shape a SUCCESSFUL sign actually went through. It starts as the row-derived one and is
  // replaced by what `signEvm` reports, because a `deposit` payload carrying calldata is a
  // `token_sweep` and only the signer knows that. Refusals keep the row-derived value: a request
  // refused at a gate never reached a shape, and naming one it did not reach would be a guess in
  // the column a dispute reads first.
  let appliedShape: string = shape

  const refused = async (status: number, code: string, gate: string, error: string): Promise<SignOutcome> => {
    await auditOnly(deps, {
      row,
      shape,
      outcome: 'refused',
      gate,
      refusalReason: error,
      actor: request.actor,
      correlationId: request.correlationId,
      payloadDigest,
      signatureDigest: null,
    })
    return { ok: false, status, code, gate, error }
  }

  // ── Gate 1: purpose ───────────────────────────────────────────────────────
  const gate = purposeGate(row)
  if (!gate.ok) return refused(403, 'purpose_forbidden', gate.gate, gate.error)

  // ── Gate 2: the binding, five fields against the stored row ───────────────
  if (!bindingMatches(identity, claim)) {
    // The MESSAGE does not name which field disagreed. That is not an oversight: the binding's
    // entropy is in `userId` and `orderId`, and a 403 that says "orderId was wrong" is an oracle a
    // caller can walk one field at a time. The fields go to the audit row and the log, which the
    // caller does not read.
    deps.logger.warn('sign refused: binding mismatch', {
      address: request.address,
      actor: request.actor,
      fields: bindingMismatches(identity, claim),
    })
    return refused(403, 'binding_mismatch', 'binding', 'sign request does not match this address')
  }

  if (row.network !== 'testnet' && row.network !== 'mainnet') {
    return refused(500, 'internal', 'network', 'address has an unknown network')
  }
  const network = row.network as KeyNetwork

  // ── Gate 3: chain id. A generic `evm` has none, and is refused ────────────
  const chainId = resolveChainId(row, network)
  if (!chainId.ok) return refused(403, 'binding_mismatch', chainId.gate, chainId.error)

  // ── Gate 4: the treasury pin, resolved from the ROW, never from the request ──
  //
  // Note what is NOT happening: the destination is not read from the request and is not compared to
  // anything the caller sent. The caller does not get to name it, even redundantly. It is looked up
  // by the ROW's own chain and network, so a deposit address on ethereum testnet can only ever pay
  // the ethereum-testnet treasury.
  let treasuryPin = ''
  // Empty for every purpose except `deposit`, and empty for a deposit chain with no registered
  // token. An empty allowlist makes `token_sweep` unreachable rather than unbounded.
  let tokenAllowlist: ReadonlySet<string> = EMPTY_ALLOWLIST
  if (row.purpose === 'deposit') {
    tokenAllowlist = await getTokenAllowlist(deps.sql, row.chain, network)
    const pinned = await getTreasuryPin(deps.sql, row.chain, network)
    if (!pinned) {
      return refused(
        403,
        'no_treasury_pinned',
        'treasury_pin',
        `no treasury is pinned for '${row.chain}' ${network} — an operator must set one before ` +
          'deposits on this chain can be swept',
      )
    }
    treasuryPin = pinned
  }

  // ── Gate 5: and only now is anything decrypted ────────────────────────────
  const privateKey = deps.keyring.decrypt(row.address, await deps.vault.read(row.address))

  let signedTx: string
  try {
    const produced = await produceSignature(row, privateKey, request.payload, {
      chainId: chainId.chainId,
      network,
      treasuryPin,
      tokenAllowlist,
    })
    signedTx = produced.signedTx
    appliedShape = produced.shape
  } catch (err) {
    if (err instanceof SignRefused) {
      // A refusal is the caller's fault and is safe to describe: every message is built from
      // constants and from values the caller itself supplied. Anything else is a fault in here and
      // reaches the error handler, which puts no internals in the response body.
      return refused(403, 'shape_refused', 'shape', err.message)
    }
    throw err
  }

  /*
   * SD-09 and SD-15: the audit row and the signature are ONE TRANSACTION.
   *
   * The property this buys is not "we logged it". It is that a signature this service hands back is
   * a signature it has already committed a durable record of — if the insert fails, the transaction
   * rolls back and the caller receives an error rather than a usable transaction nothing recorded.
   * In forge-keyvault a *successful* sign wrote nothing at all; only refusals reached a log line,
   * and a log line is sampled, redacted and expires in 7 to 30 days by design (SD-15).
   *
   * The signature is produced ABOVE this block rather than inside it deliberately: signing is
   * CPU-bound and holds no locks, and doing it inside would keep a transaction open across it for
   * no benefit. What must be transactional is the record, and it is.
   */
  const auditId = await withOutbox(deps.sql, deps.producer, async (tx, emit) => {
    const id = await insertSigningAudit(tx, {
      address: row.address,
      chain: row.chain,
      network: row.network,
      family: row.family,
      purpose: row.purpose,
      shape: appliedShape,
      outcome: 'signed',
      gate: null,
      refusalReason: null,
      userId: row.user_id,
      orderId: row.order_id,
      actor: request.actor,
      correlationId: request.correlationId,
      payloadDigest,
      signatureDigest: digestOf(signedTx),
    })
    emit({
      topic: 'custody.key.signed',
      key: row.address,
      payload: {
        auditId: id,
        address: row.address,
        chain: row.chain,
        network: row.network,
        purpose: row.purpose,
        shape: appliedShape,
        payloadDigest,
      },
      actor: request.actor,
      correlationId: request.correlationId,
    })
    return id
  })

  return { ok: true, signedTx, auditId }
}

/**
 * The signing SHAPE recorded on the audit row, for every family that has one.
 *
 * It used to fall back to the family NAME for anything not EVM, because only EVM had named shapes.
 * Solana and Bitcoin have them now, and recording `'bitcoin'` where the policy actually chosen was
 * `'sweep'` would make the audit trail unable to answer the one question a dispute asks of it:
 * which policy did this signature go through. `xrp` still records the family name — `signXrp` takes
 * its shape from a purpose comparison inline rather than from a mapping function, and inventing one
 * here to feed an audit column would be a second place the XRP mapping lives.
 */
function shapeForRow(family: string, purpose: string): string {
  if (isEvmFamily(family)) return evmShapeForPurpose(purpose)
  if (family === 'solana') return solanaShapeForPurpose(purpose)
  if (family === 'bitcoin') return bitcoinShapeForPurpose(purpose)
  return family
}

function rowIdentity(row: CustodyKeyRow): RowIdentity {
  return {
    address: row.address,
    chain: row.chain,
    network: row.network,
    userId: row.user_id,
    orderId: row.order_id,
    purpose: row.purpose,
    family: row.family,
    status: row.status,
  }
}

/**
 * The allowlist a non-deposit purpose gets: nothing.
 *
 * Frozen and shared rather than allocated per request, and named rather than written inline as
 * `new Set()`, so that every read of the sign path sees the same word for "no token is callable
 * here" and nobody has to work out whether an empty set was intended or forgotten.
 */
const EMPTY_ALLOWLIST: ReadonlySet<string> = new Set<string>()

/** A non-EVM signer returns bytes only; its shape is the row-derived one and does not need refining. */
async function wrap(shape: string, signing: string | Promise<string>): Promise<{ signedTx: string; shape: string }> {
  return { signedTx: await signing, shape }
}

/**
 * Dispatch on the ROW, never on what the caller said.
 *
 * The two are already known to agree — the binding check ran — and the row is the one this service
 * wrote itself.
 */
async function produceSignature(
  row: CustodyKeyRow,
  privateKey: string,
  payload: unknown,
  ctx: {
    chainId: number
    network: KeyNetwork
    treasuryPin: string
    tokenAllowlist: ReadonlySet<string>
  },
): Promise<{ signedTx: string; shape: string }> {
  switch (row.family) {
    case 'evm':
    case 'ember': {
      const shape = evmShapeForPurpose(row.purpose)
      // `row.chain` and NOT `row.family`, which is what this read until ETC arrived. Ethereum
      // Classic's family is `'evm'` — the same value Ethereum carries — and it is pre-London, so a
      // family test says "EIP-1559 is fine" for a chain on which a type-2 transaction is not valid
      // at all. `isLegacyGasOnlyChain` is where the list and the evidence for it live.
      const legacyOnly = isLegacyGasOnlyChain(row.chain)
      // Built as a union member rather than one object with an optional pin, so a 'sweep' with no
      // pin does not compile. `treasuryPin` is non-empty here because 'sweep' is reachable only from
      // purpose 'deposit', which is the branch that resolved it — and `signing.ts` refuses an empty
      // one anyway, because a compile-time argument is not a check.
      const policy: EvmPolicy =
        shape === 'sweep'
          ? {
              chainId: ctx.chainId,
              shape,
              treasuryPin: ctx.treasuryPin,
              tokenAllowlist: ctx.tokenAllowlist,
              legacyOnly,
            }
          : { chainId: ctx.chainId, shape, legacyOnly }
      return signEvm(privateKey, payload, policy)
    }
    case 'solana': {
      const shape = solanaShapeForPurpose(row.purpose)
      // A union member, not an object with an optional pin, for `EvmPolicy`'s reason: a 'sweep' with
      // no pin must not compile.
      const policy: SolanaPolicy = shape === 'sweep' ? { shape, treasuryPin: ctx.treasuryPin } : { shape }
      return wrap(shape, signSolana(privateKey, payload, row.address, policy))
    }
    case 'bitcoin': {
      const shape = bitcoinShapeForPurpose(row.purpose)
      const policy: BitcoinPolicy = shape === 'sweep' ? { shape, treasuryPin: ctx.treasuryPin } : { shape }
      // `row.chain` and never the family: Litecoin and Bitcoin share the family and differ in
      // every network parameter that matters. The row is the authority — it is what custody minted
      // the key under, and it is what the WIF's version byte was chosen from.
      return wrap(shape, signBitcoin(privateKey, payload, row.address, ctx.network, policy, row.chain))
    }
    case 'xrp':
      // `shapeForRow` deliberately records the FAMILY name for XRP rather than a policy shape,
      // because signXrp takes its shape from an inline purpose comparison and inventing a mapping
      // here to feed the audit column would be a second place that mapping lives. Preserved.
      return wrap(
        shapeForRow(row.family, row.purpose),
        signXrp(
          privateKey,
          payload,
          row.address,
          row.purpose === 'deposit' ? { shape: 'sweep', treasuryPin: ctx.treasuryPin } : { shape: 'payment' },
        ),
      )
    default:
      throw new Error(`no signer for family '${row.family}'`)
  }
}

/** A refusal's audit row, in its own transaction. SD-15: every refusal is an audit event too. */
async function auditOnly(
  deps: KeyDeps,
  input: {
    row: CustodyKeyRow
    shape: string
    outcome: 'refused'
    gate: string
    refusalReason: string
    actor: string
    correlationId: string
    payloadDigest: string
    signatureDigest: string | null
  },
): Promise<void> {
  await withOutbox(deps.sql, deps.producer, async (tx, emit) => {
    const id = await insertSigningAudit(tx, {
      address: input.row.address,
      chain: input.row.chain,
      network: input.row.network,
      family: input.row.family,
      purpose: input.row.purpose,
      shape: input.shape,
      outcome: 'refused',
      gate: input.gate,
      refusalReason: input.refusalReason.slice(0, 500),
      userId: input.row.user_id,
      orderId: input.row.order_id,
      actor: input.actor,
      correlationId: input.correlationId,
      payloadDigest: input.payloadDigest,
      signatureDigest: null,
    })
    emit({
      topic: 'custody.key.sign_refused',
      key: input.row.address,
      payload: { auditId: id, address: input.row.address, gate: input.gate },
      actor: input.actor,
      correlationId: input.correlationId,
    })
  })
}

/** A correlation id when the caller supplied none. */
export function newCorrelationId(): string {
  return randomUUID()
}
