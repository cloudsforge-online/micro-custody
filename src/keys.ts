/**
 * Provisioning an address, and signing with one.
 *
 * The two operations that touch key material, kept together and kept away from the HTTP layer so
 * that the order of the gates is readable in one place and cannot be reordered by editing a route.
 */

import { createHash, randomUUID } from 'node:crypto'
import type { Logger } from '@cloudsforge/telemetry'
import type { Keyring } from './crypto.ts'
import { familyForChain, generateFlatRandom, isEvmFamily, type KeyFamily, type KeyNetwork } from './chains.ts'
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
  getKey,
  getTreasuryPin,
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
}

export type ProvisionResult =
  | { readonly ok: true; readonly key: CustodyKeyRecord }
  | { readonly ok: false; readonly code: string; readonly error: string }

/**
 * Mint an address.
 *
 * THE ORDER OF THE WRITES IS A CORRECTNESS PROPERTY, NOT A STYLE. The encrypted blob reaches the
 * disk BEFORE the row that names it is committed. The two failure windows are not symmetrical:
 *
 *   crash after the blob, before the commit — an orphan blob at an address no row references.
 *     Costs one file. Nothing can ever be sent there, because the address was never published.
 *   crash after the commit, before the blob — a row naming an address whose key does not exist.
 *     The address IS published, a customer deposits to it, and the coins are unrecoverable.
 *
 * So the cheap failure is the one this ordering chooses, every time.
 */
export async function provisionAddress(deps: KeyDeps, input: ProvisionRequest): Promise<ProvisionResult> {
  const family = familyForChain(input.chain)
  if (!family) return { ok: false, code: 'unknown_chain', error: `'${input.chain}' is not a chain this service holds keys for` }

  const scheme: Scheme = input.scheme ?? 'hd_bip44'

  if (scheme === 'flat_random' && family === 'xrp') {
    // THE XRP NETWORK-BINDING FIX, ENFORCED AT THE ONLY PLACE IT CAN BE. A flat random XRP family
    // seed produces one classic address that is valid on testnet and mainnet alike, so a signed
    // Payment is submittable on either — SD-09's named defect. HD derivation fixes it by putting the
    // network in the BIP-44 coin type, and the fix only holds if there is no path left that mints
    // an XRP key without it. Adopted legacy rows keep the residual; nothing minted here adds one.
    return {
      ok: false,
      code: 'scheme_refused',
      error:
        'XRP addresses are HD-derived only — a flat-random family seed produces one address valid ' +
        'on both networks, so a signed Payment would be submittable on either',
    }
  }

  const generated = await deps.sql
    .begin(async (tx) => {
      let seedId: string | null = null
      let derivationPath: string | null = null
      let address: string
      let privateKey: string

      if (scheme === 'hd_bip44') {
        const seed = await ensureSeed(deps, tx, input.userId, family)
        const index = await takeNextIndex(tx, seed.id)
        const mnemonic = deps.keyring.decrypt(seedSlot(seed.id), await deps.vault.read(seedSlot(seed.id)))
        const derived = deriveKey(seedFromMnemonic(mnemonic), family, input.network, index)
        seedId = seed.id
        derivationPath = derived.derivationPath
        address = derived.address
        privateKey = derived.privateKey
      } else {
        const flat = generateFlatRandom(family, input.network)
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
      })
      return { row: [row] }
    })
    .then((r) => r.row[0]!)

  // The event is emitted in its own transaction rather than inside the one above, because the one
  // above holds a row lock on the seed for the whole of a scrypt derivation. Keeping the outbox
  // write out of it keeps the lock as short as the work that needs it.
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

  return { ok: true, key: toKeyRecord(generated) }
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
  if (row.purpose === 'deposit') {
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
    signedTx = await produceSignature(row, privateKey, request.payload, {
      chainId: chainId.chainId,
      network,
      treasuryPin,
    })
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
      shape,
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
        shape,
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
 * Dispatch on the ROW, never on what the caller said.
 *
 * The two are already known to agree — the binding check ran — and the row is the one this service
 * wrote itself.
 */
async function produceSignature(
  row: CustodyKeyRow,
  privateKey: string,
  payload: unknown,
  ctx: { chainId: number; network: KeyNetwork; treasuryPin: string },
): Promise<string> {
  switch (row.family) {
    case 'evm':
    case 'ember': {
      const shape = evmShapeForPurpose(row.purpose)
      // Built as a union member rather than one object with an optional pin, so a 'sweep' with no
      // pin does not compile. `treasuryPin` is non-empty here because 'sweep' is reachable only from
      // purpose 'deposit', which is the branch that resolved it — and `signing.ts` refuses an empty
      // one anyway, because a compile-time argument is not a check.
      const policy: EvmPolicy =
        shape === 'sweep'
          ? { chainId: ctx.chainId, shape, treasuryPin: ctx.treasuryPin, legacyOnly: row.family === 'ember' }
          : { chainId: ctx.chainId, shape, legacyOnly: row.family === 'ember' }
      return signEvm(privateKey, payload, policy)
    }
    case 'solana': {
      const shape = solanaShapeForPurpose(row.purpose)
      // A union member, not an object with an optional pin, for `EvmPolicy`'s reason: a 'sweep' with
      // no pin must not compile.
      const policy: SolanaPolicy = shape === 'sweep' ? { shape, treasuryPin: ctx.treasuryPin } : { shape }
      return signSolana(privateKey, payload, row.address, policy)
    }
    case 'bitcoin': {
      const shape = bitcoinShapeForPurpose(row.purpose)
      const policy: BitcoinPolicy = shape === 'sweep' ? { shape, treasuryPin: ctx.treasuryPin } : { shape }
      return signBitcoin(privateKey, payload, row.address, ctx.network, policy)
    }
    case 'xrp':
      return signXrp(
        privateKey,
        payload,
        row.address,
        row.purpose === 'deposit' ? { shape: 'sweep', treasuryPin: ctx.treasuryPin } : { shape: 'payment' },
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

/** A treasury mint's binding, DERIVED rather than accepted from the caller. */
export function treasuryBinding(chain: string, network: KeyNetwork): { userId: string; orderId: string } {
  return { userId: 'cloudsforge:treasury', orderId: `treasury:${chain}:${network}` }
}

/** A correlation id when the caller supplied none. */
export function newCorrelationId(): string {
  return randomUUID()
}
