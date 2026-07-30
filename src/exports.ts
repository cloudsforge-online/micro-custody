/**
 * The export ceremony — SD-07, and the replacement for the route SD-08 deletes.
 *
 * WHAT WAS DELETED AND WHY. `POST /admin/keys/:address/reveal` accepted any address, decrypted it,
 * and returned the plaintext private key to any holder of an administrator JWT — for every customer
 * deposit key in custody. There was no approval, no rate limit, no scoping and no bulk protection,
 * so a loop over `GET /admin/keys` followed by that route exfiltrated the entire estate. Its only
 * mitigation was an audit row, and an audit row tells you afterwards that every key is gone. **That
 * route does not exist in this service**, `routes.test.ts` asserts it 404s, and the genuine
 * break-glass cases it was justified by are met by a two-operator offline procedure against a
 * database backup — which does not need a network-reachable HTTP endpoint at all.
 *
 * WHAT REPLACES IT IS A USER RIGHT, NOT AN OPERATOR POWER. 01-product-vision principle 2: a user can
 * always leave with their assets. The safeguards are ours to design; the right is not ours to
 * withhold. Note that no operator credential can complete this ceremony — every step requires the
 * user's own token — which is the control against the malicious-insider case that the deleted route
 * had no answer for.
 *
 * **EXPORT IS NOT A READ; IT IS A STATE TRANSITION.** `active → exported`, irreversibly. An exported
 * key is a key two parties hold, and a platform that kept sweeping deposits from it into its own
 * treasury would be misrepresenting custody to the user and setting up a reconciliation break. The
 * transition is enforced in `store.markExported` (a `where status = 'active'` that a second
 * redemption cannot satisfy) and honoured in `gates.purposeGate`, which refuses to sign for it.
 *
 * THE GATES, AND WHERE EACH ONE LIVES:
 *
 *   1  re-authenticate with password  — `amr` must contain `pwd`; identity mints the claim.
 *   2  MFA challenge                  — `amr` must contain `mfa`.
 *   3  policy.decide                  — `policy.ts`, fail-closed.
 *   4  24-hour cooling-off            — `available_at`; the only control that works while the user
 *                                       is actively being deceived, which is why gates 1, 2 and 6
 *                                       do not substitute for it.
 *   5  critical notification          — emitted as events; the notifier is another service.
 *   6  second MFA at redemption       — a FRESH `amr`+`auth_time`, so the attacker must still hold
 *                                       the factor a day later.
 *   7  single-use, short-TTL token    — SHA-256 at rest, constant-time compare, spent on first use.
 *   8  delivered once, never logged   — the material is returned and never written anywhere.
 *   9  wallet → exported              — `markExported`, in the redemption's own transaction.
 *   10 recorded both sides            — an audit event on request, cancel and completion.
 */

import { createHash, randomBytes } from 'node:crypto'
import { ethers } from 'ethers'
import type { Logger } from '@cloudsforge/telemetry'
import { secretEquals, type Keyring } from './crypto.ts'
import { seedFromMnemonic } from './hd.ts'
import type { PolicyClient } from './policy.ts'
import { withOutbox, type Db, type Tx } from './outbox.ts'
import { getKey, markExported, type CustodyKeyRow } from './store.ts'
import { seedSlot, type Vault } from './vault.ts'

export type ExportStatus =
  | 'requested'
  | 'cooling_off'
  | 'challenged'
  | 'redeemed'
  | 'cancelled'
  | 'denied'
  | 'expired'

/** The formats SD-07 offers. Which ones are OFFERABLE depends on the key, see `formatRefusal`. */
export type ExportFormat = 'keystore' | 'mnemonic' | 'raw' | 'wif' | 'xrp_seed'

export const EXPORT_FORMATS: readonly ExportFormat[] = ['keystore', 'mnemonic', 'raw', 'wif', 'xrp_seed']

export interface ExportRow {
  readonly id: string
  readonly address: string
  readonly user_id: string
  readonly status: string
  readonly format: string
  readonly policy_decision: string | null
  readonly policy_reasons: unknown
  readonly requested_at: Date
  readonly available_at: Date | null
  readonly expires_at: Date
  readonly challenged_at: Date | null
  readonly token_hash: string | null
  readonly token_expires_at: Date | null
  readonly redeemed_at: Date | null
  readonly cancelled_at: Date | null
  readonly created_by: string
}

/**
 * The public projection of a ceremony. **It has no field that could carry key material or the reveal
 * token**, which is what makes the SD-16 response-body scan a property of the type rather than of
 * every route that returns one.
 */
export interface ExportRecord {
  readonly id: string
  readonly address: string
  readonly status: string
  readonly format: string
  readonly requestedAt: string
  readonly availableAt: string | null
  readonly expiresAt: string
  readonly challengedAt: string | null
  readonly tokenExpiresAt: string | null
  readonly redeemedAt: string | null
  readonly cancelledAt: string | null
  readonly policyDecision: string | null
  readonly policyReasons: readonly string[]
}

export function toExportRecord(row: ExportRow): ExportRecord {
  return {
    id: row.id,
    address: row.address,
    status: row.status,
    format: row.format,
    requestedAt: row.requested_at.toISOString(),
    availableAt: row.available_at?.toISOString() ?? null,
    expiresAt: row.expires_at.toISOString(),
    challengedAt: row.challenged_at?.toISOString() ?? null,
    tokenExpiresAt: row.token_expires_at?.toISOString() ?? null,
    redeemedAt: row.redeemed_at?.toISOString() ?? null,
    cancelledAt: row.cancelled_at?.toISOString() ?? null,
    policyDecision: row.policy_decision,
    policyReasons: Array.isArray(row.policy_reasons) ? (row.policy_reasons as string[]) : [],
  }
}

export interface ExportDeps {
  readonly sql: Db
  readonly vault: Vault
  readonly keyring: Keyring
  readonly policy: PolicyClient
  readonly logger: Logger
  readonly producer: string
  readonly coolingOffMs: number
  readonly tokenTtlMs: number
  readonly requestTtlMs: number
  /** Injected so the timers can be driven in a test without waiting a day. */
  readonly now?: () => number
}

export type ExportFailure = { readonly ok: false; readonly status: number; readonly code: string; readonly error: string }
export type ExportResult<T> = { readonly ok: true; readonly value: T } | ExportFailure

function fail(status: number, code: string, error: string): ExportFailure {
  return { ok: false, status, code, error }
}

const nowOf = (deps: ExportDeps): number => (deps.now ?? Date.now)()

/* ------------------------------------------------------------------ format rules */

/**
 * Whether a format can be honestly offered for a key, decided AT REQUEST TIME.
 *
 * Checked here rather than at redemption so a user is not told "no" after waiting a day. SDR-08 is
 * the reason the answer is ever no: a legacy `flat_random` key was generated without an HD seed and
 * cannot be retrofitted with one, so a recovery phrase for it does not exist and offering one would
 * be inventing a phrase that restores nothing.
 */
export function formatRefusal(row: CustodyKeyRow, format: ExportFormat): string | null {
  switch (format) {
    case 'mnemonic':
      if (row.scheme !== 'hd_bip44') {
        return (
          'this address predates HD derivation — it is a single flat random key with no seed, so no ' +
          'recovery phrase exists for it. Export it as a raw key or a keystore instead'
        )
      }
      return null
    case 'keystore':
      if (row.family !== 'evm' && row.family !== 'ember') {
        return 'the encrypted UTC/JSON keystore format is defined for secp256k1 EVM keys only'
      }
      return null
    case 'wif':
      return row.family === 'bitcoin' ? null : 'WIF is a Bitcoin format'
    case 'xrp_seed':
      return row.family === 'xrp' ? null : 'the family seed is an XRP format'
    case 'raw':
      return null
  }
}

/* ------------------------------------------------------------------ gate 1 + 2: the request */

export interface RequestExportInput {
  readonly address: string
  readonly userId: string
  readonly format: ExportFormat
  readonly actor: string
  readonly correlationId: string
  /** Authentication-method claims from the presented token. Gates 1 and 2. */
  readonly amr: readonly string[]
  readonly context: Record<string, unknown>
}

export async function requestExport(deps: ExportDeps, input: RequestExportInput): Promise<ExportResult<ExportRecord>> {
  const row = await getKey(deps.sql, input.address)
  if (!row) return fail(404, 'not_found', 'address not found')
  // Ownership before anything else. A user may export a wallet THEY own; the check is the same
  // per-user comparison the signing path was missing entirely.
  if (row.user_id !== input.userId) return fail(404, 'not_found', 'address not found')
  if (row.status !== 'active') {
    return fail(409, 'not_exportable', `this address is '${row.status}' and cannot be exported again`)
  }
  if (row.purpose === 'treasury' || row.purpose === 'deployer') {
    // Platform keys. They belong to no customer, so there is no user right to exercise over them,
    // and a route that could hand one out would be the deleted reveal route with extra steps.
    return fail(403, 'not_exportable', 'platform-owned addresses are not user-exportable')
  }

  if (!input.amr.includes('pwd')) {
    return fail(401, 'reauthentication_required', 'export requires a fresh password re-authentication')
  }
  if (!input.amr.includes('mfa')) {
    return fail(401, 'mfa_required', 'export requires a multi-factor challenge')
  }

  const refusal = formatRefusal(row, input.format)
  if (refusal) return fail(400, 'format_unavailable', refusal)

  const decision = await deps.policy.decide(
    {
      subject: `user:${input.userId}`,
      action: 'custody.key.export',
      resource: `custody:key:${row.address}`,
      context: { ...input.context, chain: row.chain, network: row.network, scheme: row.scheme },
    },
    { requestId: input.correlationId },
  )

  const now = nowOf(deps)
  const requestedAt = new Date(now)
  const expiresAt = new Date(now + deps.requestTtlMs)

  if (decision.effect !== 'allow') {
    // `challenge` and `review` are NOT partial successes here. They mean "not on this evidence", and
    // a ceremony left open on either would be one an attacker can return to. The user re-requests
    // once the obligation is met; the decision and its reasons are recorded either way.
    const denied = await insertExport(deps.sql, {
      address: row.address,
      userId: input.userId,
      status: 'denied',
      format: input.format,
      policyDecision: decision.effect,
      policyReasons: decision.reasons,
      availableAt: null,
      expiresAt,
      createdBy: input.actor,
    })
    deps.logger.warn('export refused by policy', {
      address: row.address,
      effect: decision.effect,
      reasons: decision.reasons,
    })
    return { ok: true, value: toExportRecord(denied) }
  }

  const availableAt = new Date(now + deps.coolingOffMs)
  const created = await withOutbox(deps.sql, deps.producer, async (tx, emit) => {
    const created = await insertExport(tx, {
      address: row.address,
      userId: input.userId,
      status: 'cooling_off',
      format: input.format,
      policyDecision: decision.effect,
      policyReasons: decision.reasons,
      availableAt,
      expiresAt,
      createdBy: input.actor,
    })
    // Gate 5. The notification itself belongs to the notifier, not here — custody's job is to make
    // the fact undeniable and delivered exactly once, which is what the outbox is for.
    emit({
      topic: 'custody.export.requested',
      key: row.address,
      payload: {
        exportId: created.id,
        address: row.address,
        userId: input.userId,
        format: input.format,
        availableAt: availableAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        severity: 'critical',
      },
      actor: input.actor,
      correlationId: input.correlationId,
    })
    return created
  })

  deps.logger.warn('export requested', {
    audit: 'export_requested',
    exportId: created.id,
    address: row.address,
    availableAt: availableAt.toISOString(),
  })
  void requestedAt
  return { ok: true, value: toExportRecord(created) }
}

/* ------------------------------------------------------------------ gate 6 + 7: the challenge */

export interface ChallengeResult {
  readonly export: ExportRecord
  /**
   * The single-use reveal token, in the clear, EXACTLY ONCE. Only the SHA-256 is stored. It is
   * returned from this function, put in one response body, and never logged, never persisted and
   * never returned again.
   */
  readonly revealToken: string
}

export async function challengeExport(
  deps: ExportDeps,
  input: { id: string; userId: string; amr: readonly string[]; authTimeSeconds: number | null; correlationId: string },
): Promise<ExportResult<ChallengeResult>> {
  const row = await getExport(deps.sql, input.id)
  if (!row || row.user_id !== input.userId) return fail(404, 'not_found', 'export request not found')

  const now = nowOf(deps)
  if (row.expires_at.getTime() <= now) return fail(409, 'expired', 'this export request has expired')
  if (row.status === 'challenged' && row.token_expires_at && row.token_expires_at.getTime() > now) {
    // A live token already exists. Minting a second would leave two redeemable secrets for one
    // ceremony, so the first would survive a cancel of the second.
    return fail(409, 'already_challenged', 'a reveal token is already outstanding for this request')
  }
  if (row.status !== 'cooling_off' && row.status !== 'challenged') {
    return fail(409, 'not_challengeable', `an export in state '${row.status}' cannot be challenged`)
  }
  if (!row.available_at || row.available_at.getTime() > now) {
    // GATE 4, and it is the reason the whole ceremony exists. Answering with the remaining time
    // rather than a bare refusal is deliberate: the user is meant to know a hold is running.
    const seconds = Math.ceil(((row.available_at?.getTime() ?? now) - now) / 1_000)
    return fail(409, 'cooling_off', `the 24-hour cooling-off has not elapsed — ${seconds}s remaining`)
  }

  // GATE 6. A FRESH factor, not the one presented a day ago: `auth_time` must be recent, so an
  // attacker holding a stolen session must still hold the second factor now.
  if (!input.amr.includes('mfa')) return fail(401, 'mfa_required', 'redemption requires a second multi-factor challenge')
  if (input.authTimeSeconds === null || now - input.authTimeSeconds * 1_000 > deps.tokenTtlMs) {
    return fail(401, 'stale_authentication', 'the multi-factor challenge must have been completed just now')
  }

  // 32 bytes, base64url. Long enough that guessing is not a threat model, and the store keeps only
  // its SHA-256 — exactly as a refresh token is kept, and for the same reason: a table that holds
  // live reveal tokens is a key-reveal primitive, which is what SD-08 deleted a route over.
  const revealToken = randomBytes(32).toString('base64url')
  const tokenExpiresAt = new Date(now + deps.tokenTtlMs)

  const updated = await updateExport(
    deps.sql,
    input.id,
    {
      status: 'challenged',
      challenged_at: new Date(now),
      token_hash: hashToken(revealToken),
      token_expires_at: tokenExpiresAt,
    },
    ['cooling_off', 'challenged'],
  )
  if (!updated) return fail(409, 'not_challengeable', 'this export request changed state; re-read it')

  return { ok: true, value: { export: toExportRecord(updated), revealToken } }
}

/* ------------------------------------------------------------------ gate 8 + 9: redemption */

export interface RevealedKey {
  readonly address: string
  readonly chain: string
  readonly network: string
  readonly scheme: string
  readonly derivationPath: string | null
  readonly format: ExportFormat
  /** The material. This is the ONE field in this service that carries a secret to a caller. */
  readonly material: string
}

export async function redeemExport(
  deps: ExportDeps,
  input: { id: string; userId: string; revealToken: string; passphrase?: string; correlationId: string },
): Promise<ExportResult<RevealedKey>> {
  const row = await getExport(deps.sql, input.id)
  if (!row || row.user_id !== input.userId) return fail(404, 'not_found', 'export request not found')
  if (row.status !== 'challenged') return fail(409, 'not_redeemable', `an export in state '${row.status}' cannot be redeemed`)

  const now = nowOf(deps)
  if (!row.token_expires_at || row.token_expires_at.getTime() <= now) {
    return fail(409, 'token_expired', 'the reveal token has expired — complete the challenge again')
  }
  // Constant-time. A byte-at-a-time comparison of a bearer secret is a byte-at-a-time forgery
  // oracle, and this is the one secret in the estate that yields a private key.
  if (!row.token_hash || !secretEquals(row.token_hash, hashToken(input.revealToken))) {
    deps.logger.warn('export redemption presented a bad reveal token', { exportId: row.id, address: row.address })
    return fail(403, 'bad_token', 'the reveal token is not the one issued for this request')
  }

  const key = await getKey(deps.sql, row.address)
  if (!key) return fail(404, 'not_found', 'address not found')

  const format = row.format as ExportFormat
  if (format === 'keystore' && (!input.passphrase || input.passphrase.length < 12)) {
    return fail(400, 'passphrase_required', 'an encrypted keystore needs a passphrase of at least 12 characters')
  }

  const material = await materialise(deps, key, format, input.passphrase)
  if (!material.ok) return material

  /*
   * The state transition and the audit, in ONE transaction, and BEFORE the material is returned.
   *
   * `markExported` carries `where status = 'active'`, so the second of two concurrent redemptions
   * updates nothing and this whole transaction refuses — which is what makes single-use a property
   * of the database rather than of the order two requests happen to arrive in.
   */
  const committed = await withOutbox(deps.sql, deps.producer, async (tx, emit) => {
    const spent = await updateExport(tx, row.id, { status: 'redeemed', redeemed_at: new Date(now), token_hash: null }, [
      'challenged',
    ])
    if (!spent) return { value: null }
    const transitioned = await markExported(tx, row.address)
    if (!transitioned) return { value: null }
    emit({
      topic: 'custody.export.completed',
      key: row.address,
      payload: {
        exportId: row.id,
        address: row.address,
        userId: row.user_id,
        format,
        severity: 'critical',
        // The material is NOT in the event. An event is delivered over HTTP to subscribers and
        // stored in an outbox table; putting a key in one would defeat every other control here.
      },
      actor: `user:${input.userId}`,
      correlationId: input.correlationId,
    })
    return { value: toExportRecord(spent) }
  })
  if (!committed.value) return fail(409, 'not_redeemable', 'this export was already redeemed or cancelled')

  // Logged as an event, with no material and no token. SD-07 gate 8: delivered once, never logged.
  deps.logger.warn('export redeemed', { audit: 'export_completed', exportId: row.id, address: row.address, format })

  return {
    ok: true,
    value: {
      address: key.address,
      chain: key.chain,
      network: key.network,
      scheme: key.scheme,
      derivationPath: key.derivation_path,
      format,
      material: material.value,
    },
  }
}

/** Turn the stored blob into the requested format. The only place plaintext material is produced. */
async function materialise(
  deps: ExportDeps,
  key: CustodyKeyRow,
  format: ExportFormat,
  passphrase: string | undefined,
): Promise<ExportResult<string>> {
  const refusal = formatRefusal(key, format)
  if (refusal) return fail(400, 'format_unavailable', refusal)

  if (format === 'mnemonic') {
    if (!key.seed_id) return fail(400, 'format_unavailable', 'this address has no seed')
    const slot = seedSlot(key.seed_id)
    // The phrase is the seed for EVERY address of this (user, family), not just this one. That is
    // inherent to BIP-44 and it is why the response states the derivation path: a user restoring
    // this phrase gets all of their addresses in that family, which is the point of a phrase.
    return { ok: true, value: deps.keyring.decrypt(slot, await deps.vault.read(slot)) }
  }

  const secret = deps.keyring.decrypt(key.address, await deps.vault.read(key.address))

  if (format === 'keystore') {
    // The DEFAULT for EVM, and SD-07's reason is worth restating: it is the only offered format that
    // is safe to save to disk, because what lands in the file is scrypt-wrapped rather than the key.
    const json = await new ethers.Wallet(secret).encrypt(passphrase!)
    return { ok: true, value: json }
  }

  // raw / wif / xrp_seed are all "the stored form", which is already the native one per family:
  // 0x-hex for EVM, base64 of the 64-byte secret key for Solana, WIF for Bitcoin, a family seed for
  // XRP. There is deliberately no re-encoding step — a format conversion in the one function that
  // handles plaintext is a bug that costs a customer their coins.
  return { ok: true, value: secret }
}

/* ------------------------------------------------------------------ cancel and expiry */

export async function cancelExport(
  deps: ExportDeps,
  input: { id: string; userId: string; actor: string; correlationId: string },
): Promise<ExportResult<ExportRecord>> {
  const row = await getExport(deps.sql, input.id)
  if (!row || row.user_id !== input.userId) return fail(404, 'not_found', 'export request not found')

  const cancelled = await withOutbox(deps.sql, deps.producer, async (tx, emit) => {
    const updated = await updateExport(tx, input.id, { status: 'cancelled', cancelled_at: new Date(nowOf(deps)), token_hash: null }, [
      'requested',
      'cooling_off',
      'challenged',
    ])
    if (!updated) return { value: null }
    emit({
      topic: 'custody.export.cancelled',
      key: row.address,
      payload: { exportId: row.id, address: row.address, userId: row.user_id, severity: 'critical' },
      actor: input.actor,
      correlationId: input.correlationId,
    })
    return { value: toExportRecord(updated) }
  })
  if (!cancelled.value) return fail(409, 'not_cancellable', `an export in state '${row.status}' cannot be cancelled`)
  return { ok: true, value: cancelled.value }
}

/**
 * Time out the ceremonies nobody finished. A leased job, not a timer — see `jobs.ts`.
 *
 * Clearing `token_hash` on the way is the part that matters: an expired-but-present hash is a
 * secret sitting in a table for no reason, and "nobody can redeem it any more" is a property of a
 * timestamp comparison somebody could edit.
 */
export async function expireExports(deps: ExportDeps): Promise<number> {
  const rows = await deps.sql<{ id: string }[]>`
    update key_exports
       set status = 'expired', token_hash = null
     where status in ('requested','cooling_off','challenged')
       and expires_at <= ${new Date(nowOf(deps))}
    returning id
  `
  return rows.length
}

/* ------------------------------------------------------------------ storage */

export async function getExport(sql: Db | Tx, id: string): Promise<ExportRow | null> {
  const rows = await sql<ExportRow[]>`select * from key_exports where id = ${id}`
  return rows[0] ?? null
}

export async function listExportsForUser(sql: Db, userId: string, limit: number): Promise<ExportRow[]> {
  return sql<ExportRow[]>`
    select * from key_exports where user_id = ${userId} order by requested_at desc limit ${limit}
  `
}

async function insertExport(
  sql: Db | Tx,
  input: {
    address: string
    userId: string
    status: ExportStatus
    format: ExportFormat
    policyDecision: string
    policyReasons: readonly string[]
    availableAt: Date | null
    expiresAt: Date
    createdBy: string
  },
): Promise<ExportRow> {
  const rows = await sql<ExportRow[]>`
    insert into key_exports
      (address, user_id, status, format, policy_decision, policy_reasons, available_at, expires_at, created_by)
    values
      (${input.address}, ${input.userId}, ${input.status}, ${input.format}, ${input.policyDecision},
       ${sql.json([...input.policyReasons] as never)}, ${input.availableAt}, ${input.expiresAt}, ${input.createdBy})
    returning *
  `
  const row = rows[0]
  if (!row) throw new Error('insert returned no row')
  return row
}

/**
 * Update a ceremony, but only out of a state it is legal to leave.
 *
 * The `status = any(...)` predicate is the state machine: every transition names the states it may
 * come from, so a concurrent request that already moved the row updates nothing and the caller gets
 * a 409 rather than a second reveal token for a ceremony that has been cancelled.
 */
async function updateExport(
  sql: Db | Tx,
  id: string,
  patch: Partial<{
    status: ExportStatus
    challenged_at: Date
    token_hash: string | null
    token_expires_at: Date
    redeemed_at: Date
    cancelled_at: Date
  }>,
  fromStatuses: readonly ExportStatus[],
): Promise<ExportRow | null> {
  const rows = await sql<ExportRow[]>`
    update key_exports set ${sql(patch as Record<string, never>)}
     where id = ${id} and status = any(${[...fromStatuses]})
    returning *
  `
  return rows[0] ?? null
}

/** SHA-256 hex. The token is never stored, only this. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

/** Re-derive an address from a seed, to prove an exported phrase restores. Used by the tests. */
export function addressFromMnemonic(mnemonic: string): Buffer {
  return seedFromMnemonic(mnemonic)
}
