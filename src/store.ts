/**
 * Every query custody makes, and the row shapes the rest of the service sees.
 *
 * Two rules are enforced here rather than left to the callers:
 *
 *   1. **No projection carries key material.** `CustodyKeyRecord` is the only shape any route may
 *      return, and it has no field that could hold one. SD-16's response-body scan proves the
 *      property end to end; this type is what makes it hard to break in the first place.
 *   2. **The treasury pin has exactly one writer** (`pinTreasury`), and it validates. A pin may only
 *      ever name an address this service minted, with `purpose = 'treasury'`, on the same chain and
 *      the same network — so a typo produces a refusal rather than a pin, and an attacker cannot pin
 *      an address they hold the key to, because this service has never seen one.
 */

import type { Db, Tx } from './outbox.ts'

export type Purpose = 'deposit' | 'treasury' | 'deployer' | 'user'
export type Scheme = 'flat_random' | 'hd_bip44'
export type KeyStatus = 'active' | 'exported' | 'retired'

export interface CustodyKeyRow {
  readonly address: string
  readonly chain: string
  readonly family: string
  readonly purpose: string
  readonly network: string
  readonly user_id: string
  readonly order_id: string
  readonly scheme: string
  readonly derivation_path: string | null
  readonly seed_id: string | null
  readonly key_version: number
  readonly storage: string
  readonly status: string
  readonly created_by: string
  readonly created_at: Date
  readonly exported_at: Date | null
}

/**
 * The public projection. **The only shape a route may return for a key.**
 *
 * `scheme` and `derivationPath` are published deliberately: 04-domain-model §3.3 says every custody
 * response states the scheme because it decides which export formats can be offered, and SDR-08
 * says a legacy key's inability to produce a recovery phrase is surfaced honestly rather than
 * hidden. A path is not a secret — it is public in every HD wallet's UI — and without it a user who
 * exports a mnemonic cannot find their own funds.
 *
 * `userId` and `orderId` are NOT here. That is carried forward from forge-keyvault, where
 * `GET /addresses/:address` used to serve them and thereby made the /sign binding check circular:
 * everything a caller had to "prove" it knew was served, under the same credential, from a read.
 * The binding's entropy is entirely in those two fields. The admin projection below adds them back,
 * because an operator investigating an address needs them and holds a different credential.
 */
export interface CustodyKeyRecord {
  readonly address: string
  readonly chain: string
  readonly family: string
  readonly purpose: string
  readonly network: string
  readonly scheme: string
  readonly derivationPath: string | null
  readonly status: string
  readonly keyVersion: number
  readonly createdAt: string
  readonly exportedAt: string | null
}

export interface CustodyKeyAdminRecord extends CustodyKeyRecord {
  readonly userId: string
  readonly orderId: string
  readonly storage: string
  readonly createdBy: string
}

export function toKeyRecord(row: CustodyKeyRow): CustodyKeyRecord {
  return {
    address: row.address,
    chain: row.chain,
    family: row.family,
    purpose: row.purpose,
    network: row.network,
    scheme: row.scheme,
    derivationPath: row.derivation_path,
    status: row.status,
    keyVersion: row.key_version,
    createdAt: row.created_at.toISOString(),
    exportedAt: row.exported_at?.toISOString() ?? null,
  }
}

export function toKeyAdminRecord(row: CustodyKeyRow): CustodyKeyAdminRecord {
  return {
    ...toKeyRecord(row),
    userId: row.user_id,
    orderId: row.order_id,
    storage: row.storage,
    createdBy: row.created_by,
  }
}

/* ------------------------------------------------------------------ keys */

export interface InsertKey {
  readonly address: string
  readonly chain: string
  readonly family: string
  readonly purpose: Purpose
  readonly network: string
  readonly userId: string
  readonly orderId: string
  readonly scheme: Scheme
  readonly derivationPath: string | null
  readonly seedId: string | null
  readonly keyVersion: number
  readonly storage: string
  readonly createdBy: string
}

export async function insertKey(sql: Db | Tx, input: InsertKey): Promise<CustodyKeyRow> {
  const rows = await sql<CustodyKeyRow[]>`
    insert into custody_keys
      (address, chain, family, purpose, network, user_id, order_id, scheme,
       derivation_path, seed_id, key_version, storage, created_by)
    values
      (${input.address}, ${input.chain}, ${input.family}, ${input.purpose}, ${input.network},
       ${input.userId}, ${input.orderId}, ${input.scheme}, ${input.derivationPath},
       ${input.seedId}, ${input.keyVersion}, ${input.storage}, ${input.createdBy})
    returning *
  `
  const row = rows[0]
  if (!row) throw new Error('insert returned no row')
  return row
}

export async function getKey(sql: Db | Tx, address: string): Promise<CustodyKeyRow | null> {
  const rows = await sql<CustodyKeyRow[]>`select * from custody_keys where address = ${address}`
  return rows[0] ?? null
}

export async function listKeys(sql: Db, limit: number): Promise<CustodyKeyRow[]> {
  return sql<CustodyKeyRow[]>`select * from custody_keys order by created_at desc limit ${limit}`
}

export async function listKeysForUser(sql: Db, userId: string, limit: number): Promise<CustodyKeyRow[]> {
  return sql<CustodyKeyRow[]>`
    select * from custody_keys where user_id = ${userId} order by created_at desc limit ${limit}
  `
}

/** Rows still on an older envelope version. The re-encryption pass's work queue. */
export async function listStaleKeys(sql: Db, belowVersion: number, limit: number): Promise<CustodyKeyRow[]> {
  return sql<CustodyKeyRow[]>`
    select * from custody_keys
     where key_version < ${belowVersion} and status <> 'retired'
     order by created_at
     limit ${limit}
  `
}

export async function setKeyVersion(sql: Db | Tx, address: string, version: number): Promise<void> {
  await sql`update custody_keys set key_version = ${version} where address = ${address}`
}

/**
 * `active → exported`, and only that direction.
 *
 * The `where status = 'active'` is the irreversibility (SD-07 gate 9): a second redemption updates
 * no row, so it cannot un-export or re-export. An exported key is one two parties hold, and the
 * platform continuing to sweep deposits from it into its own treasury would be indefensible — which
 * is why `purposeGate` refuses to sign for it at all.
 */
export async function markExported(sql: Db | Tx, address: string): Promise<boolean> {
  const rows = await sql<{ address: string }[]>`
    update custody_keys set status = 'exported', exported_at = now()
     where address = ${address} and status = 'active'
     returning address
  `
  return rows.length === 1
}

/* ------------------------------------------------------------------ seeds */

export interface SeedRow {
  readonly id: string
  readonly user_id: string
  readonly family: string
  readonly key_version: number
  readonly next_index: number
  readonly created_at: Date
}

/**
 * Take the next address index for a (user, family) seed, creating the seed if it is the first.
 *
 * `insert … on conflict do nothing` then `update … returning` under one transaction, so two
 * concurrent provisions of a user's first address cannot both believe they created the seed and
 * write two blobs to one slot. The UPDATE takes a row lock, which is what serialises the index —
 * without it two callers read `next_index = 3`, derive the same address, and the second INSERT into
 * `custody_keys` fails on the primary key having already written a blob over the first one's.
 *
 * Returns null when the seed does not exist yet, so the caller knows it must generate a mnemonic —
 * that generation cannot happen in here, because the mnemonic must be encrypted and written to disk
 * before the row that claims it exists is committed.
 */
export async function findSeed(sql: Db | Tx, userId: string, family: string): Promise<SeedRow | null> {
  const rows = await sql<SeedRow[]>`
    select * from custody_seeds where user_id = ${userId} and family = ${family}
  `
  return rows[0] ?? null
}

export async function insertSeed(
  sql: Db | Tx,
  input: { userId: string; family: string; keyVersion: number },
): Promise<SeedRow | null> {
  const rows = await sql<SeedRow[]>`
    insert into custody_seeds (user_id, family, key_version)
    values (${input.userId}, ${input.family}, ${input.keyVersion})
    on conflict (user_id, family) do nothing
    returning *
  `
  return rows[0] ?? null
}

/** Claim the next index under a row lock. See `findSeed` for why the lock is the whole point. */
export async function takeNextIndex(sql: Tx, seedId: string): Promise<number> {
  const rows = await sql<{ next_index: number }[]>`
    update custody_seeds set next_index = next_index + 1
     where id = ${seedId}
     returning next_index - 1 as next_index
  `
  const row = rows[0]
  if (!row) throw new Error(`no custody seed ${seedId}`)
  return row.next_index
}

/* ------------------------------------------------------------------ treasury pin */

export interface TreasuryRow {
  readonly chain: string
  readonly network: string
  readonly address: string
  readonly set_by: string
  readonly set_at: Date
}

export interface TreasuryPinRecord {
  readonly chain: string
  readonly network: string
  readonly address: string
  readonly setBy: string
  readonly setAt: string
}

function toPinRecord(row: TreasuryRow): TreasuryPinRecord {
  return {
    chain: row.chain,
    network: row.network,
    address: row.address,
    setBy: row.set_by,
    setAt: row.set_at.toISOString(),
  }
}

/**
 * The pinned treasury for one (chain, network), or null when none is.
 *
 * Null is NOT "sign to anywhere": /sign turns it into a named 403 and never reaches a key. An
 * unconfigured chain sweeps nothing.
 */
export async function getTreasuryPin(sql: Db | Tx, chain: string, network: string): Promise<string | null> {
  const rows = await sql<TreasuryRow[]>`
    select * from custody_treasuries where chain = ${chain} and network = ${network}
  `
  return rows[0]?.address ?? null
}

export async function listTreasuryPins(sql: Db): Promise<TreasuryPinRecord[]> {
  const rows = await sql<TreasuryRow[]>`select * from custody_treasuries order by chain, network`
  return rows.map(toPinRecord)
}

export type PinRefusal = 'address_unknown' | 'address_not_treasury' | 'address_wrong_chain' | 'address_wrong_network' | 'address_not_active'

export interface PinResult {
  readonly previous: TreasuryPinRecord | null
  readonly current: TreasuryPinRecord
}

/**
 * Set or ROTATE the pin. **The only writer**, and the validation lives here rather than in the route
 * so there is exactly one code path that can write this table and it cannot be reached without the
 * check.
 */
export async function pinTreasury(
  sql: Db,
  input: { chain: string; network: string; address: string; setBy: string },
): Promise<PinResult | { refusal: PinRefusal }> {
  const row = await getKey(sql, input.address)
  if (!row) return { refusal: 'address_unknown' }
  if (row.purpose !== 'treasury') return { refusal: 'address_not_treasury' }
  if (row.chain !== input.chain) return { refusal: 'address_wrong_chain' }
  if (row.network !== input.network) return { refusal: 'address_wrong_network' }
  // An exported treasury is a treasury whose key somebody outside this service holds. Pinning one
  // would point every future sweep at an address the platform no longer solely controls.
  if (row.status !== 'active') return { refusal: 'address_not_active' }

  const existingRows = await sql<TreasuryRow[]>`
    select * from custody_treasuries where chain = ${input.chain} and network = ${input.network}
  `
  const existing = existingRows[0]

  const written = await sql<TreasuryRow[]>`
    insert into custody_treasuries (chain, network, address, set_by)
    values (${input.chain}, ${input.network}, ${input.address}, ${input.setBy})
    on conflict (chain, network) do update
      set address = ${input.address}, set_by = ${input.setBy}, set_at = now()
    returning *
  `
  // now(), NOT new Date(): `set_at` is compared against `custody_keys.created_at`, which the
  // DATABASE writes. Comparing two machines' clocks means a rotation stamped from a Node process
  // running behind the database looks older than the treasury it just superseded — and the next
  // rotation then pins the money straight back where it started.
  return { previous: existing ? toPinRecord(existing) : null, current: toPinRecord(written[0]!) }
}

/**
 * Which of a (chain, network)'s `treasury` addresses is the OUTSTANDING ROTATION CANDIDATE — the one
 * a repeat mint must hand back instead of making another. Null when there is none.
 *
 * WHY THE PIN'S TIMESTAMP IS THE DISCRIMINATOR, and not "any treasury address that is not pinned".
 * A rotation deliberately leaves the SUPERSEDED treasury's row untouched — still `purpose:
 * 'treasury'`, still spendable, because that is how its balance stays reachable. So after one
 * rotation the unpinned treasury addresses include the old one, which is precisely the address the
 * operator is trying to abandon: hand THAT back as the next rotation's candidate and the second
 * rotation pins the money back where it started.
 *
 * Pure, and separate from the query, so the rule can be exercised without a database — which
 * matters because every case that distinguishes it involves a pin and a rotation that has already
 * happened.
 */
export function pickOutstandingCandidate<T extends { address: string; created_at: Date }>(
  treasuries: readonly T[],
  pin: { address: string; setAt: Date } | null,
): T | null {
  const candidates = treasuries.filter(
    (row) => row.address !== pin?.address && (pin === null || row.created_at > pin.setAt),
  )
  // Newest first. Two can only exist if a mint raced itself, and the caller of a race wants the
  // address its own request would have produced.
  return [...candidates].sort((a, b) => b.created_at.getTime() - a.created_at.getTime())[0] ?? null
}

export async function outstandingTreasuryCandidate(
  sql: Db,
  chain: string,
  network: string,
): Promise<CustodyKeyRow | null> {
  const pinRows = await sql<TreasuryRow[]>`
    select * from custody_treasuries where chain = ${chain} and network = ${network}
  `
  const pin = pinRows[0]
  const rows = await sql<CustodyKeyRow[]>`
    select * from custody_keys
     where chain = ${chain} and network = ${network} and purpose = 'treasury' and status = 'active'
  `
  return pickOutstandingCandidate(rows, pin ? { address: pin.address, setAt: pin.set_at } : null)
}

/* ------------------------------------------------------------------ signing audit */

export interface SigningAuditInput {
  readonly address: string
  readonly chain: string
  readonly network: string
  readonly family: string
  readonly purpose: string
  readonly shape: string
  readonly outcome: 'signed' | 'refused'
  readonly gate: string | null
  readonly refusalReason: string | null
  readonly userId: string
  readonly orderId: string
  readonly actor: string
  readonly correlationId: string | null
  readonly payloadDigest: string
  readonly signatureDigest: string | null
}

export async function insertSigningAudit(sql: Db | Tx, input: SigningAuditInput): Promise<string> {
  const rows = await sql<{ id: string }[]>`
    insert into signing_audit
      (address, chain, network, family, purpose, shape, outcome, gate, refusal_reason,
       user_id, order_id, actor, correlation_id, payload_digest, signature_digest)
    values
      (${input.address}, ${input.chain}, ${input.network}, ${input.family}, ${input.purpose},
       ${input.shape}, ${input.outcome}, ${input.gate}, ${input.refusalReason},
       ${input.userId}, ${input.orderId}, ${input.actor}, ${input.correlationId},
       ${input.payloadDigest}, ${input.signatureDigest})
    returning id
  `
  return rows[0]!.id
}

export interface SigningAuditRow extends SigningAuditInput {
  readonly id: string
  readonly created_at: Date
}

export async function listSigningAudit(sql: Db, address: string, limit: number): Promise<Record<string, unknown>[]> {
  return sql<Record<string, unknown>[]>`
    select * from signing_audit where address = ${address} order by created_at desc limit ${limit}
  `
}

/* ------------------------------------------------------------------ rate limiting */

/**
 * Attempts by one actor inside a window, counted from the AUDIT TABLE rather than from a counter of
 * its own.
 *
 * This is the whole rate limiter's storage, and using the audit table for it is deliberate. A second
 * mechanism is a second thing to keep correct, and it would drift: a counter that is incremented on
 * a path the audit row is not written on limits nothing. Counting the durable record means the limit
 * survives a restart, is queryable by an operator during an incident, and — because REFUSALS are
 * audited too — bites hardest on exactly the caller who is probing gates in a loop.
 */
export async function signAttemptsSince(sql: Db, actor: string, since: Date): Promise<number> {
  const rows = await sql<{ n: number }[]>`
    select count(*)::int as n from signing_audit where actor = ${actor} and created_at >= ${since}
  `
  return rows[0]?.n ?? 0
}

export async function addressesCreatedSince(sql: Db, actor: string, since: Date): Promise<number> {
  const rows = await sql<{ n: number }[]>`
    select count(*)::int as n from custody_keys where created_by = ${actor} and created_at >= ${since}
  `
  return rows[0]?.n ?? 0
}
