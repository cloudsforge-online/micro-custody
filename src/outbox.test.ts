/**
 * What this relay puts on the wire.
 *
 * No database — `buildEnvelope` is a pure function of a stored row, exported for exactly that
 * reason. The version defect below survived because every test of this outbox looked at the
 * INSERT and at the signature, both of which were right, and none looked inside the bytes.
 */

import assert from 'node:assert/strict'
import test from 'node:test'
import { classifyEnvelope, type EventVersion } from '@cloudsforge/contracts-events'
import { buildEnvelope, type OutboxRow } from './outbox.ts'

/* ------------------------------------------------------------------ what goes on the wire */

/**
 * A real stored row, read from the mainnet estate on 2026-08-11 — micro-org#366.
 *
 * `custody.address.created` is the topic this service has written most (263 of its 273 rows). It
 * carries an actor and a correlation id, so `version` really was its only defect, and it is used
 * here rather than an invented row because an invented one would have been free to be convenient.
 */
const STORED_ROW: OutboxRow = {
  id: 'de486f51-ef3e-4109-ab6b-23f16d146809',
  topic: 'custody.address.created',
  key: '0x6D4054a9F317d5FE230aAE236af0c19fC2B9c1E4',
  occurred_at: new Date('2026-08-04T15:12:21.210Z'),
  producer: 'custody',
  version: 1,
  actor: 'service:wallet',
  correlation_id: 'vav3j6j753fqhckz',
  payload: { chain: 'ember', userId: 'faucet-estate', network: 'testnet', purpose: 'treasury' },
}

/**
 * **THE SIGNATURE WAS RIGHT AND THE ENVELOPE WAS NOT.**
 *
 * `@cloudsforge/contracts-events` types the wire version as "major.minor" — a STRING — and this
 * relay stamped the stored INTEGER. A delivery that verified was still discarded at the envelope
 * before any consumer read a payload. Eight relays did this at once and every suite in the estate
 * stayed green, because each one declared its OWN `EventEnvelope` and no compiler ever compared
 * the two.
 *
 * Measured with the contract's own `classifyEnvelope` against `STORED_ROW` on 2026-08-11:
 *
 *      as shipped -> malformed: version: missing
 *     fixed      -> well-formed; only the registration is outstanding
 *
 * The verdict is taken from the CONTRACT'S OWN classifier, never from a shape restated here. A
 * local copy of the rule agrees with a wrong implementation instead of catching it, which is the
 * mistake that produced the defect in the first place.
 *
 * MUTATIONS THIS KILLS — each one applied to `buildEnvelope` and each one confirmed red:
 *   - `version: row.version`, the stored integer, which is what shipped: `classifyEnvelope`
 *     answers `version: missing` and the defect assertion fails.
 *   - `version: String(row.version)` — a string, but "1" rather than "1.0": the shape assertion
 *     fails, so widening the fix to "any string" does not survive either.
 *   - `actor: row.actor` / `correlationId: row.correlation_id`, the nullable columns passed
 *     straight through, which is the other half of what the estate measured above.
 */
test('the envelope this relay puts on the wire is one the contract accepts', () => {
  const envelope = buildEnvelope(STORED_ROW)

  assert.equal(typeof envelope.version, 'string', 'an integer version is refused as "version: missing"')
  assert.match(envelope.version, /^\d+\.\d+$/, 'the contract types the wire version as "major.minor"')
  assert.equal(envelope.version, '1.0', 'major 1 as stored, minor 0 — storage records the major')
  assert.equal(envelope.actor, 'service:wallet')
  assert.equal(envelope.correlationId, 'vav3j6j753fqhckz')

  // ── AND FROM A ROW WITH THE NULLABLE COLUMNS EMPTY. Every custody row measured on 2026-08-11 carried both, so the real rows do not exercise
  // this. `withOutbox` writes null whenever a caller omits an actor, and it is what the scheduled
  // paths in `nda` and `foresight` actually do — 11 of nda's 13 rows are exactly this shape.
  const fromNulls = buildEnvelope({ ...STORED_ROW, actor: null, correlation_id: null })
  assert.equal(fromNulls.actor, 'system', 'the contract has no null actor; `system` is its word for one')
  assert.equal(fromNulls.correlationId, STORED_ROW.id, 'never absent — an absent one ends an investigation')
  assert.deepEqual(
    classifyEnvelope(fromNulls).defects,
    [],
    'a null column must not become a defect on the wire',
  )

  // The topic is not in the contract's registry yet, so the honest verdict is `unregistered_topic`
  // and NOT `valid` — a different fact with a different remedy. What matters here is `defects`:
  // once the registration lands, an EMPTY defect list is the difference between this event being
  // read and being discarded, and `version: missing` is what used to be in it.
  const verdict = classifyEnvelope(envelope)
  assert.equal(verdict.reason, 'unregistered_topic', `got: ${JSON.stringify(verdict)}`)
  assert.deepEqual(verdict.defects, [], 'well-formed: the ONLY thing outstanding is the registration')
})

/**
 * The teeth of the test above. Without this, every assertion there would still pass against a
 * classifier that accepted anything at all, and "the contract accepts it" would be a claim about
 * this file rather than about the estate.
 */
test('the shape this relay used to send is REFUSED by the same classifier', () => {
  const asShipped = { ...buildEnvelope(STORED_ROW), version: STORED_ROW.version as unknown as EventVersion }

  const verdict = classifyEnvelope(asShipped)
  assert.equal(verdict.ok, false, 'an integer version must be refused at the envelope')
  assert.equal(verdict.reason, 'malformed', 'refused as malformed, not merely shelved as unregistered')
  assert.ok(
    verdict.defects.some((d) => d.startsWith('version')),
    `refused FOR THE VERSION, not incidentally: ${JSON.stringify(verdict)}`,
  )
})

/**
 * `custody.key.exported` IS in the registry, and is one of the two topics `admin-api` subscribes
 * to. It has never been written — the ceremony has never run on this estate — so nothing has been
 * lost at a subscriber. It is asserted here because the day it runs is the day the envelope has
 * to be right, and that is not a day to find out.
 */
test('a REGISTERED topic of this service passes the contract outright', () => {
  const envelope = buildEnvelope({ ...STORED_ROW, topic: 'custody.key.exported' })

  const verdict = classifyEnvelope(envelope)
  assert.equal(verdict.ok, true, `the contract must accept it, got: ${JSON.stringify(verdict)}`)
})
