/**
 * What custody puts on the bus, and the agreement with the shared registry.
 *
 * ## The defect this file exists to close
 *
 * `@cloudsforge/contracts-events` registers **`custody.key.exported`** with producer `custody`,
 * `keyedBy: 'user_id'`, and the description "FIRST. A private key left the platform. The wallet is
 * self-custodied from here." Three consumers classify that name — `notify/src/catalogue.ts:334` at
 * `priority: 'critical'`, `activity/src/classify.ts:641`, `analytics/src/catalogue.ts:320` — the
 * audit mirror marks it `audited: true` (`contracts/packages/events/src/audit.ts:117`), and two
 * ecosystem documents name it as the event journey J5 ends on (`05-user-journeys.md:309`,
 * `07-dependency-map.md:173`).
 *
 * **This service emitted `custody.export.completed` instead.** One name, in one repository, in no
 * registry, with no subscriber anywhere in the estate. So the redemption that transitions a wallet
 * to `exported` — the single most security-significant thing this service does — reached nobody:
 * the critical notification a user "may not opt out of" could not fire, the activity feed had no
 * entry, and the analytics metric counted nothing. Gate 5 of the ceremony (`exports.ts`) says the
 * notification belongs to the notifier and custody's job is to make the fact undeniable; the fact
 * was undeniable and addressed to a topic no notifier reads.
 *
 * ## Why the rename went this way round
 *
 * The alternative was registering `custody.export.completed` and renaming it in the three
 * consumers, the audit mirror and the two documents — five repositories this service does not own,
 * to move a name that exists in one it does. `custody.key.exported` is also the better name for
 * what the event means: `markExported` is a transition of the KEY, irreversible, and "the export
 * ceremony finished" is a description of our paperwork rather than of the user's position.
 *
 * The estate-wide check that found this is `micro-org`'s `tools/estate-topics.mjs`, direction 1:
 * "registered, and no `topic:` in custody/src ever names it". Nothing inside this repository could
 * have found it, and that is the point of the split below.
 *
 * ## What this file checks, and what it deliberately leaves to micro-org
 *
 * `topics.test.ts` reads every `topic: '...'` literal out of `src/` and reconciles it against the
 * list below **in both directions**: an emit site for a topic not listed fails, and a listed topic
 * no emit site names fails. `Emit` takes `CustodyTopic` rather than `string`, so an invented or
 * misspelled name is a compile error at the call site.
 *
 * What it does NOT do is ask `@cloudsforge/contracts-events` whether each name is registered.
 * identity, settlement, trade, market, community and devplatform all do that, and it is the right
 * check — but it costs this repository a dependency on the contracts package, and the reconciliation
 * it buys is now performed for all 56 repositories at once by `estate-topics.mjs`, which reads this
 * file's literals from a checkout that also holds the registry and every consumer. A local copy
 * would duplicate a check that already exists and would answer a strictly narrower question than
 * the one that caught the defect above. The registration status of each topic is therefore recorded
 * below as data, with the line that proves it, rather than computed.
 *
 * ## Why the emit sites still spell the string out
 *
 * They could reference a constant. They deliberately do not: `grep -rn 'custody.key.exported'`
 * across the estate is how a topic's producer and its consumers are found, and that grep is worth
 * more than the one-fewer-place-to-edit a constant would buy. The union type is what stops the
 * literal being wrong; the literal is what keeps it findable. (It is also what `estate-topics.mjs`
 * reads — it resolves identifiers, but a literal needs no resolver to be right.)
 */

/**
 * Every topic custody emits. Reconciled against the `topic:` literals in `src/`, both ways.
 *
 * Order is the ceremony's, not alphabetical: an address is created, it signs or is refused, and
 * then it may leave.
 */
export const EMITTED_TOPICS = Object.freeze([
  'custody.address.created',
  'custody.key.signed',
  'custody.key.sign_refused',
  'custody.export.requested',
  'custody.key.exported',
  'custody.export.cancelled',
] as const)

/** The only strings `emit` will accept. Anything else is a compile error at the call site. */
export type CustodyTopic = (typeof EMITTED_TOPICS)[number]

/**
 * What the shared registry says about a topic this service emits.
 *
 * `registered` is a statement about `contracts/packages/events/src/index.ts` at the line named in
 * `evidence`, checked by a human and by `estate-topics.mjs`, not by an import. `keyedBy` is the
 * ordering partition and is part of the contract rather than this producer's private choice — a
 * producer that switched from `user_id` to `address` would silently change what "in order" means
 * for every consumer, and `activity/src/classify.ts` reads the envelope key AS the user id for both
 * custody topics it classifies.
 */
export interface TopicRecord {
  readonly registered: boolean
  /** What the envelope `key` carries. Must match the registry's `keyedBy` when registered. */
  readonly keyedBy: string
  /** Where the claim was verified — a path and a line — or the proposal that would register it. */
  readonly evidence: string
}

export const TOPIC_RECORDS: Readonly<Record<CustodyTopic, TopicRecord>> = Object.freeze({
  'custody.address.created': Object.freeze({
    registered: false,
    keyedBy: 'address',
    evidence:
      'No registry names it. Proposed as producer custody, payloadType AddressCreated, version 1.0, keyedBy address: wallet already reads this over HTTP and an event would retire the poll, but nothing consumes it today so registration is not urgent.',
  }),
  'custody.key.signed': Object.freeze({
    registered: false,
    keyedBy: 'address',
    evidence:
      'No registry names it. Proposed as producer custody, payloadType KeySigned, version 1.0, keyedBy address: the signing audit trail is the estate\'s record of every movement authorised by a platform-held key, and it reaches no consumer at all today.',
  }),
  'custody.key.sign_refused': Object.freeze({
    registered: false,
    keyedBy: 'address',
    evidence:
      'No registry names it. Proposed as producer custody, payloadType KeySignRefused, version 1.0, keyedBy address: a refusal is the half of the audit trail that says a gate held, and an operator surface that only sees successes cannot tell a quiet service from a broken one.',
  }),
  'custody.export.requested': Object.freeze({
    registered: true,
    keyedBy: 'user_id',
    evidence:
      "contracts/packages/events/src/index.ts:372 — producer 'custody', keyedBy 'user_id'. The key was the ADDRESS here until the same change that renamed the completion event; activity/src/classify.ts:634 reads the key as the user id for this topic, so every export request was filed against a user id that was really an address.",
  }),
  'custody.key.exported': Object.freeze({
    registered: true,
    keyedBy: 'user_id',
    evidence:
      "contracts/packages/events/src/index.ts:379 — producer 'custody', keyedBy 'user_id'. This service emitted 'custody.export.completed' instead, which no registry names and nothing subscribes to; see the header of this file.",
  }),
  'custody.export.cancelled': Object.freeze({
    registered: false,
    keyedBy: 'user_id',
    evidence:
      'No registry names it. Proposed as producer custody, payloadType KeyExportCancelled, version 1.0, keyedBy user_id: the closing half of custody.export.requested, which IS registered. A user who is told a 24-hour hold started and never told it ended has been left watching for something that will not arrive.',
  }),
})

/** Topics this service emits that no registry names. A census, not a defect — see the header. */
export function unregisteredEmittedTopics(): readonly CustodyTopic[] {
  return EMITTED_TOPICS.filter((topic) => !TOPIC_RECORDS[topic].registered)
}
