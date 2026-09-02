/**
 * Right to erasure — `identity.user.deleted`, handled.
 *
 * Rule 6 of docs/ecosystem/03 §2: every service storing a `user_id` subscribes to this event and
 * erases. This one stores it in four tables and had no subscription at all, because micro-org#534
 * held the four money-holding services open on a question the register could not answer for itself:
 * what does the estate do with a key, a deposit address and a signing record belonging to a person
 * who has asked to be forgotten?
 *
 * The owner answered it on 2026-09-02: **everything is anonymised.** That is the rule this file
 * implements, and `deploy/erasure/register.psv` carries the decision in full.
 *
 * ── WHY DELETION IS NOT THE ANSWER HERE, AND WHY THAT IS NOT A DODGE ──────────────────────────
 *
 * A custody row is not a copy of a fact about a person. It is one half of a key that controls
 * money on a public chain, and the other half is the chain itself, which this estate cannot edit
 * and no regulator can order edited. Delete `custody_keys` and the address stays exactly where it
 * was, still holding whatever it holds, and the estate has destroyed the only record of how to
 * reach it. That is not erasure of personal data; it is the destruction of the person's own
 * property, performed in their name.
 *
 * So the identifier goes and the key material stays. After this runs, nothing in the schema says
 * WHOSE any of it is — which is what was asked — and every derivation path, signing record and
 * export still reconciles, which is what Art. 17(3)(b) preserves.
 *
 * ── THE STATUS COLUMN IS DELIBERATELY NOT TOUCHED, AND THAT IS THE SUBTLE PART ─────────────────
 *
 * The tempting extra step is to retire the person's addresses: they have gone, so stop using the
 * keys. It is the wrong step, twice over.
 *
 * `gates.ts` refuses to sign for any key whose `status <> 'active'` (gate 3, SD-07). Retiring a
 * deposit address therefore does not stop deposits — the chain has never heard of this database —
 * it stops the estate SPENDING what arrives. Coins sent to that address after the erasure, by a
 * counterparty who has no way to know, would be observable, attributable to nobody, and
 * permanently unmovable. Anonymising strands the identity; retiring would strand the money.
 *
 * Nor is `exported` reachable: `store.markExported`'s `where status = 'active'` is the
 * irreversibility that stops a second redemption, and forcing that transition here would consume
 * it without an export having happened.
 *
 * What IS true is that this estate has no settlement-before-erasure flow: nothing sweeps a
 * departing person's balances back out before the identifier is destroyed. That is a product gap,
 * recorded as one, and not something a handler can paper over — a handler that refused the erasure
 * until the balance was zero would simply be an erasure that never completes, which is the failure
 * this whole subscription exists to end.
 *
 * ── THE DECISIONS ───────────────────────────────────────────────────────────────────────────────
 *
 * | table                 | action    | reasoning |
 * | --------------------- | --------- | --------- |
 * | `custody_seeds`       | ANONYMISE | The BIP-32 master seed a person's addresses derive from. Deleting it destroys the ability to re-derive every key beneath it — see above. `custody_seeds_user_family_uniq (user_id, family)` still holds: one placeholder across the person's families keeps each row distinct. |
 * | `custody_keys`        | ANONYMISE | The addresses themselves, and `address` is the primary key. Four columns, not one: `created_by` carries `user:<uuid>` when the person minted their own address, `order_id` is what the wallet keys a deposit binding on, and `idempotency_key` is caller-supplied text that has no defined shape at all. `custody_keys_binding_uniq (chain, network, purpose, user_id, order_id)` and `custody_keys_idempotency_uniq (created_by, idempotency_key)` both keep working: the placeholder is unique, so each row still occupies exactly one slot and no second mint can take it. |
 * | `signing_audit`       | ANONYMISE | Every signature and every refusal, which is the record SD-07 exists to produce. `user_id`, `order_id` and `actor` all name the person; `payload_digest` and `signature_digest` are hashes of transactions, not of identities. Basis: Art. 17(3)(b). |
 * | `key_exports`         | ANONYMISE | The export requests, including the cooling-off and challenge timestamps that are the anti-theft control. `key_exports_one_open_idx` is partial on `address`, which the placeholder does not disturb. |
 * | `outbox`              | REDACT    | The outbound delivery journal. An unpublished row still has to be delivered, so the id is swept out of `key`, `actor` and `payload` in place rather than the row being dropped. |
 * | `custody_treasuries`, `custody_seed_paths`, `custody_token_contracts`, `inbox`, `event_subscriptions`, `outbox_deliveries` | — | No user id in any of them. Asserted rather than assumed: `erasure.test.ts` sweeps every column in the schema for the raw uuid afterwards, which is the check that catches the column a reading of the migrations would miss. |
 *
 * ── ONE PLANE, NOT TWO ──────────────────────────────────────────────────────────────────────────
 *
 * Unlike `agora` and `ledger`, this service has never held one database per network: `env.ts` reads
 * a single `DATABASE_URL` and `network` is a COLUMN (`custody_keys_network_ck`). So a single
 * transaction covers mainnet and testnet here, and there is no `erasureplanes.ts` sweep to do —
 * `micro-org#516` finished the consolidation of the last rows left in the old testnet database.
 * The `where` clauses are deliberately not filtered by network for the same reason: an erasure that
 * cleared one network's rows and left the other's is the exact defect #474 was.
 *
 * ── THE PLACEHOLDER ─────────────────────────────────────────────────────────────────────────────
 *
 * ONE random uuid per erasure, from `randomUUID()`, never derived from the real id. A hash of a
 * uuid is not an anonymisation: the candidate space is whatever list of users an attacker already
 * has, and checking it is one hash each. Nothing stores the mapping.
 *
 * It is REUSED across every table, which keeps the retained rows linked to one another — a key, its
 * signing history and its export request stay recognisably one story. That is unavoidable once
 * anything is retained: a derivation path and a timestamp link them regardless of what the id
 * column says, and separating them would produce an audit trail that no longer reconciles while
 * anonymising nothing further.
 */

import { randomUUID } from 'node:crypto'
import type { Tx } from './outbox.ts'

export const USER_DELETED_TOPIC = 'identity.user.deleted'

export interface ErasureOutcome {
  readonly seeds: number
  readonly keys: number
  readonly signings: number
  readonly exports: number
  readonly outbox: number
}

/**
 * Anonymise one user, in one transaction.
 *
 * Counts are returned rather than logged here, and the caller logs the counts and never the id —
 * writing the erased id into a log would recreate, in the one store nothing erases, exactly what
 * the request was to remove.
 */
export async function eraseUser(tx: Tx, userId: string): Promise<ErasureOutcome> {
  const placeholder = randomUUID()
  // For the text and jsonb sweeps. The id is a uuid, so a substring match cannot catch a shorter
  // string by accident, and matching ANYWHERE is the point: a payload may nest it at any depth.
  const anywhere = `%${userId}%`

  // Seeds first: `custody_keys.seed_id` references them, and doing the parent before the children
  // keeps the two consistent at every point inside the transaction rather than only at commit.
  const seeds = await tx`
    update custody_seeds set user_id = ${placeholder} where user_id = ${userId} returning 1
  `

  // `created_by` is swept with a `replace` rather than an assignment because it is not always the
  // person: an address minted by a service carries that service's name, and overwriting it would
  // erase WHO ACTED as well as who it was for.
  const keys = await tx`
    update custody_keys
       set user_id         = ${placeholder},
           order_id        = replace(order_id, ${userId}, ${placeholder}),
           created_by      = replace(created_by, ${userId}, ${placeholder}),
           idempotency_key = case
             when idempotency_key is null then null
             else replace(idempotency_key, ${userId}, ${placeholder})
           end
     where user_id = ${userId}
        or order_id like ${anywhere}
        or created_by like ${anywhere}
        or idempotency_key like ${anywhere}
    returning 1
  `

  // `order_id` and `actor` too. The same sweep is done on `custody_keys` above, and for the same
  // reason: an id can be named in a column whose NAME does not suggest a person.
  const signings = await tx`
    update signing_audit
       set user_id  = ${placeholder},
           order_id = replace(order_id, ${userId}, ${placeholder}),
           actor    = replace(actor, ${userId}, ${placeholder})
     where user_id = ${userId} or order_id like ${anywhere} or actor like ${anywhere}
    returning 1
  `

  const exports = await tx`
    update key_exports
       set user_id    = ${placeholder},
           created_by = replace(created_by, ${userId}, ${placeholder})
     where user_id = ${userId} or created_by like ${anywhere}
    returning 1
  `

  // Rows are NOT dropped: an unpublished row still has to be delivered, and dropping it would lose
  // the event rather than anonymise it.
  const outbox = await tx`
    update outbox
       set key     = replace(key, ${userId}, ${placeholder}),
           actor   = case when actor is null then null else replace(actor, ${userId}, ${placeholder}) end,
           payload = replace(payload::text, ${userId}, ${placeholder})::jsonb
     where key like ${anywhere} or actor like ${anywhere} or payload::text like ${anywhere}
    returning 1
  `
  return {
    seeds: seeds.length,
    keys: keys.length,
    signings: signings.length,
    exports: exports.length,
    outbox: outbox.length,
  }
}
