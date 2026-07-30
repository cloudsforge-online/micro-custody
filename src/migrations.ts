/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 §2: versioned files, run by a one-shot job under an advisory lock,
 * expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the only
 * caller, and the service asserts the version rather than reaching it.
 *
 * **A released migration is immutable.** `@cloudsforge/db` checksums each one and refuses a run
 * where the text changed after it was applied. The fix for a wrong migration is a new migration.
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'

export const MIGRATIONS: readonly Migration[] = [
  { version: 1, name: 'jobs', up: JOBS_SCHEMA_SQL },
  {
    version: 2,
    name: 'outbox',
    up: `
      create table if not exists outbox (
        id             uuid        primary key default gen_random_uuid(),
        topic          text        not null,
        key            text        not null,
        occurred_at    timestamptz not null default now(),
        producer       text        not null,
        version        integer     not null default 1,
        actor          text,
        correlation_id text,
        payload        jsonb       not null default '{}'::jsonb,
        published_at   timestamptz
      );

      create index if not exists outbox_unpublished_idx
        on outbox (occurred_at)
        where published_at is null;

      create table if not exists event_subscriptions (
        id         uuid        primary key default gen_random_uuid(),
        topic      text        not null,
        url        text        not null,
        active     boolean     not null default true,
        created_at timestamptz not null default now(),
        constraint event_subscriptions_topic_url_uniq unique (topic, url)
      );

      create table if not exists outbox_deliveries (
        event_id        uuid        not null references outbox (id) on delete cascade,
        subscription_id uuid        not null references event_subscriptions (id) on delete cascade,
        delivered_at    timestamptz,
        attempts        integer     not null default 0,
        last_error      text,
        primary key (event_id, subscription_id)
      );
    `,
  },
  {
    version: 3,
    name: 'inbox',
    up: `
      create table if not exists inbox (
        topic       text        not null,
        event_id    uuid        not null,
        received_at timestamptz not null default now(),
        primary key (topic, event_id)
      );
    `,
  },
  {
    version: 4,
    name: 'custody',
    /*
     * The domain. Five tables, and each one exists because something in SD-06 to SD-09 or
     * 04-domain-model §3.3 could not be true without it.
     *
     * NOTE WHAT IS NOT HERE: a column, anywhere, holding a private key. The blobs live on disk
     * under `CUSTODY_DATA_DIR`, one directory per address, `0600`. `key_version` records which
     * envelope version the blob on disk carries, so the re-encryption pass can find the stragglers
     * with an indexed query rather than by opening every file.
     */
    up: `
      -- One BIP-39 seed per (user, family). 04-domain-model §3.3. The seed's own secret is a blob
      -- on disk like every other, addressed by 'seed:<id>' rather than by a chain address.
      create table if not exists custody_seeds (
        id          uuid        primary key default gen_random_uuid(),
        user_id     text        not null,
        family      text        not null,
        key_version integer     not null,
        -- Allocated monotonically and NEVER reused, across both networks and every chain that
        -- shares this family's coin type. Reuse would mint a second row at an address that
        -- already exists, and the primary key below would be the only thing that noticed.
        next_index  integer     not null default 0,
        created_at  timestamptz not null default now(),
        constraint custody_seeds_user_family_uniq unique (user_id, family)
      );

      create table if not exists custody_keys (
        address         text        primary key,
        chain           text        not null,
        family          text        not null,
        -- deposit | treasury | deployer | user. Selects the signing policy — see signing.ts.
        purpose         text        not null,
        network         text        not null,
        user_id         text        not null,
        order_id        text        not null,
        -- flat_random (legacy, not migratable — SDR-08) | hd_bip44. Stated in every response.
        scheme          text        not null,
        derivation_path text,
        seed_id         uuid        references custody_seeds (id),
        key_version     integer     not null,
        storage         text        not null,
        -- active | exported | retired. 'exported' is one-way and excludes the row from sweeping.
        status          text        not null default 'active',
        created_by      text        not null,
        created_at      timestamptz not null default now(),
        exported_at     timestamptz,
        constraint custody_keys_purpose_ck  check (purpose in ('deposit','treasury','deployer','user')),
        constraint custody_keys_network_ck  check (network in ('mainnet','testnet')),
        constraint custody_keys_status_ck   check (status  in ('active','exported','retired')),
        -- The two schemes are structurally different rows, and the database says so. A 'hd_bip44'
        -- row with no path is a row nothing can re-derive; a 'flat_random' row WITH one is a claim
        -- that a legacy key can be recovered from a phrase, which is exactly the lie SDR-08 says
        -- must be surfaced honestly rather than papered over.
        constraint custody_keys_scheme_ck check (
          (scheme = 'flat_random' and derivation_path is null and seed_id is null)
          or (scheme = 'hd_bip44' and derivation_path is not null and seed_id is not null)
        )
      );

      create index if not exists custody_keys_user_idx    on custody_keys (user_id, created_at desc);
      create index if not exists custody_keys_creator_idx on custody_keys (created_by, created_at desc);
      -- The re-encryption pass's access path. Partial on the stragglers, so the index is the size
      -- of the backlog rather than the size of custody.
      create index if not exists custody_keys_version_idx on custody_keys (key_version)
        where status <> 'retired';

      -- The treasury pin. One address per (chain, network), and the ONLY thing a sweep may pay.
      create table if not exists custody_treasuries (
        chain   text        not null,
        network text        not null,
        address text        not null references custody_keys (address),
        set_by  text        not null,
        set_at  timestamptz not null default now(),
        primary key (chain, network)
      );

      -- SD-09 and SD-15. A *successful* sign recorded nothing at all in the service this replaces;
      -- only refusals were logged, and a log line is sampled, redacted and expires.
      --
      -- NEITHER THE PAYLOAD NOR THE SIGNATURE IS STORED, only their digests. A signed transaction
      -- in a table is a submittable transaction: anyone with read access to this database could
      -- broadcast a sweep the platform decided not to send. The digest answers "which transaction
      -- was signed, for whom, by which caller" — which is what a dispute needs — without making
      -- the audit trail itself a money-movement primitive.
      create table if not exists signing_audit (
        id                uuid        primary key default gen_random_uuid(),
        address           text        not null,
        chain             text        not null,
        network           text        not null,
        family            text        not null,
        purpose           text        not null,
        shape             text        not null,
        outcome           text        not null,
        gate              text,
        refusal_reason    text,
        user_id           text        not null,
        order_id          text        not null,
        actor             text        not null,
        correlation_id    text,
        payload_digest    text        not null,
        signature_digest  text,
        created_at        timestamptz not null default now(),
        constraint signing_audit_outcome_ck check (outcome in ('signed','refused'))
      );

      create index if not exists signing_audit_actor_idx   on signing_audit (actor, created_at desc);
      create index if not exists signing_audit_address_idx on signing_audit (address, created_at desc);

      -- SD-07. Export is not a read; it is a state transition, and these are its timers.
      create table if not exists key_exports (
        id               uuid        primary key default gen_random_uuid(),
        address          text        not null references custody_keys (address),
        user_id          text        not null,
        status           text        not null,
        format           text        not null,
        policy_decision  text,
        policy_reasons   jsonb       not null default '[]'::jsonb,
        requested_at     timestamptz not null default now(),
        -- requested_at + the cooling-off. Gate 4, and the only control in SD-07 that works while
        -- the user is actively being deceived.
        available_at     timestamptz,
        -- An abandoned request must not stay redeemable for ever.
        expires_at       timestamptz not null,
        challenged_at    timestamptz,
        -- The reveal token is stored SHA-256 only, exactly as a refresh token is. Storing it would
        -- make this table a key-reveal primitive, which is the thing SD-08 deleted a route over.
        token_hash       text,
        token_expires_at timestamptz,
        redeemed_at      timestamptz,
        cancelled_at     timestamptz,
        created_by       text        not null,
        constraint key_exports_status_ck check (
          status in ('requested','cooling_off','challenged','redeemed','cancelled','denied','expired')
        )
      );

      -- One open ceremony per address. Two concurrent requests would each mint a reveal token for
      -- the same key, so cancelling one would leave the other live — which defeats the cancel link
      -- that gates 4 and 5 depend on.
      create unique index if not exists key_exports_one_open_idx
        on key_exports (address)
        where status in ('requested','cooling_off','challenged');

      create index if not exists key_exports_user_idx on key_exports (user_id, requested_at desc);
    `,
  },
]

/**
 * The version this build requires. `index.ts` asserts it at boot and refuses to serve below it,
 * which stops a replica of the new code answering requests against the old schema.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce((max, m) => Math.max(max, m.version), 0)

/**
 * Custody is a NEW database, not an adopted one. The rows in `forge-keyvault` are adopted by an
 * offline import that writes through this schema's own constraints, not by baselining a hand-built
 * schema — the two differ in every table, and `scheme`, `key_version` and `status` have no
 * equivalent column to baseline onto.
 */
export const BASELINE_VERSION = 0
