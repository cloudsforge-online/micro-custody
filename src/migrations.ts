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
  {
    version: 5,
    name: 'treasury_pin_integrity',
    /*
     * THE PIN IS NOW THE SAFETY PROPERTY FOR EVERY FAMILY, SO IT STOPS BEING A CODE-LEVEL RULE.
     *
     * Until Bitcoin and Solana gained sweep shapes, a `deposit`-purpose address in those families
     * could not be signed for at all — `gates.SWEEPABLE_FAMILIES` refused it. What replaced that
     * refusal is the pinned destination: every output of a BTC sweep, and the sole destination of a
     * SOL sweep, must be `custody_treasuries.address` for the row's own (chain, network). Five
     * families now depend on that row being what it claims to be.
     *
     * `store.pinTreasury` validates exactly that and is the only writer — the address must exist,
     * carry `purpose = 'treasury'`, and sit on the SAME chain and the SAME network as the pin. But
     * that is a rule in a TypeScript function, and the estate's rule (03 §2) is that an invariant
     * money depends on lives in the schema, where a bug, a future migration, an offline adoption
     * script or an operator with a psql prompt cannot route around it. Migration 4's foreign key
     * checked only that the address EXISTS in `custody_keys`; it permitted pinning a customer's
     * `deposit` address, or a treasury on a different chain, and every sweep in the estate would
     * then have paid it.
     *
     * The composite key carries all three facts at once. `purpose` is denormalised onto the pin row
     * so it can participate in the reference, and a CHECK holds it at 'treasury' — the FK then says
     * "there is a custody_keys row with this address, this chain, this network AND purpose
     * 'treasury'", which is `pinTreasury`'s validation minus nothing except `status`.
     *
     * WHY `status` IS NOT IN THE KEY, said explicitly because its absence looks like an omission.
     * `status` is the one mutable column of the four, so including it would make `markExported`
     * fail against a pinned row rather than merely refuse — and it would make the FK a lock on a
     * lifecycle transition, which is not what a reference is for. It does not need to be here:
     * `exports.requestExport` refuses a `treasury` or `deployer` address outright with
     * 'platform-owned addresses are not user-exportable', so a pinned treasury cannot reach
     * 'exported' by any route, and `pinTreasury` refuses to pin one that is not active.
     *
     * THE BACKFILL, AND WHAT IT WOULD DO TO A BAD ROW. `purpose` defaults to 'treasury', so every
     * existing pin is asserted to be one and the FK is validated against it as the migration runs. A
     * pin that was never valid would therefore fail the migration with a bare 23503 rather than the
     * named refusal `pinTreasury` gives — and `index.ts` asserts the schema version at boot, so the
     * service would refuse to serve rather than sweep to it. That is the right way round, and it is
     * also unreachable: custody is a NEW database (`BASELINE_VERSION = 0`) and `pinTreasury` has
     * been the only writer of this table since migration 4 created it.
     */
    up: `
      -- Backs the reference below. address is already the primary key, so this is unique for free
      -- and exists only so the composite foreign key has something to point at.
      create unique index if not exists custody_keys_pin_target_uniq
        on custody_keys (address, chain, network, purpose);

      alter table custody_treasuries
        add column if not exists purpose text not null default 'treasury';

      alter table custody_treasuries
        drop constraint if exists custody_treasuries_purpose_ck;
      alter table custody_treasuries
        add constraint custody_treasuries_purpose_ck check (purpose = 'treasury');

      -- Migration 4's 'references custody_keys (address)', which postgres named for us. Dropped
      -- rather than kept because the reference below is strictly stronger: same address column,
      -- three more facts.
      alter table custody_treasuries
        drop constraint if exists custody_treasuries_address_fkey;

      alter table custody_treasuries
        drop constraint if exists custody_treasuries_key_fk;
      alter table custody_treasuries
        add constraint custody_treasuries_key_fk
          foreign key (address, chain, network, purpose)
          references custody_keys (address, chain, network, purpose);
    `,
  },
  {
    version: 6,
    name: 'provisioning_idempotency',
    /*
     * A RETRY MUST NOT MINT A SECOND ADDRESS, AND THE DATABASE IS WHAT SAYS SO.
     *
     * Until this migration custody had no idempotency of any kind: `provisionAddress` minted
     * unconditionally and the `idempotency-key` header both callers send was discarded at the
     * boundary. That is not a duplicate row. An address is where a user is told to send money, so a
     * second one is a second place their funds can arrive — a place nothing is watching, nothing
     * sweeps, and the ledger has no entry for. Retries are the ordinary case here: both callers
     * reach this service over HTTP, and `@cloudsforge/http` RETRIES a POST by itself precisely when
     * an idempotency key is present, so the client believed to be making the call safe was the
     * thing making the duplicate.
     *
     * TWO IDENTITIES, BECAUSE THE TWO CALLERS OFFER TWO DIFFERENT THINGS.
     *
     * 1. `(created_by, idempotency_key)` — what the CALLER says is the same request. Scoped by
     *    actor: the string is the caller's own to choose, and two services picking 'deposit-1' must
     *    not become one address. NULL is not equal to NULL in a unique index, so a caller that
     *    sends no key is simply not covered by this one.
     *
     * 2. `(chain, network, purpose, user_id, order_id)` for 'deposit' and 'deployer' — the SD-09
     *    binding, which for those two purposes is one-per-address by construction: wallet's
     *    `orderId` is its deposit assignment's primary key and mint's is the token's id, both
     *    created once per address they intend to exist. A second row under one binding therefore
     *    cannot be anything but a duplicate mint, whatever the caller meant.
     *
     * AND WHY 'treasury' IS ABSENT FROM THE SECOND, which is the constraint's most important line.
     * A treasury's binding is DERIVED from (chain, network) alone — `keys.treasuryBinding` — so
     * every rotation candidate a chain will ever have carries the same one on purpose. Rotation is
     * three deliberate steps (mint, move the balance, pin) and this index would delete the first of
     * them for ever after the first pin. That route has its own reuse rule, `pickOutstandingCandidate`,
     * which is deliberately time-and-pin-aware in a way a unique index cannot be. 'user' is absent
     * for a weaker reason and it is worth being honest about it: no caller in the estate mints one,
     * so nothing establishes that its `orderId` is per-address, and a constraint whose justification
     * is "nobody does this" is a constraint that will be wrong the day somebody does.
     *
     * ORDINARY INDEXES, NOT `CONCURRENTLY`: the migrator is a one-shot job holding an advisory lock
     * and `@cloudsforge/db` runs each migration in a transaction, which `CONCURRENTLY` cannot join.
     * custody_keys is small — it holds one row per address the platform has ever minted — and the
     * lock is measured in milliseconds.
     */
    up: `
      alter table custody_keys add column if not exists idempotency_key text;

      -- Bounded here as well as at the route, because the route is the thing that is one deploy
      -- away from forgetting. An empty string is not a key: it is a caller that sent the header and
      -- put nothing in it, and treating it as an identity would make every such request "the same".
      alter table custody_keys drop constraint if exists custody_keys_idempotency_ck;
      alter table custody_keys
        add constraint custody_keys_idempotency_ck
          check (idempotency_key is null or (length(idempotency_key) between 1 and 255));

      create unique index if not exists custody_keys_idempotency_uniq
        on custody_keys (created_by, idempotency_key)
        where idempotency_key is not null;

      create unique index if not exists custody_keys_binding_uniq
        on custody_keys (chain, network, purpose, user_id, order_id)
        where purpose in ('deposit', 'deployer');
    `,
  },
  {
    version: 7,
    name: 'token_contracts',
    /*
     * THE TOKEN ALLOWLIST — WHICH CONTRACTS A DEPOSIT KEY MAY BE MADE TO CALL.
     *
     * `token_sweep` (signing.ts) is the only shape in this service whose `tx.to` is a CONTRACT
     * rather than an address this service minted. Its recipient is pinned inside the calldata, so
     * the money cannot go anywhere but the treasury; what this table bounds is the other half —
     * WHICH CODE a customer's deposit key is allowed to execute. An unbounded version admits
     * `transfer` on an attacker-deployed contract that does something else entirely under that
     * name, which is a signing oracle wearing an ERC-20's clothes.
     *
     * IT REFUSES BY DEFAULT AND STARTS EMPTY. No token is sweepable until an administrator inserts
     * it. A chain with no row here signs native sweeps and nothing else, which is exactly the
     * behaviour before this migration — so deploying it changes no existing capability.
     *
     * THE ADDRESS IS STORED LOWER-CASE AND THE CHECK ENFORCES IT, which is the invariant that makes
     * the allowlist an allowlist. EVM addresses have three valid spellings; if two of them could
     * coexist in this table, then "is this contract registered" would depend on how the caller
     * happened to type it, and a lookup miss on a checksummed spelling fails OPEN in the worst
     * possible direction — it would refuse a legitimate sweep, an operator would "fix" it by
     * inserting the other spelling, and the table would then contain two rows an audit has to
     * reconcile by eye. One spelling, enforced by the database, and `signing.ts` lower-cases the
     * candidate before asking.
     *
     * `decimals` IS RECORDED BUT NOT USED BY THIS SERVICE, and that is on purpose. Custody signs;
     * it does not denominate. The column exists because an operator registering a token has to have
     * looked the value up, and a registry that does not record what the operator believed cannot
     * later be checked against the contract — which is the check that catches a six-decimal
     * stablecoin credited as an eighteen-decimal one, an error of 10^12.
     *
     * WHY (chain, network) IS PART OF THE KEY. The same brand of stablecoin is a different contract
     * on every chain, and one of them being registered must never make the others callable. The
     * lookup in `keys.ts` is by the ROW's own chain and network, the same source as the treasury
     * pin, so a token registered on ethereum mainnet is invisible to an address on any other.
     */
    up: `
      create table if not exists custody_token_contracts (
        chain    text        not null,
        network  text        not null,
        contract text        not null,
        symbol   text        not null,
        decimals smallint    not null,
        set_by   text        not null,
        set_at   timestamptz not null default now(),
        primary key (chain, network, contract),

        -- One spelling per contract, and it is the lower-cased one. See the note above.
        constraint custody_token_contracts_contract_ck
          check (contract = lower(contract) and contract ~ '^0x[0-9a-f]{40}$'),

        -- ERC-20 permits any uint8. The band is wide enough for every real token and narrow enough
        -- that a transposed or defaulted value is refused rather than stored.
        constraint custody_token_contracts_decimals_ck
          check (decimals between 0 and 36),

        constraint custody_token_contracts_symbol_ck
          check (length(symbol) between 1 and 32),

        -- A token sweep is an EVM shape and nothing else has one. A row on a Bitcoin chain would be
        -- unreachable by any code path, so it is a mistake rather than a future feature, and the
        -- place to catch a mistake is where it is written.
        constraint custody_token_contracts_network_ck
          check (network in ('mainnet', 'testnet'))
      );
    `,
  },
  {
    version: 8,
    name: 'pool_purpose',
    /*
     * A FIFTH PURPOSE — `pool`, THE ADDRESS A FOUND BLOCK'S COINBASE IS PAID TO.
     *
     * micro-pool builds Bitcoin-family block templates and pays the coinbase of every block it finds
     * to the address in `POOL_<CHAIN>_PAYOUT_ADDRESS` (`pool/src/env.ts`), one per chain, validated
     * against that chain's own node at boot. 36-multi-chain-and-mining-pool §5.3 states what lands
     * there: found blocks are "the pool's revenue AND THE MINERS' CLAIM ON IT". So it is not an
     * operating address holding the platform's own float — it holds coin that is owed to people, and
     * a key under coin owed to people belongs in custody rather than in a wallet on the pool host.
     *
     * That is the whole of the change: one more legal value in `custody_keys_purpose_ck`. No table,
     * no column, no index. Every line below this one is why it could not be an existing purpose and
     * why it needs nothing more than this.
     *
     * ── WHY NOT ONE OF THE FOUR ──────────────────────────────────────────────────────────────
     *
     * `deposit` is owned by the wallet's deposit machinery end to end: an address carrying it is
     * watched, credited to a user's ledger balance and swept to the settlement treasury. A coinbase
     * landing on one would be read as a user's deposit and credited to whoever the row's `user_id`
     * happened to name.
     *
     * `deployer` is contract deployment and is EVM-shaped — `evmShapeForPurpose` maps it to
     * 'creation'. It has no meaning on a chain where the money arrives as a coinbase output.
     *
     * `user` is an end user's own key, exportable by them, and the pool's payout address is owned by
     * no user.
     *
     * `treasury` IS THE DANGEROUS ONE AND IT IS WHY THIS MIGRATION IS WRITTEN THIS CAREFULLY. A
     * `treasury`-purpose row is not merely a label: `outstandingTreasuryCandidate` (`store.ts`)
     * selects `purpose = 'treasury'` on a (chain, network) and hands the newest unpinned one back as
     * THE ROTATION CANDIDATE, and `pinTreasury` will then pin it. micro-pool's chains today are BTC
     * and LTC (`pool/src/env.ts`), and settlement pins an LTC mainnet treasury — so a pool payout
     * address minted as `treasury` on `litecoin` `mainnet` would be sitting in the candidate set for
     * the next rotation of the very pin every LTC sweep pays.
     *
     * What that costs, measured rather than imagined: settlement books the pinned address's balance
     * as platform equity from the moment it starts watching it, so every block the pool had already
     * mined to that address would arrive as custody inflow no ledger entry explains. That is exactly
     * the shape of the drift that froze EMBER withdrawals for three days from 2026-08-05 —
     * micro-org#247 and #248, measured drift -25000020999999996000 — with the sign the other way
     * round and a coinbase's worth of magnitude behind it. **A purpose that can be promoted into the
     * settlement treasury must never be the pool's**, and the only way to be sure of that is for the
     * pool's addresses not to carry it.
     *
     * ── AND WIDENING THIS CHECK CANNOT LET A `pool` ROW BE PINNED ─────────────────────────────
     *
     * The reason to be sure of this rather than to assume it: migration 5 made the pin a composite
     * foreign key, and a foreign key that referenced the purpose SET rather than a purpose VALUE
     * would have been widened by this migration without anybody touching it.
     *
     * It does not, because migration 5 names one literal in two places. `custody_treasuries.purpose`
     * is held at exactly 'treasury' by `custody_treasuries_purpose_ck` — an equality, not a
     * membership test, so nothing added here changes what that column may hold. And
     * `custody_treasuries_key_fk` references `custody_keys (address, chain, network, purpose)` by
     * VALUE. Put the two together: a pin row can only ever carry purpose 'treasury', and the FK then
     * demands a `custody_keys` row with that same address, chain, network AND the literal purpose
     * 'treasury'. A `pool` row carries 'pool' in that column, so it satisfies no such reference —
     * the insert fails with a 23503 before any of custody's TypeScript is consulted.
     *
     * Three further walls stand in front of that one and none of them is what this argument rests
     * on: `pinTreasury` refuses `row.purpose !== 'treasury'` outright, it also demands the platform
     * treasury binding (micro-org#250), and `outstandingTreasuryCandidate` filters on both. They are
     * code, and the estate's rule (03 §2) is that an invariant money depends on lives in the schema.
     * Here it already does, and this migration is careful not to loosen it.
     *
     * ── THE UNIQUENESS DECISION: NOTHING, DELIBERATELY ───────────────────────────────────────
     *
     * Migration 6's `custody_keys_binding_uniq` covers `(chain, network, purpose, user_id, order_id)`
     * `where purpose in ('deposit','deployer')`. `pool` is NOT added to it, and no index of its own is
     * added either. Both candidates were considered:
     *
     * 1. ADD 'pool' TO THAT INDEX. Refused because it would not state anything true. Migration 6's
     *    justification for the two purposes in it is specific: their `order_id` is the primary key of
     *    a row the CALLER creates once per address it intends to exist — wallet's deposit assignment,
     *    mint's token — so a second row under one binding cannot be anything but a duplicate mint.
     *    Nothing plays that role for a pool payout address. Its `user_id` and `order_id` are strings
     *    an operator chooses at mint time, so the index would say "one address per caller-chosen
     *    order id", which `custody_keys_idempotency_uniq` already covers for any caller that sends a
     *    key and which any caller can step around by changing one string. A constraint that does not
     *    state the invariant is worse than no constraint, because it gets cited as though it did.
     *
     * 2. A STRONGER INDEX, `unique (chain, network) where purpose = 'pool'`. This one WOULD state the
     *    real-world fact — a pool has one payout address per chain per network. It is refused for the
     *    reason migration 6 gives for keeping `treasury` out of its index, and the reason applies
     *    harder here. A pool payout key ACCUMULATES: every block ever found adds to it, so it is
     *    precisely the key an operator must be able to abandon and replace — on a suspected
     *    compromise, on an envelope rotation, on a change of pool operator. Under that index the
     *    replacement mint fails, and the only routes left are mutating or deleting the live row,
     *    which in this service means orphaning the coin at an address whose row no longer says who
     *    holds it. Rotation must stay three deliberate steps (mint, move the balance, repoint), and a
     *    unique index deletes the first one for ever after the first mint.
     *
     * SO NOTHING, AND THAT IS NOT A GAP. Custody does not know which of its `pool` addresses is live;
     * it is not a fact this service holds. micro-pool reads exactly one address per chain from
     * `POOL_<CHAIN>_PAYOUT_ADDRESS` and refuses to boot without it, so "one per chain and network" is
     * enforced by configuration in the service that actually pays the coinbase. Custody has exactly
     * one table that says "this address is the live one for this chain" — `custody_treasuries` — and
     * the entire point of the argument above is that a `pool` row must never appear in it.
     *
     * ── RUNNING IT ───────────────────────────────────────────────────────────────────────────
     *
     * Drop then add, both inside the one transaction `@cloudsforge/db` wraps a migration in, so there
     * is no instant at which `custody_keys` has no purpose check at all. The new check is strictly
     * weaker than the one it replaces — same four values plus one — so every existing row satisfies
     * it by construction and the validation scan cannot fail. `custody_keys` holds one row per address
     * the platform has ever minted, so that scan is milliseconds; ALTER TABLE takes an
     * AccessExclusiveLock and the migrator already holds an advisory lock of its own, so nothing is
     * reading the table while it runs.
     */
    up: `
      alter table custody_keys drop constraint if exists custody_keys_purpose_ck;
      alter table custody_keys
        add constraint custody_keys_purpose_ck
          check (purpose in ('deposit','treasury','deployer','user','pool'));
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
