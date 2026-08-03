# cloudsforge-custody

Key custody for CloudsForge: HD seeds, key generation, the encryption envelope, the **signing
policy**, treasury pins, the key lifecycle and the export ceremony.

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

It supersedes `forge-keyvault`. The signing policy is carried forward almost unchanged — SD-09 calls
it the best-designed component in the estate — and seven named defects around it are fixed.

**This service makes no outbound call except to `policy`.** No RPC providers, no price feeds, no
product services. Its network reachability is the security model (03 §3, SD-13), and `env.test.ts`
asserts that no variable it reads names a third destination.

---

## What is carried forward, unchanged

The gate order in `src/gates.ts` and `src/signing.ts`, which **does not change**:

1. **Purpose gate** — a `deposit` key signs exactly one shape, `sweep`. A `treasury` key signs
   `transfer`. A `deployer` key signs zero-value contract creation only.
2. **Binding check** — five fields restated by the caller, compared to the stored row.
3. **Chain-id resolution** — a generic `evm` is refused outright, because a signature without a
   chain id is valid on every EVM chain.
4. **Treasury pin** — a sweep's destination is chosen **by the vault**, never by the caller.
5. **And only then is the key decrypted.**

Every gate that can fail closed runs before the decrypt, so a refused request never causes a private
key to exist in the process at all.

Per-family shape allowlists: an EVM field allowlist with exactly one fee model and a
`gasLimit × maxFee` ceiling; a Solana instruction allowlist admitting SPL mint creation only, with
Transfer, Approve, SetAuthority, Burn and CloseAccount refused; Bitcoin PSBTs only, every input's
`witnessUtxo.script` belonging to the signing address, SIGHASH_ALL only; XRP `Payment` only with a
bound `Account`, a fee ceiling and a mandatory `LastLedgerSequence`.

AES-256-GCM envelope with per-address scrypt-derived data keys. Boot-time refusal of placeholder
secrets.

---

## What is fixed

| # | Defect | Where | How |
| --- | --- | --- | --- |
| 1 | `KEYVAULT_MASTER_SECRET` **cannot be rotated** — a compromise is unrecoverable (SDR-03) | `crypto.ts`, `reencrypt.ts` | The envelope version selects a **secret**, not just a salt. `CUSTODY_MASTER_SECRET_V<n>` is a keyring; a background pass re-encrypts; the old secret can then be removed. Rotation is a **deploy**, not a release. |
| 2 | `row.userId` was compared to nothing | `gates.ts` | It is one of the five binding fields, and it is compared. |
| 3 | A *successful* `/sign` recorded nothing at all | `keys.ts`, `signing_audit` | Every signature writes an audit row **in the same transaction**. Refusals too, with the gate that refused. |
| 4 | No rate limiting | `ratelimit.ts` | Per calling credential, on `/v1/sign` and address creation, counted from the audit table. |
| 5 | XRP testnet and mainnet share a seed and address | `hd.ts`, `keys.ts` | BIP-44 gives testnet coin type 1, so the two networks are different accounts. A flat-random XRP key can no longer be minted at all. |
| 6 | No HD derivation, no seed, no mnemonic | `hd.ts` | BIP-39/32/44 with a per-(user, family) seed, checked against the published vectors. Legacy flat-random keys stay flat and are **not** migratable; every response states `scheme`. |
| 7 | `POST /admin/keys/:address/reveal` — total exfiltration in a loop | `exports.ts` | **Deleted.** Replaced by the user-facing export ceremony: policy decision → 24-hour cooling-off → second challenge → single-use short-TTL reveal token → wallet becomes `exported`, irreversibly. |

---

## The two key schemes, permanently

04-domain-model §3.3. Addresses created before HD derivation are `flat_random`: one key each, no
seed, no path, **no recovery phrase**. They cannot be retrofitted — deriving a new key would produce
a *different address*, so "migrating" a row means abandoning the coins at the old one (SDR-08).

So both schemes coexist for ever, both are signable, both are exportable, and every custody response
states which one an address is, because that decides which export formats can honestly be offered.
The database enforces the distinction: a `flat_random` row carrying a derivation path is refused by
a CHECK constraint, so nothing can quietly relabel a legacy key as recoverable from a phrase that
does not exist.

**XRP's derivation rule is ours and is written down here**, because a recovery phrase that only
restores under an undocumented rule is not a recovery phrase. An XRP secret is a base58 family seed
carrying 16 bytes of entropy, and no standard maps a BIP-32 node onto one. Custody takes the node at
`m/44'/144'/0'/0/<index>` (or `m/44'/1'/…` on testnet) and uses **the first 16 bytes of its private
key** as secp256k1 entropy for the family seed.

---

## The vault: encrypted blobs on disk, and what that trades away

`src/vault.ts` writes one directory per address under `CUSTODY_DATA_DIR`, mode `0700`, holding one
`key.enc` at `0600`, replaced atomically by `rename`.

**The Docker-socket, container-per-address design is deliberately not reproduced.** The service this
supersedes provisions a per-address Docker volume inside a per-address `alpine` holder container
with `NetworkMode: none`, driven over a read-write Docker socket by a process running as **root**.
SD-06 freezes that design where it is; SDR-01 records it as *the largest accepted risk in the
estate*, and SDR-02 records that it is also what makes custody permanently single-host.

What that design buys is real: a holder container has no network, and its volume is not on the
service's own filesystem. What it costs is that any RCE in custody is total custody loss, because
the process is root and the socket is a whole-host primitive.

What is **kept** here is the property that actually defends the keys: an attacker with database
access gets nothing at all, because no key material and no ciphertext is in the database — only
addresses, versions and audit rows. What is **given up** is isolation from an attacker who already
has code execution as this process — and against that attacker the holder containers were never a
defence either, since the same process holds the master secret in memory and can ask the socket for
any volume it likes.

**The conditions that would reverse this decision:** an HSM or cloud KMS for the master secret
(open in doc 16), which changes the calculus entirely because the secret would stop being in this
process's memory; or a measured attack that recovers a key from disk without code execution, which
would mean the envelope rather than the storage is the weak part.

`CUSTODY_DATA_DIR` must be a mounted, backed-up volume — and its backups must be stored
**separately from the master secret**. A backup and its secret in one place is a plaintext key store
with extra steps (SD-17).

---

## The export ceremony

SD-07, and the replacement for the deleted reveal route. `active → exported`, irreversibly.

| # | Gate | Where |
| --- | --- | --- |
| 1 | Password re-authentication | `amr` contains `pwd` |
| 2 | MFA challenge | `amr` contains `mfa` |
| 3 | `policy.decide('custody.key.export')` | `policy.ts`, **fail-closed** |
| 4 | **24-hour cooling-off**, cancellable | `available_at` |
| 5 | Critical notification at request and expiry | emitted as events; the notifier is elsewhere |
| 6 | Second MFA at redemption | a *fresh* `amr` and `auth_time` |
| 7 | Single-use, short-TTL reveal token | SHA-256 at rest, constant-time compare |
| 8 | Delivered once, never logged, `no-store` | set centrally, so a route cannot forget it |
| 9 | Wallet → `exported`; custody stops signing for it | `purposeGate` refuses it |
| 10 | Recorded for both parties | outbox events on request, cancel and completion |

**No operator credential can complete any step.** Every one compares `user_id` on the row — which is
the control the deleted route had no answer for.

Formats: encrypted UTC/JSON keystore by default (EVM), BIP-39 mnemonic (HD wallets only), raw key,
WIF (Bitcoin), XRP family seed. A format the key cannot honestly produce is refused **at request
time**, so a user is not told "no" after waiting a day.

---

## Running it

```sh
pnpm install
cp .env.example .env          # then fill in OUTBOX_SIGNING_SECRET and CUSTODY_MASTER_SECRET_V2
pnpm migrate                  # the one-shot migrator, separately from the service
pnpm start
```

```sh
pnpm typecheck && pnpm test

# The database-backed tests skip unless this is set, and the name must contain "test":
# they truncate, and that requirement is the difference between a red build and an emptied
# key store.
CUSTODY_TEST_DATABASE_URL=postgres://…/custody_test pnpm test
```

`--test-concurrency=1` is required, not a preference: the database test files truncate between
cases, and `node:test` runs *files* in parallel by default. A `TRUNCATE` takes an
`AccessExclusiveLock`, so one file's reset deadlocks against another file's inserts.

---

## Rotating the master secret

```sh
# 1. Add the new secret. LEAVE THE OLD ONE IN PLACE.
CUSTODY_MASTER_SECRET_V3=$(openssl rand -base64 48)

# 2. Make it the write version and restart. Existing blobs still decrypt under V2.
CUSTODY_KEY_VERSION=3

# 3. Drain. The job does this on its own every 30s; this forces it and exits non-zero
#    while anything remains, so it is safe in a deploy gate.
pnpm reencrypt
curl -s localhost:4005/v1/admin/rotation -H "authorization: Bearer $ADMIN"   # remaining must be 0

# 4. ONLY NOW remove CUSTODY_MASTER_SECRET_V2.
```

Removing the old secret at step 3 loses every key still on it. The command's exit code and the
`custody_key_version_backlog` gauge exist so that "can I remove it yet" has a machine answer.

---

## Routes

| Method | Path | Credential |
| --- | --- | --- |
| GET | `/livez` `/readyz` `/metrics` | none |
| POST | `/v1/addresses` | `custody:address:create` |
| GET | `/v1/addresses/:address` | scoped service, or the owner |
| GET | `/v1/keys` | user |
| GET | `/v1/treasuries/:chain/:network` | `custody:treasury:read` — **read only, no writer here** |
| POST | `/v1/sign` | `custody:sign:<purpose>` |
| POST/GET | `/v1/exports`, `/v1/exports/:id` | the owner, and only the owner |
| POST | `/v1/exports/:id/{cancel,challenge,redeem}` | the owner |
| GET | `/v1/admin/keys`, `/v1/admin/keys/:address`, `…/audit` | `admin` role |
| GET/POST/PUT | `/v1/admin/treasuries…` | `admin` role |
| GET | `/v1/admin/rotation` | `admin` role |
| ~~POST~~ | ~~`/admin/keys/:address/reveal`~~ | **deleted — 404, asserted in the suite** |

`GET /v1/addresses/:address` publishes neither `userId` nor `orderId`. Publishing them made the
`/sign` binding check circular: everything a caller had to "prove" it knew was served, under the same
credential, from a read.

Exactly one route can return key material — `POST /v1/exports/:id/redeem` — and
`src/bodyscan.test.ts` drives every other route under every credential and proves none of them can
(SD-16).

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, under
human direction and review.
