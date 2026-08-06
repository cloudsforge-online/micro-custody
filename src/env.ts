/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — a repo declares the variables it needs and the deploy provides
 * exactly those. The boot-time refusal of a placeholder secret is CARRIED FORWARD from
 * forge-keyvault, which is the only service in the old estate that gets it right: a default secret
 * in source is not convenient, it is catastrophic, because everything derived from it is forgeable
 * by anyone who can read the repository.
 *
 * ONE VARIABLE HERE IS READ BY PATTERN RATHER THAN BY NAME, and that is the fix for SDR-03.
 * `CUSTODY_MASTER_SECRET_V<n>` is enumerated from the environment instead of being listed as
 * `..._V1`, `..._V2`, `..._V3`. Rotating the master secret must be a DEPLOY, not a release: an
 * operator adds `CUSTODY_MASTER_SECRET_V3`, moves `CUSTODY_KEY_VERSION` to 3, lets the
 * re-encryption job drain, and then removes V2. If the version had to be added to this file first,
 * a rotation would need a code change, a review and an image build in the middle of an incident —
 * which is how a secret ends up never being rotated at all.
 *
 * WHAT IS DELIBERATELY ABSENT: any RPC endpoint, any price feed, any product service URL. Custody
 * makes no outbound call except to `policy` (03 §3, SD-13). Its network reachability is the whole
 * security model, so a variable naming a third destination would be the defect, not the feature.
 *
 * `CUSTODY_TOKEN` IS ALSO DELIBERATELY ABSENT, and it is worth saying so rather than leaving the
 * next reader to rediscover it. That variable exists — `deploy/compose/docker-compose.estate.yml`
 * sets it on `faucet` and `faucet-migrate`, fed from `FAUCET_CUSTODY_TOKEN` — but it belongs to
 * micro-faucet, which READS it (`faucet/src/env.ts`) and PRESENTS it to this service as a
 * bearer. Custody is the audience, not the holder: it verifies whatever arrives against the JWKS at
 * `IDENTITY_JWKS_URL`, so it needs no copy of the token and must never be given one. Declaring it
 * here would put it in the manifest rule 9 derives from this file, and a service that is handed a
 * credential it does not use is exactly the `env_file:` fan-out that rule exists to end.
 *
 * (The live value is an EXPIRED JWT — micro-org #222 — which is a real defect and is micro-faucet's
 * to fix, by adopting `ServiceTokenProvider` against `FAUCET_IDENTITY_CREDENTIAL`. Nothing in this
 * file can fix it, and nothing in this file should pretend to.)
 */

import { hostname } from 'node:os'
import { SecretError, assertGeneratedSecret } from '@cloudsforge/secrets'

/**
 * The service's own name. A constant, not a variable: it seeds the migration advisory lock, and
 * making it configurable is how two services end up sharing one.
 */
export const SERVICE = 'custody'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

/**
 * THE `PLACEHOLDERS` SET THAT USED TO BE HERE IS GONE, AND ITS ABSENCE IS THE FIX.
 *
 * It held ten exact strings and was paired with a 32-character floor. Neither could fail for the
 * value that actually reached 44 containers on both networks: micro-org #142's
 * `estate-only-outbox-secret-00000000000000` is 40 characters and was on nobody's list. A check
 * that cannot fail is worse than no check, because the absence of an alarm gets read as the absence
 * of a problem — and this service holds every private key the platform custodies.
 *
 * A deny-list of exact strings is structurally unable to work: the next placeholder somebody writes
 * is, by definition, not on it. `@cloudsforge/secrets` asserts the SHAPE of a generated value
 * instead, which is the property a placeholder cannot have. It is imported rather than copied so
 * that this service cannot drift from the other sixteen.
 *
 * The floors, the marker list and the ordering in that package were PORTED FROM THIS FILE — the
 * `assertMasterSecret` that used to live below was the only guard in the estate that got this
 * right, and micro-org #143 was the job of folding it in. What is deleted here is therefore the
 * original, not a copy of it, and keeping a second copy behind would be the drift the package
 * exists to prevent.
 */

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * Re-wrap the shared guard's `SecretError` as this service's `EnvError`.
 *
 * `loadEnv` documents a single error class for every configuration failure, and the boot path
 * catches that one class. The message is preserved verbatim — it already names the variable and the
 * command that fixes it, and it never contains the value.
 */
function asEnvError<T>(run: () => T): T {
  try {
    return run()
  } catch (err) {
    if (err instanceof SecretError) throw new EnvError(err.message)
    throw err
  }
}

/**
 * A secret THIS ESTATE GENERATES, held to the shape a generator produces and a keyboard does not.
 *
 * `assertGeneratedSecret` is the right class for both of custody's secret variables, and that was
 * checked against the running containers rather than inferred from the names — the estate has
 * `*_TOKEN` variables holding `cfsc_` credentials and `*_TOKEN` variables holding JWTs under the
 * same suffix, so a name classifies nothing. Measured on 2026-08-05:
 *
 *     CUSTODY_MASTER_SECRET_V2   base64, 64 characters, 48 bytes
 *     CUSTODY_MASTER_SECRET_V3   base64, 64 characters, 48 bytes
 *     OUTBOX_SIGNING_SECRET      base64, 64 characters, 48 bytes
 *
 * All three are `openssl rand` output written into a gitignored file by an operator following a
 * runbook, so the estate controls the alphabet and the strict rule is the correct one. Neither of
 * the other two classes applies: nothing here is minted by identity, and nothing here arrives from
 * a vendor whose alphabet somebody else chose.
 *
 * The old `minLength` parameter is gone rather than kept in front: it is a strict subset of the
 * shape check, and running it first answers a 40-character placeholder with "must be at least 32
 * characters" — true, useless, and about the wrong property.
 */
function requiredGeneratedSecret(source: Source, name: string): string {
  const value = required(source, name)
  asEnvError(() => assertGeneratedSecret(name, value))
  return value
}

/* -------------------------------------------- the master-secret guard, and where it lives now
 *
 * WHAT FAILED. `deploy/compose/docker-compose.estate.yml` carried a hardcoded 40-character master
 * secret in a PUBLIC repository, under a comment reading "Minimum 32 characters" — and it was. It
 * passed the `requiredSecret` this file used to carry: not one of the ten strings in `PLACEHOLDERS`,
 * and longer than the floor. Everything the estate had encrypted at rest was therefore encrypted
 * under a value anybody could read. The control that was supposed to stop this was a comment, and a
 * comment is not a control; a deny-list of exact strings is barely one, because the next placeholder
 * somebody writes is by definition not on it.
 *
 * THE RULE HAS NOT CHANGED — IT HAS MOVED. `@cloudsforge/secrets` asserts the shape of a generator's
 * output rather than a keyboard's: base64 or hex and nothing else, at least 32 decoded BYTES, a
 * MEASURED Shannon entropy floor per alphabet, and a normalised placeholder marker anywhere in the
 * value. Those four checks, those floors and that ordering were lifted from the function that stood
 * here — this file was the only place in the estate that got it right, and micro-org #143 was the
 * job of promoting it so the other sixteen services stop each writing their own slightly different
 * version. Read that package's header for the argument; it is not repeated here, because two copies
 * of an argument drift exactly as fast as two copies of a check.
 *
 * ONE CLAIM THAT USED TO BE HERE WAS WRONG AND IS NOT CARRIED FORWARD. This file said the marker
 * check "still fires the day somebody base64s a placeholder". It does not: base64 destroys the
 * substring the marker matches on, measured in that package's own test. The check is still worth
 * having for a placeholder WRITTEN in the base64 alphabet, which is a different thing.
 *
 * THERE IS NO OFF SWITCH, AND THAT IS THE POINT. No `NODE_ENV` exemption, no `CUSTODY_ALLOW_*`
 * variable, no CI branch. An escape hatch is a comment with a longer name — it would be reached for
 * in exactly the hurry that produced the defect. A developer who needs a secret runs one command;
 * `env.test.ts` asserts the absence of the hatches somebody would otherwise add.
 *
 * THIS GUARD PROVES SHAPE, NOT SECRECY. A high-entropy value published in a public repository still
 * passes, and nothing here can know that. Secrecy is the deploy's job and is bought by the value
 * living only in a gitignored file — see `deploy/compose/docker-compose.estate.yml`'s custody block.
 *
 * SCOPE IS NO LONGER "MASTER SECRETS ONLY". This file used to argue that `OUTBOX_SIGNING_SECRET`
 * had to be exempt, because holding custody alone to the strict rule would stop custody booting on a
 * value every peer still accepts. That was true when it was written and is not true now: the estate
 * rotated the outbox key onto generated material (measured on both networks 2026-08-06: 64
 * characters, base64, 48 BYTES, 5.27 bits per character — `openssl rand -base64 48`), and the guard
 * is landing in every service at once rather than in this one.
 * The exemption was the last thing keeping the #142 placeholder bootable here, so it is gone.
 */

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

/** `CUSTODY_MASTER_SECRET_V<n>`. The `n` is the envelope version the secret decrypts. */
const MASTER_SECRET_VAR = /^CUSTODY_MASTER_SECRET_V([0-9]{1,3})$/

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  readonly databaseUrl: string
  readonly databasePoolMax: number
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  readonly outboxSigningSecret: string
  readonly instanceId: string
  /** Where the encrypted blobs live. One directory per address, `0700`, files `0600`. */
  readonly dataDir: string
  /** The envelope version NEW blobs are written under. Every lower version stays readable. */
  readonly keyVersion: number
  /** version → master secret. Every version any stored blob might carry must be present. */
  readonly masterSecrets: ReadonlyMap<number, string>
  /** The ONLY outbound destination this service has. See SD-13. */
  readonly policyBaseUrl: string
  /** SD-07 gate 4. Configurable because staging rehearses the ceremony; never below one hour. */
  readonly exportCoolingOffHours: number
  /** How long a redeemed-but-unspent reveal token lives. SD-07 gate 7: short. */
  readonly exportTokenTtlSeconds: number
  /** An abandoned export request must not stay redeemable for ever. */
  readonly exportRequestTtlHours: number
  readonly signRatePerMinute: number
  readonly addressRatePerHour: number
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

/**
 * Collect every `CUSTODY_MASTER_SECRET_V<n>` present, and refuse the ones that are not secrets.
 *
 * The map is what makes rotation possible at all. `decryptForAddress` selects the secret by the
 * version stamped on the blob it was handed, so a v2 blob keeps decrypting under the v2 secret
 * after v3 has become the write version — which is precisely the property SDR-03 says custody does
 * not have today, where `KEYVAULT_MASTER_SECRET` is one string and changing it bricks every key in
 * the estate.
 */
export function collectMasterSecrets(source: Source): Map<number, string> {
  const secrets = new Map<number, string>()
  for (const [name, raw] of Object.entries(source)) {
    const match = MASTER_SECRET_VAR.exec(name)
    if (!match) continue
    // EMPTY IS UNSET, AND THAT IS A SUPPORTED MODE RATHER THAN AN OVERSIGHT. Compose interpolates
    // `${CUSTODY_MASTER_SECRET_V3:-}` and an unset variable arrives as the empty string, not as an
    // absent key — so a deployment that has only reached step 1 of a rotation for ONE of its two
    // networks renders an empty `_V3` on the other. Skipping it is safe only because the WRITE
    // version must be present in the map: an empty `_V3` cannot silently downgrade new blobs back
    // to v2, it fails to boot with `CUSTODY_KEY_VERSION` named. The check therefore stays AHEAD of
    // the assertion; putting the assertion first would turn every such render into `exit(1)` on the
    // service that holds every custodied key.
    const value = raw?.trim()
    if (!value) continue
    const version = Number(match[1])
    if (version < 1) {
      throw new EnvError(`${name} names version ${version}; envelope versions start at 1`)
    }
    // EVERY version, not just the write version. A retained old secret is not a lesser secret: it
    // still decrypts every blob that has not yet been re-encrypted, so a placeholder kept "just for
    // the drain" is the whole compromise for as long as the drain takes. Draining off a placeholder
    // is therefore work for the image that predates this guard, which is friction in exactly the
    // right direction.
    asEnvError(() => assertGeneratedSecret(name, value))
    secrets.set(version, value)
  }
  return secrets
}

/** Pure over its source so the failure paths are testable without mutating the process. */
export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  const masterSecrets = collectMasterSecrets(source)
  if (masterSecrets.size === 0) {
    throw new EnvError(
      'at least one CUSTODY_MASTER_SECRET_V<n> is required — custody cannot read or write a key without one',
    )
  }
  const keyVersion = integer(source, 'CUSTODY_KEY_VERSION', Math.max(...masterSecrets.keys()), 1, 999)
  if (!masterSecrets.has(keyVersion)) {
    // Fail closed and name the variable. Booting without the write version's secret means every
    // address minted from this replica is encrypted under a key nothing holds.
    throw new EnvError(
      `CUSTODY_KEY_VERSION is ${keyVersion} but CUSTODY_MASTER_SECRET_V${keyVersion} is not set — ` +
        'new keys would be written under a secret this process does not have',
    )
  }

  // Not below an hour, ever. The cooling-off is the only control in SD-07 that works while the
  // user is actively being deceived, and a deployment that sets it to a minute has removed it.
  const exportCoolingOffHours = integer(source, 'CUSTODY_EXPORT_COOLING_OFF_HOURS', 24, 1, 720)

  return {
    // 4005, not 4008. micro-indexer also binds 4008, so the two could not run together on one
    // machine — and the registry has said 4005 for this service all along: `keyvault`, "Custodial
    // key service" (`ui/packages/ui/src/surfaces.ts`). The indexer keeps 4008 because four
    // consumers name it (mint, foresight and market via INDEXER_URL, plus the explorer surface),
    // where only micro-faucet names custody's.
    port: integer(source, 'PORT', 4005, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'CUSTODY_DATABASE_URL'),
    databasePoolMax: integer(source, 'CUSTODY_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    // No longer exempt from the shape rule — see "SCOPE IS NO LONGER MASTER SECRETS ONLY" above.
    outboxSigningSecret: requiredGeneratedSecret(source, 'OUTBOX_SIGNING_SECRET'),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),
    dataDir: optional(source, 'CUSTODY_DATA_DIR', '/var/lib/custody/keys'),
    keyVersion,
    masterSecrets,
    policyBaseUrl: required(source, 'POLICY_BASE_URL'),
    exportCoolingOffHours,
    exportTokenTtlSeconds: integer(source, 'CUSTODY_EXPORT_TOKEN_TTL_SECONDS', 300, 30, 3_600),
    exportRequestTtlHours: integer(source, 'CUSTODY_EXPORT_REQUEST_TTL_HOURS', 168, 2, 2_160),
    signRatePerMinute: integer(source, 'CUSTODY_SIGN_RATE_PER_MINUTE', 60, 1, 10_000),
    addressRatePerHour: integer(source, 'CUSTODY_ADDRESS_RATE_PER_HOUR', 500, 1, 100_000),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and the
 * only symptom is a container that exits instantly.
 *
 * So emit one structured fatal line by hand, built from a literal rather than routed through the
 * telemetry package — nothing that can itself fail may sit between a configuration error and the
 * report of it. The message is the one `loadEnv` produced, which by construction never contains a
 * value.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
