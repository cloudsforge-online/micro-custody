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
 */

import { hostname } from 'node:os'

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
 * Values that must never be accepted. Short on purpose: these are the strings that actually appear
 * in this repository's own `.env.example` and in the estate's compose files, because those are the
 * ones somebody in a hurry copies into a deployment.
 */
const PLACEHOLDERS = new Set([
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'dev-secret',
  'dev-master-secret',
  'dev-outbox-signing-secret',
  'replace-with-a-real-secret',
  'test-master-secret',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * A secret, with the two checks that matter. Length is a proxy for entropy and the only one
 * available here; it is set above the point at which a human-chosen string is plausible, so a
 * memorable password fails too.
 */
function requiredSecret(source: Source, name: string, minLength = 32): string {
  const value = required(source, name)
  assertSecret(name, value, minLength)
  return value
}

function assertSecret(name: string, value: string, minLength: number): void {
  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new EnvError(`${name} is set to a known placeholder — generate a real secret`)
  }
  if (value.length < minLength) {
    throw new EnvError(`${name} must be at least ${minLength} characters (got ${value.length})`)
  }
}

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
    const value = raw?.trim()
    if (!value) continue
    const version = Number(match[1])
    if (version < 1) {
      throw new EnvError(`${name} names version ${version}; envelope versions start at 1`)
    }
    assertSecret(name, value, 32)
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
    port: integer(source, 'PORT', 4008, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'CUSTODY_DATABASE_URL'),
    databasePoolMax: integer(source, 'CUSTODY_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    outboxSigningSecret: requiredSecret(source, 'OUTBOX_SIGNING_SECRET'),
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
