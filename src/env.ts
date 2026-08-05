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

/* ------------------------------------------------------- the master-secret guard, and its argument
 *
 * WHAT FAILED. `deploy/compose/docker-compose.estate.yml` carried a hardcoded 40-character master
 * secret in a PUBLIC repository, under a comment reading "Minimum 32 characters" — and it was. It
 * passed `requiredSecret` above: not one of the eight strings in `PLACEHOLDERS`, and longer than the
 * floor. Everything the estate had encrypted at rest was therefore encrypted under a value anybody
 * could read. The control that was supposed to stop this was a comment, and a comment is not a
 * control; a deny-list of exact strings is barely one, because the next placeholder somebody writes
 * is by definition not on it.
 *
 * THE RULE, AND WHY IT IS THIS ONE. A guard cannot test secrecy — it holds a string, not the
 * internet. What it CAN test is whether the string has the shape of a generator's output rather than
 * a keyboard's, and every placeholder that has ever reached this estate came from a keyboard. So:
 *
 *   1. The value must be BASE64 or HEX and nothing else. This alone rejects every placeholder in the
 *      estate's compose files, because a human writing a memorable value reaches for a hyphen and
 *      neither alphabet contains one. It costs an operator nothing: `openssl rand -base64 48` is
 *      what the README already tells them to run.
 *   2. It must decode to at least 32 BYTES. The old floor counted keystrokes; the unit that matters
 *      is entropy, and 32 characters of prose is not 32 bytes of key.
 *   3. Its Shannon entropy per character must clear a floor, which is what rejects a value that is
 *      long, well-formed and degenerate — 64 zeros, `deadbeef` eight times. The floors are MEASURED,
 *      not guessed: over 200,000 samples the minimum was 4.292 for `rand -base64 32`, 4.605 for
 *      `rand -base64 48`, and 3.375 for `rand -hex 32`. The floors sit below those with margin, so
 *      the chance of refusing a genuinely generated secret is negligible — which matters, because a
 *      guard that occasionally rejects correct input is a guard somebody removes.
 *   4. A normalised placeholder MARKER anywhere in the value is refused. Punctuation and case are
 *      stripped first, so `estate-only`, `ESTATE_ONLY` and `estateonly` are one rule. This is
 *      redundant with (1) for every value seen so far, and it is kept because it is the check that
 *      still fires the day somebody base64s a placeholder.
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
 * SCOPE: MASTER SECRETS ONLY, on purpose. `OUTBOX_SIGNING_SECRET` is one shared HMAC key across
 * fifteen services, and holding custody alone to this rule would stop custody booting on a value
 * every peer still accepts — an outage, not a fix. The estate's outbox secret is a placeholder in
 * the same public file and is a LIVE DEFECT; it needs one coordinated rotation across every service
 * that verifies with it, which is a different change from this one.
 */

/** Standard base64, padding optional. `-` and `_` are absent on purpose: see marker note below. */
const BASE64_ONLY = /^[A-Za-z0-9+/]+={0,2}$/
const HEX_ONLY = /^[0-9a-fA-F]+$/

/** Bytes, not characters. `openssl rand -base64 32` and `openssl rand -hex 32` both clear it. */
const MIN_SECRET_BYTES = 32

/**
 * Shannon entropy floors, per character, per alphabet — because the ceilings differ: 6 bits for
 * base64 and 4 for hex, so one number cannot serve both. See the measured minima in the header.
 */
const MIN_ENTROPY_BASE64 = 4.0
const MIN_ENTROPY_HEX = 2.8

/**
 * Placeholder markers, PUNCTUATION AND CASE STRIPPED before matching.
 *
 * Every entry is six characters or more. That is not stylistic: the test is a substring test over a
 * value that may legitimately be random, and a four-letter marker would match a genuine secret about
 * once in seventeen thousand — a boot failure nobody could explain. At six the odds are below one in
 * ten million per marker, and a spurious refusal is one regeneration away in any case.
 */
const SECRET_MARKERS = [
  'estateonly',
  'testonly',
  'localonly',
  'changeme',
  'placeholder',
  'notareal',
  'notarealsecret',
  'donotuse',
  'insecure',
  'example',
  'replaceme',
  'temporary',
  'password',
  'mastersecret',
  'sufficientlength',
]

function normalise(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '')
}

/** Shannon entropy of the value's own character distribution, in bits per character. */
export function entropyPerChar(value: string): number {
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)
  let bits = 0
  for (const n of counts.values()) {
    const p = n / value.length
    bits -= p * Math.log2(p)
  }
  return bits
}

/**
 * The one gate every `CUSTODY_MASTER_SECRET_V<n>` passes through.
 *
 * NO MESSAGE BELOW CONTAINS THE VALUE. `fatalConfig` writes `err.message` verbatim to stderr and the
 * collector ships it, so an echoed secret would move from one public place to another. Lengths and
 * measurements only — and every message names the variable and the command that fixes it, because a
 * refusal an operator cannot act on is an outage rather than a control.
 */
export function assertMasterSecret(name: string, value: string): void {
  const fix = `generate one with: openssl rand -base64 48`

  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new EnvError(`${name} is set to a known placeholder — ${fix}`)
  }

  const flat = normalise(value)
  for (const marker of SECRET_MARKERS) {
    if (flat.includes(marker)) {
      throw new EnvError(`${name} reads as a placeholder (it contains '${marker}') — ${fix}`)
    }
  }

  const hex = HEX_ONLY.test(value)
  const base64 = !hex && BASE64_ONLY.test(value)
  if (!hex && !base64) {
    // The check that catches every placeholder this estate has actually written, all of which
    // contain a hyphen. Naming the alphabets rather than the offending character keeps the value out
    // of the message.
    throw new EnvError(
      `${name} is not base64 or hex — a master secret is generated, not typed, and a typed one is ` +
        `readable by whoever reads the file it was typed into. ${fix}`,
    )
  }

  const bytes = hex ? Math.floor(value.length / 2) : Buffer.from(value, 'base64').length
  if (bytes < MIN_SECRET_BYTES) {
    throw new EnvError(
      `${name} carries ${bytes} bytes of key material and at least ${MIN_SECRET_BYTES} are required ` +
        `— length in CHARACTERS is not the unit that matters. ${fix}`,
    )
  }

  const floor = hex ? MIN_ENTROPY_HEX : MIN_ENTROPY_BASE64
  const measured = entropyPerChar(value)
  if (measured < floor) {
    throw new EnvError(
      `${name} is long enough but its entropy is ${measured.toFixed(2)} bits per character, below ` +
        `the ${floor} floor for ${hex ? 'hex' : 'base64'} — a repeated pattern is not a key. ${fix}`,
    )
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
    // EVERY version, not just the write version. A retained old secret is not a lesser secret: it
    // still decrypts every blob that has not yet been re-encrypted, so a placeholder kept "just for
    // the drain" is the whole compromise for as long as the drain takes. Draining off a placeholder
    // is therefore work for the image that predates this guard, which is friction in exactly the
    // right direction.
    assertMasterSecret(name, value)
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
    // key service" (`ui/packages/ui/src/surfaces.ts:537-542`). The indexer keeps 4008 because four
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
