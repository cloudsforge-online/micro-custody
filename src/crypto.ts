/**
 * The encryption envelope.
 *
 * CARRIED FORWARD, because SD-06 says to keep it: AES-256-GCM with a per-address, scrypt-derived
 * data key. Deriving per address means one leaked data key never unlocks another address, and an
 * attacker with database access gets ciphertext and nothing else.
 *
 * THE DEFECT THIS FILE FIXES IS SDR-03. forge-keyvault's `crypto.ts` already carries a `v<n>:`
 * prefix and already folds the version into the scrypt salt — and it is still unrotatable, because
 * every version derives from the SAME `env.masterSecret`. The version selected the salt; it did not
 * select the secret. So changing `KEYVAULT_MASTER_SECRET` makes every blob in custody
 * undecryptable, in every version, at once. "A compromise is unrecoverable" is not an acceptable
 * property for a custody system (SD-06), and it is the reason SDR-03 says to treat any custody host
 * compromise as terminal.
 *
 * The fix is that the version now selects a SECRET, from a keyring:
 *
 *   v1 — `scrypt(secret_v1, "cf:custody:v1:<address>")`, N = 16384. The salt is the address.
 *   v2 — `scrypt(secret_v2, <16 random bytes>)`, N = 32768, and the salt is stored IN the envelope.
 *
 * v2 is not merely "v1 under a different secret". SD-06 rejected "raising the scrypt cost and
 * randomising the salt in place" as impossible without versioning — so versioning arriving is
 * exactly when those two become possible, and doing them in the same version is cheaper than two
 * rotations. A random salt is what stops the address, a value published on chain, from being the
 * salt; the higher cost is what a 2015-era default no longer buys.
 *
 * ROTATION, END TO END: add `CUSTODY_MASTER_SECRET_V3`, set `CUSTODY_KEY_VERSION=3`, let
 * `reencryptOnce` drain, remove V2. At no point is a blob unreadable, because the keyring holds
 * every version any stored blob might carry and `decrypt` picks by the stamp on the blob itself.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

/**
 * `v<n>:<base64>`. ':' is not in the base64 alphabet, so a versioned blob and a bare one can never
 * be confused — which matters because a bare blob's leading byte is an IV that happens to start
 * that way once every 256 addresses, and there is therefore no BYTE that can be claimed as a
 * version marker.
 */
const VERSIONED = /^v([0-9]{1,3}):([A-Za-z0-9+/]+={0,2})$/

const IV_BYTES = 12
const TAG_BYTES = 16
const SALT_BYTES = 16
const KEY_BYTES = 32

/** Per-version key-derivation parameters. A released version's parameters are frozen for ever. */
interface VersionSpec {
  /** scrypt cost. Powers of two only. */
  readonly cost: number
  /** Whether the salt is random and carried in the envelope, or derived from the address. */
  readonly randomSalt: boolean
}

/**
 * Versions whose parameters are FROZEN because blobs exist on disk under them. A released version's
 * parameters can never be edited: doing so does not re-encrypt anything, it makes every blob at that
 * version undecryptable, which is the exact failure this whole file exists to remove.
 */
const LEGACY_SPECS: Readonly<Record<number, VersionSpec>> = Object.freeze({
  // What the service custody supersedes has on disk: address-derived salt, scrypt at the 2015
  // default cost.
  1: Object.freeze({ cost: 16_384, randomSalt: false }),
})

/**
 * The parameters for v2 AND EVERY VERSION ABOVE IT.
 *
 * This is what makes a rotation a DEPLOY rather than a RELEASE. If each version number needed its
 * own entry above, adding `CUSTODY_MASTER_SECRET_V3` would need a code change, a review and an image
 * build — in the middle of an incident, which is how a secret ends up never being rotated at all.
 * A version number selects a SECRET; it only selects PARAMETERS for the versions that predate the
 * current ones. Changing the parameters again is a new frozen entry here plus a new default, and
 * that IS a release, correctly.
 */
const CURRENT_SPEC: VersionSpec = Object.freeze({ cost: 32_768, randomSalt: true })

/** The first version written with the current parameters. Below it, `LEGACY_SPECS` governs. */
export const FIRST_CURRENT_VERSION = 2

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvelopeError'
  }
}

function specFor(version: number): VersionSpec {
  if (version < 1) throw new EnvelopeError(`envelope versions start at 1 (got ${version})`)
  return LEGACY_SPECS[version] ?? CURRENT_SPEC
}

/** The version stamped on a stored blob, without decrypting it. Used by the re-encryption pass. */
export function versionOf(blob: string): number {
  const match = VERSIONED.exec(blob.trim())
  if (!match) throw new EnvelopeError('blob carries no envelope version')
  return Number(match[1])
}

/**
 * The master secrets this process holds, by version.
 *
 * A class rather than a module-level `env` read, for one reason that is not tidiness: a rotation
 * test has to hold two keyrings at once — the old one that wrote the blob and the new one that must
 * still read it — and a module-level secret cannot be two values in one process.
 */
export class Keyring {
  readonly #secrets: ReadonlyMap<number, string>
  readonly #writeVersion: number

  constructor(secrets: ReadonlyMap<number, string>, writeVersion: number) {
    if (!secrets.has(writeVersion)) {
      throw new EnvelopeError(`no master secret for the write version v${writeVersion}`)
    }
    specFor(writeVersion)
    this.#secrets = secrets
    this.#writeVersion = writeVersion
  }

  get writeVersion(): number {
    return this.#writeVersion
  }

  /** Versions this keyring can read. An operator needs this to know when a rotation is finished. */
  get readableVersions(): readonly number[] {
    return [...this.#secrets.keys()].sort((a, b) => a - b)
  }

  #secret(version: number): string {
    const secret = this.#secrets.get(version)
    if (!secret) {
      throw new EnvelopeError(
        `no master secret for envelope version v${version} — set CUSTODY_MASTER_SECRET_V${version}`,
      )
    }
    return secret
  }

  #deriveKey(version: number, address: string, salt: Buffer | null): Buffer {
    const spec = specFor(version)
    const material = spec.randomSalt ? salt! : Buffer.from(`cf:custody:v${version}:${address}`, 'utf8')
    // maxmem must exceed 128 * N * r; the default 32 MiB is below what N = 32768 needs.
    return scryptSync(this.#secret(version), material, KEY_BYTES, { N: spec.cost, r: 8, p: 1, maxmem: 256 * 1024 * 1024 })
  }

  /**
   * Encrypt a private key for one address under the current write version.
   *
   * The blob is self-contained — `v<n>:` + base64 of (`salt?` || iv || tag || ciphertext) — so a
   * per-address storage location holds everything needed to decrypt it except the master secret,
   * which never leaves this process, and says which secret that is.
   */
  encrypt(address: string, plaintext: string): string {
    return this.encryptAs(this.#writeVersion, address, plaintext)
  }

  /** Encrypt under a named version. Only the re-encryption pass and its tests need this. */
  encryptAs(version: number, address: string, plaintext: string): string {
    const spec = specFor(version)
    const salt = spec.randomSalt ? randomBytes(SALT_BYTES) : null
    const key = this.#deriveKey(version, address, salt)
    const iv = randomBytes(IV_BYTES)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    // The address is authenticated data as well as key-derivation input. Moving a blob from one
    // address's directory to another's then fails the GCM tag rather than decrypting to a key that
    // does not match the row — a failure that would otherwise surface much later, as a signature
    // the chain rejects.
    cipher.setAAD(Buffer.from(`${address}|v${version}`, 'utf8'))
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    const parts = salt ? [salt, iv, tag, ct] : [iv, tag, ct]
    return `v${version}:${Buffer.concat(parts).toString('base64')}`
  }

  /** Decrypt a blob of ANY version this keyring holds a secret for. */
  decrypt(address: string, blob: string): string {
    const trimmed = blob.trim()
    const match = VERSIONED.exec(trimmed)
    if (!match) throw new EnvelopeError(`custody blob for ${address} carries no envelope version`)
    const version = Number(match[1])
    const spec = specFor(version)
    // Asked FIRST, before the blob is even measured. "This process holds no secret for v3" and
    // "this file is truncated" are different incidents with different remedies, and reporting the
    // second when the first is true sends an operator looking for a disk fault.
    this.#secret(version)
    const buf = Buffer.from(match[2]!, 'base64')

    let offset = 0
    let salt: Buffer | null = null
    if (spec.randomSalt) {
      salt = buf.subarray(0, SALT_BYTES)
      offset = SALT_BYTES
    }
    const iv = buf.subarray(offset, offset + IV_BYTES)
    const tag = buf.subarray(offset + IV_BYTES, offset + IV_BYTES + TAG_BYTES)
    const ct = buf.subarray(offset + IV_BYTES + TAG_BYTES)
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
      throw new EnvelopeError(`custody blob for ${address} is truncated`)
    }

    const key = this.#deriveKey(version, address, salt)
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAAD(Buffer.from(`${address}|v${version}`, 'utf8'))
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')
  }
}

/**
 * Constant-time comparison of two secrets presented as strings.
 *
 * Used for the export reveal token. A byte-at-a-time comparison of a bearer secret is a
 * byte-at-a-time forgery oracle, and the token this guards is the one credential in the estate that
 * yields a private key.
 */
export function secretEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}
