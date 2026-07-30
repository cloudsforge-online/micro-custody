/**
 * Where the encrypted blobs live.
 *
 * ONE DIRECTORY PER SLOT UNDER `CUSTODY_DATA_DIR`, MODE 0700, HOLDING ONE `key.enc` AT 0600.
 *
 * THE DOCKER-SOCKET DESIGN IS DELIBERATELY NOT REPRODUCED. forge-keyvault provisions a per-address
 * Docker volume inside a per-address `alpine` holder container with `NetworkMode: none`, driven
 * over a read-write Docker socket by a process running as ROOT. SD-06 freezes that design where it
 * is and SDR-01 records it as "the largest accepted risk in the estate": root plus a read-write
 * Docker socket means any RCE in custody is total custody loss, and it is also what makes custody
 * permanently single-host (SDR-02).
 *
 * The isolation it buys is real — a holder container has no network and its volume is not on the
 * service's own filesystem — and it is bought at a price this service is not willing to pay for a
 * clean start. What is kept is the property that actually defends the keys: an attacker with
 * DATABASE access gets nothing, because no ciphertext and no key material is in the database at
 * all. What is given up is isolation from an attacker who already has code execution as this
 * process — and against that attacker the holder containers were never a defence either, since the
 * same process holds the master secret in memory and can ask the socket for any volume it likes.
 *
 * The trade-off, and the conditions that would reverse it, are in the README.
 */

import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'

export type StorageKind = 'file'

/** A slot is an address, or `seed:<uuid>` for the HD seeds, which have no chain address. */
export type Slot = string

export interface Vault {
  readonly kind: StorageKind
  write(slot: Slot, blob: string): Promise<StorageKind>
  read(slot: Slot): Promise<string>
}

/**
 * Slot names reach the filesystem, so they are validated rather than trusted.
 *
 * Chain addresses are base58, bech32 or 0x-hex and none of them contains a separator — but the slot
 * for a seed is built from a uuid this service generated, and the day somebody passes a
 * caller-supplied string here is the day `../../etc` becomes a key directory. Refusing here is one
 * line; noticing later is an incident.
 */
const SAFE_SLOT = /^[A-Za-z0-9:_-]{1,128}$/

export class FileVault implements Vault {
  readonly kind: StorageKind = 'file'
  readonly #root: string

  constructor(root: string) {
    this.#root = root
  }

  #dir(slot: Slot): string {
    if (!SAFE_SLOT.test(slot)) throw new Error('unsafe custody slot name')
    return resolve(this.#root, slot)
  }

  /**
   * Write, atomically.
   *
   * A truncate-then-write loses the key if the process dies between the two, and the re-encryption
   * pass rewrites live blobs — so a crash mid-rotation would destroy a customer's key rather than
   * leaving it on the old version. `rename` within one directory is atomic on every filesystem this
   * runs on, so the reader sees either the whole old blob or the whole new one.
   */
  async write(slot: Slot, blob: string): Promise<StorageKind> {
    const dir = this.#dir(slot)
    await mkdir(dir, { recursive: true, mode: 0o700 })
    // mkdir's mode is masked by the process umask, so it is asserted rather than requested.
    await chmod(dir, 0o700)
    const temp = resolve(dir, `.key.enc.${randomBytes(6).toString('hex')}`)
    await writeFile(temp, blob, { mode: 0o600 })
    await rename(temp, resolve(dir, 'key.enc'))
    return 'file'
  }

  async read(slot: Slot): Promise<string> {
    return readFile(resolve(this.#dir(slot), 'key.enc'), 'utf8')
  }
}

/** An in-memory vault. Test seam only — it is never constructed by `index.ts`. */
export class MemoryVault implements Vault {
  readonly kind: StorageKind = 'file'
  readonly #blobs = new Map<string, string>()

  async write(slot: Slot, blob: string): Promise<StorageKind> {
    if (!SAFE_SLOT.test(slot)) throw new Error('unsafe custody slot name')
    this.#blobs.set(slot, blob)
    return 'file'
  }

  async read(slot: Slot): Promise<string> {
    const blob = this.#blobs.get(slot)
    if (blob === undefined) throw new Error(`no custody blob for ${slot}`)
    return blob
  }
}

/** The slot a seed's secret lives at. Namespaced so it can never collide with a chain address. */
export function seedSlot(seedId: string): Slot {
  return `seed:${seedId}`
}
