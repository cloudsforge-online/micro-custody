/**
 * The envelope, and the rotation SDR-03 says custody cannot do.
 *
 * SD-06's verification line is "a test that decrypts a `v1` blob after the master secret has been
 * rotated to a new value with re-encryption complete". That is the last test in this file, and it is
 * the one that matters: everything else here is scaffolding for it.
 */

import assert from 'node:assert/strict'
import { chmod, stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import test from 'node:test'
import { EnvelopeError, FIRST_CURRENT_VERSION, Keyring, secretEquals, versionOf } from './crypto.ts'
import { FileVault, MemoryVault } from './vault.ts'
import { SECRET_V1, SECRET_V2, SECRET_V3, keyringFor, tempFileVaultDir } from './testsupport.ts'

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
const ADDRESS = '0x1234567890123456789012345678901234567890'

test('a v2 blob round-trips and is stamped with its version', () => {
  const keyring = keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2)
  const blob = keyring.encrypt(ADDRESS, KEY)
  assert.equal(versionOf(blob), 2)
  assert.equal(keyring.decrypt(ADDRESS, blob), KEY)
})

test('the ciphertext never contains the plaintext', () => {
  const keyring = keyringFor({ 2: SECRET_V2 }, 2)
  const blob = keyring.encrypt(ADDRESS, KEY)
  assert.equal(blob.includes(KEY), false)
  assert.equal(Buffer.from(blob.split(':')[1]!, 'base64').includes(Buffer.from(KEY)), false)
})

test('v1 is still readable — the format the service custody supersedes writes', () => {
  const keyring = keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2)
  const legacy = keyring.encryptAs(1, ADDRESS, KEY)
  assert.equal(versionOf(legacy), 1)
  assert.equal(keyring.decrypt(ADDRESS, legacy), KEY)
})

test('v1 and v2 of one key under one secret set are different ciphertexts', () => {
  // Not a tautology: it is what proves the version selects the derivation, so a v2 blob is not
  // decryptable by anything that only knows how to do v1.
  const keyring = keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2)
  assert.notEqual(keyring.encryptAs(1, ADDRESS, KEY), keyring.encryptAs(2, ADDRESS, KEY))
})

test('two addresses derive different data keys, so one leak does not unlock another', () => {
  const keyring = keyringFor({ 2: SECRET_V2 }, 2)
  const a = keyring.encrypt(ADDRESS, KEY)
  assert.throws(() => keyring.decrypt('0x0000000000000000000000000000000000000001', a))
})

test('the address is authenticated data — moving a blob between slots fails the tag', () => {
  const keyring = keyringFor({ 2: SECRET_V2 }, 2)
  const blob = keyring.encrypt(ADDRESS, KEY)
  assert.throws(() => keyring.decrypt('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', blob))
})

test('a v2 envelope carries a random salt, so two encryptions of one key differ', () => {
  const keyring = keyringFor({ 2: SECRET_V2 }, 2)
  assert.notEqual(keyring.encrypt(ADDRESS, KEY), keyring.encrypt(ADDRESS, KEY))
})

test('a blob at a version this process holds no secret for names the variable, not a corrupt key', () => {
  // The failure mode this replaces is a GCM authentication error, which reads like disk corruption
  // and sends an operator hunting for a hardware fault instead of an unset variable.
  const keyring = keyringFor({ 2: SECRET_V2 }, 2)
  assert.throws(
    () => keyring.decrypt(ADDRESS, 'v99:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    (err: unknown) => err instanceof EnvelopeError && /CUSTODY_MASTER_SECRET_V99/.test((err as Error).message),
  )
})

test('a version above the current one needs no code change — rotation is a deploy, not a release', () => {
  // The property, stated as a test: v7 has no entry anywhere in `crypto.ts`, and it works. If this
  // ever needed a source edit, an operator mid-incident could not rotate without a release.
  const keyring = keyringFor({ 7: SECRET_V3 }, 7)
  const blob = keyring.encrypt(ADDRESS, KEY)
  assert.equal(versionOf(blob), 7)
  assert.equal(keyring.decrypt(ADDRESS, blob), KEY)
  assert.equal(FIRST_CURRENT_VERSION, 2)
})

test('a keyring refuses a write version it holds no secret for', () => {
  assert.throws(() => keyringFor({ 1: SECRET_V1 }, 2), EnvelopeError)
})

test('decrypting a version whose secret has been removed names the variable to set', () => {
  const wrote = keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2)
  const blob = wrote.encryptAs(1, ADDRESS, KEY)
  const afterRetirement = keyringFor({ 2: SECRET_V2 }, 2)
  assert.throws(
    () => afterRetirement.decrypt(ADDRESS, blob),
    (err: unknown) => err instanceof EnvelopeError && /CUSTODY_MASTER_SECRET_V1/.test((err as Error).message),
  )
})

/**
 * THE ROTATION, END TO END. This is SD-06's verification line and SDR-03's exit condition.
 *
 * It is written against `Keyring` and a vault rather than against the job, because the property is
 * about the envelope: the blob written under the old secret keeps decrypting while the new secret is
 * the write version, and stops needing the old secret once it has been rewritten.
 * `reencrypt.test.ts` drives the same rotation through the actual job and the database.
 */
test('a full master-secret rotation: v1 blob → v2 write version → re-encrypted → v1 secret retired', async () => {
  const vault = new MemoryVault()

  // 1. The world before. One secret, one version, and a blob written under it.
  const before = keyringFor({ 1: SECRET_V1 }, 1)
  await vault.write(ADDRESS, before.encrypt(ADDRESS, KEY))
  assert.equal(versionOf(await vault.read(ADDRESS)), 1)

  // 2. The new secret is added and becomes the write version. The old blob is untouched and still
  //    readable — this is the step that is impossible today, where one variable holds one secret.
  const during = keyringFor({ 1: SECRET_V1, 2: SECRET_V2 }, 2)
  assert.equal(during.decrypt(ADDRESS, await vault.read(ADDRESS)), KEY)
  assert.deepEqual(during.readableVersions, [1, 2])

  // 3. The re-encryption pass rewrites it under the new secret.
  const plaintext = during.decrypt(ADDRESS, await vault.read(ADDRESS))
  await vault.write(ADDRESS, during.encryptAs(2, ADDRESS, plaintext))
  assert.equal(versionOf(await vault.read(ADDRESS)), 2)

  // 4. The old secret is REMOVED — the moment the compromise becomes recoverable — and the key is
  //    still readable. Before this change, step 4 bricked every key in custody.
  const after = keyringFor({ 2: SECRET_V2 }, 2)
  assert.equal(after.decrypt(ADDRESS, await vault.read(ADDRESS)), KEY)
  assert.deepEqual(after.readableVersions, [2])

  // 5. And it rotates again, because the mechanism is not single-use.
  const again = keyringFor({ 2: SECRET_V2, 3: SECRET_V3 }, 3)
  await vault.write(ADDRESS, again.encryptAs(3, ADDRESS, again.decrypt(ADDRESS, await vault.read(ADDRESS))))
  assert.equal(keyringFor({ 3: SECRET_V3 }, 3).decrypt(ADDRESS, await vault.read(ADDRESS)), KEY)
})

test('the file vault writes 0600 files in 0700 directories', async () => {
  const { dir, cleanup } = await tempFileVaultDir()
  try {
    const vault = new FileVault(dir)
    const keyring = keyringFor({ 2: SECRET_V2 }, 2)
    await vault.write(ADDRESS, keyring.encrypt(ADDRESS, KEY))

    const dirStat = await stat(resolve(dir, ADDRESS))
    const fileStat = await stat(resolve(dir, ADDRESS, 'key.enc'))
    assert.equal(dirStat.mode & 0o777, 0o700)
    assert.equal(fileStat.mode & 0o777, 0o600)
    assert.equal(keyring.decrypt(ADDRESS, await vault.read(ADDRESS)), KEY)

    // Rewriting keeps the mode — the re-encryption pass rewrites live blobs, and a rotation that
    // widened permissions on the way through would be a silent downgrade of every key it touched.
    await chmod(resolve(dir, ADDRESS), 0o755)
    await vault.write(ADDRESS, keyring.encrypt(ADDRESS, KEY))
    assert.equal((await stat(resolve(dir, ADDRESS))).mode & 0o777, 0o700)
    assert.equal((await stat(resolve(dir, ADDRESS, 'key.enc'))).mode & 0o777, 0o600)
  } finally {
    await cleanup()
  }
})

test('a slot name that could escape the data directory is refused', async () => {
  const vault = new MemoryVault()
  await assert.rejects(() => vault.write('../../etc/passwd', 'x'), /unsafe custody slot/)
})

test('secretEquals is length-safe and correct', () => {
  assert.equal(secretEquals('abc', 'abc'), true)
  assert.equal(secretEquals('abc', 'abd'), false)
  assert.equal(secretEquals('abc', 'abcd'), false)
})

test('a Keyring can be constructed for every declared version', () => {
  for (let v = 1; v <= FIRST_CURRENT_VERSION; v += 1) {
    const keyring = new Keyring(new Map([[v, SECRET_V2]]), v)
    assert.equal(keyring.decrypt(ADDRESS, keyring.encrypt(ADDRESS, KEY)), KEY)
  }
})
