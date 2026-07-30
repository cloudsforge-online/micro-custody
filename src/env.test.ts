/**
 * Configuration, and the boot-time refusals that are carried forward.
 *
 * SD-06's verification line includes "boot-time refusal on placeholder secrets, which already exists
 * and is asserted in CI". It exists here too, and it is asserted here — plus the new refusal that
 * SDR-03 needs: a write version with no master secret behind it, which would silently encrypt every
 * new key under something this process cannot read back.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

const SECRET = 'a-real-looking-secret-of-sufficient-length-0123'

/**
 * A valid environment, applied to the process BEFORE `./env.ts` is imported.
 *
 * The import is itself a test: `env.ts` validates eagerly and calls `process.exit(1)` on a bad
 * configuration, so if these values were insufficient this file would not run at all. Every failure
 * case below goes through `loadEnv`, which is pure over its source and therefore testable without a
 * child process.
 */
const BASE: Record<string, string> = {
  CUSTODY_DATABASE_URL: 'postgres://localhost/custody_test',
  IDENTITY_JWKS_URL: 'http://identity:4000/.well-known/jwks.json',
  IDENTITY_ISSUER: 'https://id.cloudsforge.test',
  OUTBOX_SIGNING_SECRET: SECRET,
  POLICY_BASE_URL: 'http://policy:4009',
  CUSTODY_MASTER_SECRET_V2: SECRET,
}
for (const [key, value] of Object.entries(BASE)) process.env[key] = value

const { EnvError, SERVICE, collectMasterSecrets, env: liveEnv, loadEnv } = await import('./env.ts')

test('a valid environment loads, and importing the module did not exit', () => {
  assert.equal(SERVICE, 'custody')
  assert.equal(liveEnv.keyVersion, 2)
  const env = loadEnv(BASE, 'host-1')
  assert.equal(env.keyVersion, 2)
  assert.equal(env.masterSecrets.get(2), SECRET)
  assert.equal(env.exportCoolingOffHours, 24)
  assert.equal(env.instanceId, 'host-1')
})

test('a missing variable NAMES ITSELF rather than propagating undefined into a driver error', () => {
  for (const name of ['CUSTODY_DATABASE_URL', 'IDENTITY_JWKS_URL', 'IDENTITY_ISSUER', 'POLICY_BASE_URL']) {
    const source = { ...BASE }
    delete source[name]
    assert.throws(
      () => loadEnv(source),
      (err: unknown) => err instanceof EnvError && (err as Error).message.startsWith(name),
      name,
    )
  }
})

test('a known PLACEHOLDER secret is refused outright — carried forward from custody today', () => {
  // A default secret in source is not convenient, it is catastrophic: everything derived from it is
  // forgeable by anyone who can read the repository, and a placeholder that boots is a placeholder
  // that reaches production.
  for (const placeholder of ['changeme', 'CHANGEME', 'dev-secret', 'placeholder']) {
    assert.throws(
      () => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: placeholder }),
      (err: unknown) => err instanceof EnvError && /placeholder/.test((err as Error).message),
      placeholder,
    )
    assert.throws(
      () => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: placeholder }),
      EnvError,
      `master secret ${placeholder}`,
    )
  }
})

test('a short secret is refused — length is the only entropy proxy available here', () => {
  assert.throws(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: 'short' }), EnvError)
  assert.throws(() => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: 'still-too-short' }), EnvError)
})

test('with NO master secret at all, custody refuses to boot', () => {
  const source = { ...BASE }
  delete source.CUSTODY_MASTER_SECRET_V2
  assert.throws(
    () => loadEnv(source),
    (err: unknown) => err instanceof EnvError && /CUSTODY_MASTER_SECRET_V<n>/.test((err as Error).message),
  )
})

test('a write version with no secret behind it is refused, by name', () => {
  // Booting past this would encrypt every new address under a key nothing holds — the failure would
  // surface later, as a customer's key that cannot be decrypted, with no way back.
  assert.throws(
    () => loadEnv({ ...BASE, CUSTODY_KEY_VERSION: '3' }),
    (err: unknown) => err instanceof EnvError && /CUSTODY_MASTER_SECRET_V3 is not set/.test((err as Error).message),
  )
})

test('the master secrets are collected BY PATTERN, so a rotation is a deploy and not a release', () => {
  const secrets = collectMasterSecrets({
    CUSTODY_MASTER_SECRET_V1: `${SECRET}-one`,
    CUSTODY_MASTER_SECRET_V2: `${SECRET}-two`,
    CUSTODY_MASTER_SECRET_V17: `${SECRET}-seventeen`,
    // Not a master secret. The pattern is anchored, so a near-miss is ignored rather than
    // silently becoming version NaN.
    CUSTODY_MASTER_SECRET: SECRET,
    CUSTODY_MASTER_SECRET_VX: SECRET,
  })
  assert.deepEqual([...secrets.keys()].sort((a, b) => a - b), [1, 2, 17])
})

test('the write version defaults to the highest secret present', () => {
  const env = loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V1: `${SECRET}-one`, CUSTODY_MASTER_SECRET_V4: `${SECRET}-four` })
  assert.equal(env.keyVersion, 4)
  assert.deepEqual([...env.masterSecrets.keys()].sort((a, b) => a - b), [1, 2, 4])
})

test('the cooling-off can be shortened for a rehearsal but never below an hour', () => {
  // A deployment that set it to a minute would have removed the only control in SD-07 that works
  // while the user is actively being deceived.
  assert.equal(loadEnv({ ...BASE, CUSTODY_EXPORT_COOLING_OFF_HOURS: '1' }).exportCoolingOffHours, 1)
  assert.throws(() => loadEnv({ ...BASE, CUSTODY_EXPORT_COOLING_OFF_HOURS: '0' }), EnvError)
})

test('NO variable names an RPC endpoint, a price feed or a product service', () => {
  // SD-13 and 03 §3: custody makes no outbound call except to policy, and its network reachability
  // is the whole security model. The declared surface is what a deploy manifest is derived from, so
  // a third destination would have to appear here first.
  const env = loadEnv(BASE)
  const outbound = Object.entries(env).filter(([, value]) => typeof value === 'string' && /^https?:\/\//.test(value))
  assert.deepEqual(
    outbound.map(([name]) => name).sort(),
    // `identityIssuer` is a token claim to compare against, not a destination. `identityJwksUrl` is
    // a read of a public document. `policyBaseUrl` is the one and only service custody calls.
    ['identityIssuer', 'identityJwksUrl', 'policyBaseUrl'],
  )
})

test('LOG_LEVEL is validated rather than silently falling back', () => {
  assert.throws(() => loadEnv({ ...BASE, LOG_LEVEL: 'verbose' }), EnvError)
  assert.equal(loadEnv({ ...BASE, LOG_LEVEL: 'debug' }).logLevel, 'debug')
})
