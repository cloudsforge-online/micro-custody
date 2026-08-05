/**
 * Configuration, and the boot-time refusals that are carried forward.
 *
 * SD-06's verification line includes "boot-time refusal on placeholder secrets, which already exists
 * and is asserted in CI". It exists here too, and it is asserted here — plus the new refusal that
 * SDR-03 needs: a write version with no master secret behind it, which would silently encrypt every
 * new key under something this process cannot read back.
 */

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import test from 'node:test'

const SECRET = 'a-real-looking-secret-of-sufficient-length-0123'

/**
 * A master secret fixture, GENERATED rather than written down.
 *
 * A literal here would be a string somebody could copy into a deployment, and the whole subject of
 * this file is what happens when they do. `openssl rand -base64 48` is what the README tells an
 * operator to run; this is the same 48 bytes, and every call returns a different one.
 */
function master(): string {
  return randomBytes(48).toString('base64')
}

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
  CUSTODY_MASTER_SECRET_V2: master(),
}
for (const [key, value] of Object.entries(BASE)) process.env[key] = value

const { EnvError, SERVICE, collectMasterSecrets, env: liveEnv, loadEnv } = await import('./env.ts')

test('a valid environment loads, and importing the module did not exit', () => {
  assert.equal(SERVICE, 'custody')
  assert.equal(liveEnv.keyVersion, 2)
  const env = loadEnv(BASE, 'host-1')
  assert.equal(env.keyVersion, 2)
  assert.equal(env.masterSecrets.get(2), BASE['CUSTODY_MASTER_SECRET_V2'])
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

/* ------------------------------------------------ the master-secret guard, and the defect it fixes */

/**
 * THE DEFECT, REPRODUCED IN SHAPE AND NOT IN VALUE.
 *
 * `deploy/compose/docker-compose.estate.yml` shipped a hardcoded 40-character master secret in a
 * PUBLIC repository, under a comment that said "Minimum 32 characters" — which it was. It cleared
 * every check this file had: it was not in `PLACEHOLDERS`, and it was longer than 32. A comment is
 * not a control, and neither is a deny-list of eight exact strings.
 *
 * The literal itself is deliberately NOT written here. It is still the read key for v1 blobs until
 * the estate's rotation drains, and re-publishing it in a second public repository while it is
 * load-bearing would be repeating the mistake this test exists to close. Every value below is the
 * same SHAPE — an operator-written, hyphenated, word-bearing string, padded past 32 characters.
 */
const COMPOSE_SHAPED = [
  'estate-only-a-master-secret-that-is-long-enough',
  'ci-only-not-a-real-secret-at-least-32-chars-1234',
  'dev-only-master-secret-for-the-local-stack-00000',
  'replace-me-with-a-real-secret-before-production',
  'not-a-real-secret-but-it-is-forty-characters-ok',
]

test('a hand-written secret past the length floor is REFUSED — the defect that made this guard', () => {
  for (const value of COMPOSE_SHAPED) {
    assert.ok(value.length >= 32, `${value.length} — the old floor would have passed this`)
    assert.throws(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: value }), EnvError, value)
  }
})

test('what an operator is TOLD to generate is accepted, in both encodings the README names', () => {
  // If this ever goes red the guard has become unusable, which is the other way to fail: a control
  // that refuses correct input is a control an operator disables.
  for (let i = 0; i < 200; i += 1) {
    assert.doesNotThrow(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: randomBytes(48).toString('base64') }))
    assert.doesNotThrow(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: randomBytes(32).toString('base64') }))
    assert.doesNotThrow(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: randomBytes(32).toString('hex') }))
  }
})

test('a master secret must carry 32 BYTES, not 32 characters', () => {
  // 31 bytes is 44 base64 characters with padding — longer than the old floor and still short of a
  // key. The unit that matters is entropy, and the unit the old check used was keystrokes.
  assert.throws(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: randomBytes(31).toString('base64') }), EnvError)
  assert.throws(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: randomBytes(31).toString('hex') }), EnvError)
  assert.doesNotThrow(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: randomBytes(32).toString('base64') }))
})

test('a long, well-formed, DEGENERATE secret is refused on entropy', () => {
  // Every one of these is in an accepted alphabet and past every length floor. Only a measurement
  // of the value itself rejects them.
  for (const value of ['A'.repeat(64), '0'.repeat(64), 'deadbeef'.repeat(8), 'abababababababab'.repeat(4)]) {
    assert.throws(() => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: value }), EnvError, value)
  }
})

test('THE GUARD HAS NO OFF SWITCH — no environment, no variable, no flag disables it', () => {
  // The failure this replaces was a comment saying "change this in production". Anything that can
  // be turned off is a comment with a longer name, so the escape hatches that would be reached for
  // are asserted absent here rather than merely not written.
  const placeholder = COMPOSE_SHAPED[0]!
  for (const escape of [
    { NODE_ENV: 'development' },
    { NODE_ENV: 'test' },
    { CUSTODY_ALLOW_WEAK_SECRETS: 'true' },
    { CUSTODY_SKIP_SECRET_CHECKS: '1' },
    { CI: 'true' },
  ]) {
    assert.throws(
      () => loadEnv({ ...BASE, ...escape, CUSTODY_MASTER_SECRET_V2: placeholder }),
      EnvError,
      JSON.stringify(escape),
    )
  }
})

test('the refusal names the variable and never echoes the value', () => {
  // A configuration error is logged, and a log line carrying the secret would move it from one
  // public place to another. `fatalConfig` writes `err.message` verbatim, so this is the check.
  const value = COMPOSE_SHAPED[0]!
  assert.throws(
    () => loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V2: value }),
    (err: unknown) =>
      err instanceof EnvError &&
      (err as Error).message.includes('CUSTODY_MASTER_SECRET_V2') &&
      !(err as Error).message.includes(value),
  )
})

test('OUTBOX_SIGNING_SECRET is DELIBERATELY not held to the master-secret rule', () => {
  // Scope, asserted so that widening it is a decision somebody makes on purpose. The outbox secret
  // is one shared HMAC key across fifteen services; holding custody alone to a stricter rule would
  // stop custody booting on a value every one of its peers still accepts. It is a live gap and it
  // is recorded as one — see the file header of env.ts.
  assert.doesNotThrow(() => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: SECRET }))
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
    CUSTODY_MASTER_SECRET_V1: master(),
    CUSTODY_MASTER_SECRET_V2: master(),
    CUSTODY_MASTER_SECRET_V17: master(),
    // Not a master secret. The pattern is anchored, so a near-miss is ignored rather than
    // silently becoming version NaN — and note that these two values would FAIL the master-secret
    // guard, so if the pattern ever loosened this case would go red rather than quietly widen.
    CUSTODY_MASTER_SECRET: SECRET,
    CUSTODY_MASTER_SECRET_VX: SECRET,
  })
  assert.deepEqual([...secrets.keys()].sort((a, b) => a - b), [1, 2, 17])
})

test('the write version defaults to the highest secret present', () => {
  const env = loadEnv({ ...BASE, CUSTODY_MASTER_SECRET_V1: master(), CUSTODY_MASTER_SECRET_V4: master() })
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
