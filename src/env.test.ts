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

/**
 * A hand-written string that USED TO BE THIS SUITE'S IDEA OF A VALID SECRET.
 *
 * It was named `SECRET` and it was `OUTBOX_SIGNING_SECRET` in `BASE`, so every test in this file
 * ran against it and the suite as a whole asserted that it was acceptable. It is not, and it never
 * was: it is hyphenated (so it is in neither the base64 nor the hex alphabet, which is the check
 * that catches every placeholder this estate has actually written), and once punctuation and case
 * are stripped it literally contains the marker `sufficientlength`.
 *
 * It is kept, renamed, for the one job it can honestly do — being a value the guard must REFUSE.
 */
const REFUSED_SHAPE = 'a-real-looking-secret-of-sufficient-length-0123'

/**
 * A secret fixture, GENERATED rather than written down.
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
  // GENERATED, not written. This was `REFUSED_SHAPE` above, which means every case in this file
  // was running against an outbox secret the estate's own guard now refuses.
  OUTBOX_SIGNING_SECRET: master(),
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

test('OUTBOX_SIGNING_SECRET is held to EXACTLY the rule the master secrets are — the exemption is gone', () => {
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  // THIS TEST IS THE INVERSE OF THE ONE IT REPLACES, AND THE OLD ONE WAS DEFENDING THE DEFECT.
  //
  // It read `OUTBOX_SIGNING_SECRET is DELIBERATELY not held to the master-secret rule` and it
  // asserted `doesNotThrow` on `REFUSED_SHAPE` — a hyphenated, hand-written string containing the
  // marker `sufficientlength`. The argument for the exemption was real at the time: one shared HMAC
  // key across fifteen services, and holding custody alone to the strict rule would have stopped
  // custody booting on a value every peer still accepted. But an assertion that a bad value LOADS
  // is a test that goes red the moment the value stops being bad, so the fix could not land without
  // this file objecting to it.
  //
  // Both halves of the argument have expired: the estate rotated the outbox key onto generated
  // material (measured on both networks — 64 characters, 32 bytes, one alphabet), and the guard is
  // landing across every service at once rather than in custody alone.
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  assert.throws(
    () => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: REFUSED_SHAPE }),
    (err: unknown) =>
      err instanceof EnvError &&
      err.message.includes('OUTBOX_SIGNING_SECRET') &&
      !err.message.includes(REFUSED_SHAPE),
  )
  // And the estate placeholder itself — 40 characters, which cleared the old 32-character floor and
  // was on nobody's deny-list, which is the whole of micro-org #142.
  assert.throws(
    () => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: 'estate-only-outbox-secret-00000000000000' }),
    EnvError,
  )
  assert.doesNotThrow(() => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: master() }))
})

test('a short secret is refused, and the unit is BYTES rather than keystrokes', () => {
  // This used to be titled `length is the only entropy proxy available here`, which stated the old
  // rule as a fact. Length was never the only proxy — it was the only one this file implemented,
  // and counting keystrokes is precisely what let a 40-character placeholder through.
  //
  // `hunter2` is spelled entirely in the base64 alphabet, so it is not the alphabet that catches
  // it: it decodes to five bytes. The assertion is on the PROPERTY (bytes, the floor, the variable
  // named, the value absent) rather than on any particular wording, so a future improvement to the
  // message cannot fail CI for being an improvement.
  for (const name of ['CUSTODY_MASTER_SECRET_V2', 'OUTBOX_SIGNING_SECRET']) {
    assert.throws(
      () => loadEnv({ ...BASE, [name]: 'hunter2' }),
      (err: unknown) =>
        err instanceof EnvError &&
        /5 bytes of key material/.test(err.message) &&
        /at least 32/.test(err.message) &&
        err.message.includes(name) &&
        !err.message.includes('hunter2'),
      name,
    )
  }
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
    CUSTODY_MASTER_SECRET: REFUSED_SHAPE,
    CUSTODY_MASTER_SECRET_VX: REFUSED_SHAPE,
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
