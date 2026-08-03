/**
 * The producer half of the bus contract, read out of the source rather than out of a list.
 *
 * `topics.ts` says what custody emits. This file checks that claim against the only thing that can
 * contradict it — the emit sites themselves — in both directions:
 *
 *   1. every `topic: '...'` literal in `src/` is a topic `EMITTED_TOPICS` declares, and
 *   2. every topic `EMITTED_TOPICS` declares has an emit site.
 *
 * Direction 2 is the one that matters here, and it is the direction that was missing for the whole
 * life of this service: `custody.key.exported` was registered, classified by three consumers and
 * emitted by nothing, because the redemption emitted `custody.export.completed` instead. A list
 * that named the topic would have been a list that lied about the code, so the code is what is
 * read.
 *
 * It also checks the ordering KEY at each emit site, which is the part a rename cannot fix by
 * itself: `TopicSpec.keyedBy` is contract, `activity/src/classify.ts` reads the envelope key AS the
 * user id for both custody topics it classifies, and this service keyed both by the ADDRESS.
 *
 * No database. Pure text over `src/`, so it runs even when the database-backed suite skips.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { EMITTED_TOPICS, TOPIC_RECORDS, unregisteredEmittedTopics } from './topics.ts'

const SRC = dirname(fileURLToPath(import.meta.url))

/**
 * Comments out, code in.
 *
 * Not a nicety. identity's `unreferencedEmitters` passed while the function it was looking for was
 * dead, because the paragraph naming that function counted as a call site — and this file's own
 * header names `custody.key.exported` and `custody.export.completed` in prose. A guard that its own
 * documentation can satisfy is worse than no guard, because it reads as a proof.
 */
function codeOf(text: string): string {
  return text
    .split('\n')
    .map((line) => {
      const trimmed = line.trimStart()
      if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) return ''
      return line.replace(/\/\/.*$/, '')
    })
    .join('\n')
}

interface EmitSite {
  readonly file: string
  readonly line: number
  readonly topic: string
  /** The expression after `key:` on the following lines, or `''` when there is none. */
  readonly key: string
}

/**
 * Every emit site in `src/`, excluding the tests.
 *
 * Tests emit deliberately fake events and `testsupport.ts` builds fixtures, so including them would
 * let a fixture satisfy direction 2 for a topic production never sends.
 */
function emitSites(): readonly EmitSite[] {
  const out: EmitSite[] = []
  for (const name of readdirSync(SRC)) {
    if (!name.endsWith('.ts')) continue
    if (name.endsWith('.test.ts') || name === 'testsupport.ts') continue
    const text = codeOf(readFileSync(join(SRC, name), 'utf8'))
    for (const match of text.matchAll(/\btopic:\s*'([a-z0-9_.]+)'/g)) {
      const after = text.slice(match.index + match[0].length, match.index + match[0].length + 400)
      const key = /^\s*,\s*key:\s*([^,\n]+)/.exec(after)?.[1]?.trim() ?? ''
      out.push({
        file: name,
        line: text.slice(0, match.index).split('\n').length,
        topic: match[1] ?? '',
        key,
      })
    }
  }
  return out
}

test('every emit site names a topic this service declares', () => {
  const declared = new Set<string>(EMITTED_TOPICS)
  for (const site of emitSites()) {
    assert.ok(
      declared.has(site.topic),
      `${site.file}:${site.line} emits '${site.topic}', which EMITTED_TOPICS does not declare — add it with its registration status, or fix the name`,
    )
  }
})

test('every declared topic has an emit site, so none of them is a promise', () => {
  const emitted = new Set(emitSites().map((site) => site.topic))
  // The direction that was missing. `custody.key.exported` is registered, notify holds a CRITICAL
  // rule on it, activity and analytics classify it — and no line of this service ever sent it.
  assert.deepEqual(
    EMITTED_TOPICS.filter((topic) => !emitted.has(topic)),
    [],
    'declared and never emitted — every consumer of it is waiting for a fact nothing sends',
  )
  // And the scan found something, rather than passing because it read no files.
  assert.ok(emitted.size >= 5, `the scan found ${emitted.size} emitted topics; it is broken, not the service`)
})

test('the export completion is emitted under the name the estate registered', () => {
  const sites = emitSites().filter((site) => site.topic === 'custody.key.exported')
  assert.equal(sites.length, 1, 'exactly one emit for the completion of an export ceremony')
  assert.equal(sites[0]?.file, 'exports.ts')
  // The name it was emitted under before, which is in no registry and has no subscriber anywhere.
  // Spelled by concatenation so this assertion cannot be satisfied by this line.
  const abandoned = ['custody', 'export', 'completed'].join('.')
  assert.equal(
    emitSites().some((site) => site.topic === abandoned),
    false,
    `${abandoned} is in no registry and nothing in the estate subscribes to it`,
  )
})

test('a topic the registry keys by user_id is keyed by the user at its emit site', () => {
  // The half a rename does not fix. activity/src/classify.ts uses the envelope KEY as the user id
  // for both custody topics it classifies, so an address here files a security event against a user
  // that does not exist — and notify's userIdOf falls back to the key for exactly these topics.
  for (const site of emitSites()) {
    const record = TOPIC_RECORDS[site.topic as keyof typeof TOPIC_RECORDS]
    if (!record || record.keyedBy !== 'user_id') continue
    assert.notEqual(site.key, '', `${site.file}:${site.line} (${site.topic}) has no key expression to read`)
    assert.match(
      site.key,
      /user/i,
      `${site.file}:${site.line} emits ${site.topic} keyed by \`${site.key}\`, and the registry says user_id`,
    )
    assert.doesNotMatch(
      site.key,
      /address/i,
      `${site.file}:${site.line} emits ${site.topic} keyed by an address; the registry says user_id`,
    )
  }
})

test('every declared topic records its registration status with evidence', () => {
  assert.deepEqual(Object.keys(TOPIC_RECORDS).sort(), [...EMITTED_TOPICS].sort())
  for (const topic of EMITTED_TOPICS) {
    const record = TOPIC_RECORDS[topic]
    assert.ok(record.keyedBy.trim().length > 0, `${topic}: name the ordering partition`)
    assert.ok(
      record.evidence.length > 80,
      `${topic}: cite the registry line, or state the spec that would register it — under eighty characters is a shrug`,
    )
    if (!record.registered) {
      // An unregistered topic must carry the proposal, so adopting it into contracts is a copy
      // rather than a fresh design. This is what settlement's and trade's AWAITING_REGISTRATION do;
      // it is recorded as prose here because this repository does not depend on the contracts
      // package — see the header of topics.ts.
      assert.match(record.evidence, /producer custody/, `${topic}: no spec anybody could paste`)
    }
  }
  // The two the registry names today. If contracts registers more, this fails and the records are
  // updated — which is the point of recording it rather than assuming it.
  assert.deepEqual(
    EMITTED_TOPICS.filter((topic) => TOPIC_RECORDS[topic].registered),
    ['custody.export.requested', 'custody.key.exported'],
  )
  assert.equal(unregisteredEmittedTopics().length, 4)
})
