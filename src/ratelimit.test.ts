/**
 * The rate limiter's arithmetic. Its STORAGE is the audit table, and that half is exercised against
 * a real database in `server.test.ts`.
 */

import assert from 'node:assert/strict'
import test from 'node:test'
import { ADDRESS_WINDOW_MS, SIGN_WINDOW_MS, decide, windowStart } from './ratelimit.ts'

const RULE = { limit: 3, windowMs: 60_000 }
const NOW = Date.UTC(2026, 0, 1, 12, 0, 30)

test('under the limit is allowed, at the limit is not', () => {
  assert.equal(decide(RULE, 0, NOW).allowed, true)
  assert.equal(decide(RULE, 2, NOW).allowed, true)
  assert.equal(decide(RULE, 3, NOW).allowed, false)
  assert.equal(decide(RULE, 99, NOW).allowed, false)
})

test('Retry-After names the moment the window rolls, so a caller can back off exactly', () => {
  assert.equal(decide(RULE, 3, NOW).retryAfterSeconds, 30)
  assert.equal(decide(RULE, 3, Date.UTC(2026, 0, 1, 12, 0, 0)).retryAfterSeconds, 60)
  // Never zero: a Retry-After of 0 is an invitation to spin.
  assert.equal(decide(RULE, 3, Date.UTC(2026, 0, 1, 12, 0, 59, 999)).retryAfterSeconds, 1)
})

test('the window start is what the count query covers', () => {
  assert.equal(windowStart(RULE, NOW).toISOString(), new Date(Date.UTC(2026, 0, 1, 12, 0, 0)).toISOString())
})

test('the fixed window admits up to 2× across a boundary, and that is stated rather than implied', () => {
  // Documented in `ratelimit.ts`. The alternative needs per-request state and buys nothing against
  // the threat being bounded, which is a sustained loop rather than a precisely-timed burst.
  const endOfWindow = Date.UTC(2026, 0, 1, 12, 0, 59)
  const startOfNext = Date.UTC(2026, 0, 1, 12, 1, 0)
  assert.equal(decide(RULE, 2, endOfWindow).allowed, true)
  // The count resets because the query's window moved, not because anything was cleared.
  assert.equal(windowStart(RULE, startOfNext).getTime() > windowStart(RULE, endOfWindow).getTime(), true)
})

test('the two surfaces have different windows', () => {
  assert.equal(SIGN_WINDOW_MS, 60_000)
  assert.equal(ADDRESS_WINDOW_MS, 3_600_000)
})
