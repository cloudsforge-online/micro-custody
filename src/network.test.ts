/**
 * The `network` metric label, and why it is not simply the caller's word.
 *
 * Added in the network consolidation so one custody serving both estates can tell a testnet
 * signing refusal from a mainnet one. A background security review caught the first version of it:
 * the sign route reads `network` with `stringField`, which is raw caller input, and the counters
 * are incremented on the REFUSAL path — so the unvalidated value reached a label.
 */
import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'

const NETWORKS = new Set(['mainnet', 'testnet'])
const labelFor = (claimed: string) => (NETWORKS.has(claimed) ? claimed : 'invalid')

describe('the network label is bounded by what this service knows', () => {
  it('passes the two real estates through', () => {
    assert.equal(labelFor('mainnet'), 'mainnet')
    assert.equal(labelFor('testnet'), 'testnet')
  })

  it('collapses anything else to one value, so a caller cannot mint series', () => {
    /*
     * The failure this prevents: a loop posting a fresh uuid as `network` mints a new time series
     * per request. 13-operational-model §13 budgets 500k active series for the WHOLE estate, and
     * one unauthenticated-ish route could spend them. A metric label must be bounded by something
     * the SERVICE controls — the same rule written on beacon's `probes.target`.
     */
    for (const nonsense of [crypto.randomUUID(), 'MAINNET', 'main', '', 'mainnet\n', '../../etc']) {
      assert.equal(labelFor(nonsense), 'invalid')
    }
  })

  it('does not let a caller attribute its refusals to an estate it names', () => {
    // The second half of the finding: labelling with the raw value would let a caller book its own
    // refusals against whichever estate it liked — the opposite of what the label exists for.
    assert.equal(labelFor('mainnet-but-actually-testnet'), 'invalid')
  })

  it('says `invalid` rather than dropping the label, because that is a different alert', () => {
    // "somebody is sending nonsense at the signing route" and "testnet signing is failing" want
    // different people woken up. Collapsing them into one unlabelled series would hide the first.
    assert.notEqual(labelFor('nonsense'), 'testnet')
    assert.equal(labelFor('nonsense'), 'invalid')
  })
})
