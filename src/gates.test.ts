/**
 * The gates, and the ORDER of them.
 *
 * SD-09 fixes the order — purpose, binding, chain id, treasury pin, and only then decrypt — and the
 * point of every gate that can fail closed running before the decrypt is that a refused request
 * never causes a private key to exist in the process at all. These tests are the per-gate half;
 * `server.test.ts` proves the order end to end by asserting that a refusal never reads a blob.
 */

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  bindingMatches,
  bindingMismatches,
  bitcoinShapeForPurpose,
  evmShapeForPurpose,
  purposeGate,
  resolveChainId,
  signScopeFor,
  solanaShapeForPurpose,
  type RowIdentity,
} from './gates.ts'

const ROW: RowIdentity = {
  address: '0x1111111111111111111111111111111111111111',
  chain: 'ethereum',
  network: 'testnet',
  userId: 'user-a',
  orderId: 'order-1',
  purpose: 'deposit',
  family: 'evm',
  status: 'active',
}

/* ------------------------------------------------------------------ gate 1 */

test('gate 1: the three signable purposes and the one that is not', () => {
  for (const purpose of ['deposit', 'treasury', 'deployer']) {
    assert.equal(purposeGate({ purpose, family: 'evm', status: 'active' }).ok, true, purpose)
  }
  // `user` deliberately has no signing shape: a user wallet exists so the customer can hold and
  // export it, and giving it one would make custody a signing oracle for keys whose owner never
  // asked it to sign anything.
  const user = purposeGate({ purpose: 'user', family: 'evm', status: 'active' })
  assert.equal(user.ok, false)
  assert.match(user.ok ? '' : user.error, /purpose this service does not sign for/)
})

test('gate 1: a `pool` address is NOT signed for — a payout has no field the vault chooses', () => {
  // Migration 8 added the purpose so micro-pool's coinbase payout address can be a custody key. It
  // is a RECEIVING address: the coinbase output is created by a block the pool mines, not by a
  // transaction this service signs, so minting the key is the entire capability the pool needs.
  //
  // A spend from one would be a payout to miners — N destinations the caller names, for amounts
  // computed from a share ledger custody cannot see — which leaves this service no field to pin, the
  // same answer `user` gets. Asserted on every family, because the refusal must not depend on which
  // signer happens to exist.
  for (const family of ['bitcoin', 'evm', 'ember', 'solana', 'xrp']) {
    const gate = purposeGate({ purpose: 'pool', family, status: 'active' })
    assert.equal(gate.ok, false, family)
    assert.match(gate.ok ? '' : gate.error, /purpose this service does not sign for/, family)
  }
})

test('gate 1: a deposit address in a family with no sweep shape is refused before anything else', () => {
  // THE ALLOWLIST IS STILL AN ALLOWLIST, which is the whole reason the gate survives now that it
  // names every family custody currently holds keys for. `SIGNABLE_PURPOSES` contains `deposit`, so
  // a sixth family added to `chains.ts` would become signable the moment `keys.ts` learned to
  // dispatch it — with whatever its signer happened to offer, which for a new signer is normally
  // "whatever the caller asked for". This is what makes that a refusal instead, and the assertion is
  // written against a family that does not exist precisely so it keeps meaning something.
  for (const family of ['aptos', 'cardano', '']) {
    const gate = purposeGate({ purpose: 'deposit', family, status: 'active' })
    assert.equal(gate.ok, false, family)
    assert.match(gate.ok ? '' : gate.error, /have no sweep shape/)
  }
  // The five that DO have one. `bitcoin` and `solana` were refused here until their sweep shapes
  // were built — the property has moved into `signing.ts`, where every output of a BTC sweep and
  // the sole destination of a SOL sweep must be the pinned treasury.
  for (const family of ['evm', 'ember', 'xrp', 'bitcoin', 'solana']) {
    assert.equal(purposeGate({ purpose: 'deposit', family, status: 'active' }).ok, true, family)
  }
})

test('gate 1: an EXPORTED key is not signed for — the platform stops sweeping it', () => {
  // SD-07 gate 9. This is where "the platform stops treating it as custodial" is enforced rather
  // than merely documented: an exported key is a key two parties hold.
  const gate = purposeGate({ purpose: 'deposit', family: 'evm', status: 'exported' })
  assert.equal(gate.ok, false)
  assert.match(gate.ok ? '' : gate.error, /'exported' and is no longer signed for/)
  assert.equal(purposeGate({ purpose: 'deposit', family: 'evm', status: 'retired' }).ok, false)
})

test('the EVM shape is chosen by purpose, and the unreachable fallback is the narrowest', () => {
  assert.equal(evmShapeForPurpose('deployer'), 'creation')
  assert.equal(evmShapeForPurpose('treasury'), 'transfer')
  assert.equal(evmShapeForPurpose('deposit'), 'sweep')
  // Unreachable — `purposeGate` excluded it — and 'creation' because a creation cannot move value.
  // Deliberately not 'sweep', which despite its pinned destination still moves money.
  assert.equal(evmShapeForPurpose('something-new'), 'creation')
})

test('the Solana and Bitcoin shapes are chosen by purpose, and their fallback can sign NOTHING', () => {
  assert.equal(solanaShapeForPurpose('deployer'), 'mint')
  assert.equal(solanaShapeForPurpose('treasury'), 'transfer')
  assert.equal(solanaShapeForPurpose('deposit'), 'sweep')

  assert.equal(bitcoinShapeForPurpose('deployer'), 'payment')
  assert.equal(bitcoinShapeForPurpose('treasury'), 'payment')
  assert.equal(bitcoinShapeForPurpose('deposit'), 'sweep')

  // 'sweep' reads like the WIDER fallback and is the narrowest one available. `keys.ts` resolves a
  // treasury pin only for `purpose = 'deposit'`, so an unforeseen purpose reaching this fallback is
  // handed an EMPTY pin, and both signers refuse an empty pin outright — see the two
  // 'no usable treasury is pinned' cases in signing.test.ts. The fallback therefore signs nothing.
  // 'mint' and 'payment' would both still move money.
  assert.equal(solanaShapeForPurpose('something-new'), 'sweep')
  assert.equal(bitcoinShapeForPurpose('something-new'), 'sweep')
})

test('a `pool` purpose takes the fallback in all three mappings, and every fallback is the safe one', () => {
  // `pool` is deliberately NOT given an entry in any of the three maps: an entry would read as "this
  // purpose may select this shape", and gate 1 refuses it. What the fallbacks answer still matters,
  // because `keys.shapeForRow` computes one BEFORE the gate runs, to label the refusal's audit row.
  //
  // The values are the fail-closed ones. On Bitcoin — the family the pool actually mines — it is
  // 'sweep', which resolves no pin for a non-deposit purpose and therefore signs nothing at all; on
  // EVM it is 'creation', which cannot move value. So even if gate 1 were removed tomorrow, a pool
  // payout address would not be handed a shape that can spend a block reward.
  assert.equal(bitcoinShapeForPurpose('pool'), 'sweep')
  assert.equal(solanaShapeForPurpose('pool'), 'sweep')
  assert.equal(evmShapeForPurpose('pool'), 'creation')
})

/* ------------------------------------------------------------------ gate 2 */

test('gate 2: an exact restatement matches', () => {
  assert.equal(bindingMatches(ROW, { ...ROW }), true)
})

test('gate 2: a MISMATCH ON EACH OF THE FIVE FIELDS is refused, one field at a time', () => {
  // SD-09 names five: address, chain, network, userId, orderId. Asserted individually because a
  // comparison that dropped one field would still pass a test that changed two.
  const cases: Array<[keyof RowIdentity, string]> = [
    ['address', '0x2222222222222222222222222222222222222222'],
    ['chain', 'ember'],
    ['network', 'mainnet'],
    ['userId', 'user-b'],
    ['orderId', 'order-2'],
  ]
  for (const [field, value] of cases) {
    const claim = { ...ROW, [field]: value }
    assert.equal(bindingMatches(ROW, claim), false, `${field} was not compared`)
    assert.deepEqual(bindingMismatches(ROW, claim), [field])
  }
})

test('gate 2: userId is COMPARED, which is the field that was compared to nothing before', () => {
  // The defect, named: in forge-keyvault `row.userId` was never compared at all, so a caller that
  // had learned one address could sign for it while claiming any customer they liked.
  assert.equal(bindingMatches(ROW, { ...ROW, userId: 'someone-else' }), false)
})

test('gate 2: purpose and family are compared too — two more than SD-09 lists, carried forward', () => {
  assert.equal(bindingMatches(ROW, { ...ROW, purpose: 'treasury' }), false)
  assert.equal(bindingMatches(ROW, { ...ROW, family: 'ember' }), false)
})

/* ------------------------------------------------------------------ gate 3 */

test('gate 3: a GENERIC `evm` chain is refused — a signature with no chain id is valid everywhere', () => {
  const result = resolveChainId({ family: 'evm', chain: 'evm' }, 'testnet')
  assert.equal(result.ok, false)
  assert.match(result.ok ? '' : result.error, /valid on every EVM chain/)
})

test('gate 3: chain ids come from @cloudsforge/contracts-chain and are never redefined here', () => {
  // These are the exact-pinned values. If this test ever has to be edited, contracts-chain changed
  // and every consumer must be released together — which is the point of pinning it.
  assert.deepEqual(resolveChainId({ family: 'evm', chain: 'ethereum' }, 'mainnet'), { ok: true, chainId: 1 })
  assert.deepEqual(resolveChainId({ family: 'evm', chain: 'ethereum' }, 'testnet'), { ok: true, chainId: 11_155_111 })
  assert.deepEqual(resolveChainId({ family: 'ember', chain: 'ember' }, 'mainnet'), { ok: true, chainId: 7411 })
  assert.deepEqual(resolveChainId({ family: 'ember', chain: 'ember' }, 'testnet'), { ok: true, chainId: 7412 })
})

test('gate 3: a non-EVM family has no chain id to resolve and is not refused for lacking one', () => {
  for (const family of ['bitcoin', 'solana', 'xrp']) {
    assert.equal(resolveChainId({ family, chain: family }, 'testnet').ok, true)
  }
})

/* ------------------------------------------------------------------ scopes */

test('the signing scope is chosen by purpose — SD-05', () => {
  assert.equal(signScopeFor('deposit'), 'custody:sign:deposit')
  assert.equal(signScopeFor('treasury'), 'custody:sign:treasury')
  assert.equal(signScopeFor('deployer'), 'custody:sign:deployer')
})
