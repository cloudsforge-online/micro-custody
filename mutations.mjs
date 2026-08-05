/**
 * Mutation testing for Litecoin derivation.
 *
 * The bug being fixed produced a WELL-FORMED address with a VALID checksum that nothing rejected —
 * a `bc1…` Bitcoin address published as a Litecoin deposit address. Nothing threw, so nothing a
 * happy-path test could see was different. Each mutation below reintroduces one facet of it and
 * names the test that must go red.
 *
 * Run: CUSTODY_TEST_DATABASE_URL=... node mutations.mjs
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

const MUTATIONS = [
  {
    name: 'THE ORIGINAL BUG: Litecoin derives under Bitcoin network parameters',
    file: 'src/chains.ts',
    from: `    litecoin: { mainnet: LITECOIN_MAINNET, testnet: LITECOIN_TESTNET },`,
    to: `    litecoin: { mainnet: bitcoin.networks.bitcoin, testnet: bitcoin.networks.testnet },`,
    expect: 'LITECOIN: the address this service mints is ltc1 on mainnet and tltc1 on testnet',
  },
  {
    name: 'the bech32 HRP is Bitcoin’s, so the address reads bc1',
    file: 'src/chains.ts',
    from: `  bech32: 'ltc',`,
    to: `  bech32: 'bc',`,
    expect: 'LITECOIN: the published Trezor vector for m/44\'/2\'/0\'/0/0',
  },
  {
    name: 'the WIF version byte is Bitcoin’s, so the key is stored as a Bitcoin key',
    file: 'src/chains.ts',
    from: `  wif: 0xb0,`,
    to: `  wif: 0x80,`,
    expect: 'LITECOIN: the WIF carries Litecoin version byte, which IS the network binding',
  },
  {
    name: 'the legacy pubKeyHash byte is Bitcoin’s, so a legacy address reads 1 rather than L',
    file: 'src/chains.ts',
    from: `  pubKeyHash: 0x30,`,
    to: `  pubKeyHash: 0x00,`,
    expect: 'LITECOIN: the published Trezor vector for m/44\'/2\'/0\'/0/0',
  },
  {
    name: 'an unknown bitcoin-family chain silently defaults to Bitcoin',
    file: 'src/chains.ts',
    from: `  const params = BITCOIN_FAMILY_NETWORKS[chain]
  if (!params) {`,
    to: `  const params = BITCOIN_FAMILY_NETWORKS[chain] ?? BITCOIN_FAMILY_NETWORKS['bitcoin']
  if (!params) {`,
    expect: 'LITECOIN: a bitcoin-family chain with no parameters is refused, never defaulted to Bitcoin',
  },
  {
    name: 'Litecoin shares Bitcoin’s BIP-44 coin type, so one seed gives one keyspace',
    file: 'src/hd.ts',
    from: `const CHAIN_COIN_TYPE: Readonly<Record<string, number>> = Object.freeze({
  litecoin: 2,
})`,
    to: `const CHAIN_COIN_TYPE: Readonly<Record<string, number>> = Object.freeze({})`,
    expect: "LITECOIN: coin type is SLIP-0044's 2, so BTC and LTC are different keys from one seed",
  },
  {
    name: 'the chain-specific coin type is consulted after the family instead of before',
    file: 'src/hd.ts',
    from: `  return CHAIN_COIN_TYPE[chain] ?? COIN_TYPE[family]`,
    to: `  return COIN_TYPE[family] ?? CHAIN_COIN_TYPE[chain]`,
    expect: "LITECOIN: coin type is SLIP-0044's 2, so BTC and LTC are different keys from one seed",
  },
  {
    name: 'testnet stops collapsing to coin type 1, breaking the network binding',
    file: 'src/hd.ts',
    from: `  if (network !== 'mainnet') return TESTNET_COIN_TYPE`,
    to: `  if (network === 'never') return TESTNET_COIN_TYPE`,
    expect: 'every family separates its two networks by coin type',
  },
  {
    name: 'the flat-random scheme ignores the chain and mints a Bitcoin address',
    file: 'src/chains.ts',
    from: `      const net = bitcoinNetwork(chain, network)
      const keyPair = ECPair.makeRandom({ network: net })`,
    to: `      const net = bitcoinNetwork('bitcoin', network)
      const keyPair = ECPair.makeRandom({ network: net })`,
    expect: 'LITECOIN: a flat-random key is Litecoin too, so the legacy scheme cannot mint a Bitcoin address',
  },
  {
    name: 'HD derivation ignores the chain and uses Bitcoin parameters',
    file: 'src/hd.ts',
    from: `      const net = bitcoinNetwork(chain, network)`,
    to: `      const net = bitcoinNetwork('bitcoin', network)`,
    expect: 'LITECOIN: the address this service mints is ltc1 on mainnet and tltc1 on testnet',
  },
  {
    name: 'the signer resolves network parameters from the family instead of the row chain',
    file: 'src/keys.ts',
    from: `      return wrap(shape, signBitcoin(privateKey, payload, row.address, ctx.network, policy, row.chain))`,
    to: `      return wrap(shape, signBitcoin(privateKey, payload, row.address, ctx.network, policy, 'bitcoin'))`,
    expect: null,
  },
  {
    name: 'litecoin is dropped from the chains custody will mint for',
    file: 'src/chains.ts',
    from: `  litecoin: 'LTC',`,
    to: ``,
    expect: null,
  },
]

const originals = new Map()
process.on('exit', () => {
  for (const [file, text] of originals) writeFileSync(file, text)
})

const FILES = ['src/hd.test.ts', 'src/signing.test.ts', 'src/litecoin.test.ts']

function runSuite() {
  try {
    execFileSync(
      'node',
      ['--import', 'tsx', '--test', '--test-concurrency=1', ...FILES.filter(existsIsh)],
      { encoding: 'utf8', stdio: 'pipe' },
    )
    return { failures: [] }
  } catch (err) {
    const out = `${err.stdout ?? ''}${err.stderr ?? ''}`
    const names = [...out.matchAll(/^\s*✖ (.+?) \(/gm)].map((m) => m[1])
    return { failures: [...new Set(names)] }
  }
}

function existsIsh(file) {
  try {
    readFileSync(file)
    return true
  } catch {
    return false
  }
}

console.log('baseline …')
const baseline = runSuite()
if (baseline.failures.length > 0) {
  console.error('the suite is not green before mutating:', baseline.failures)
  process.exit(1)
}
console.log('baseline is green\n')

let killed = 0
const survivors = []
for (const mutation of MUTATIONS) {
  if (!originals.has(mutation.file)) originals.set(mutation.file, readFileSync(mutation.file, 'utf8'))
  const original = originals.get(mutation.file)
  if (!original.includes(mutation.from)) {
    console.log(`?  ${mutation.name}\n   — text not found; the mutation is stale`)
    continue
  }
  writeFileSync(mutation.file, original.replace(mutation.from, mutation.to))
  const { failures } = runSuite()
  writeFileSync(mutation.file, original)

  if (failures.length === 0) {
    survivors.push(mutation.name)
    console.log(`✖  SURVIVOR: ${mutation.name}`)
  } else if (mutation.expect === null || failures.includes(mutation.expect)) {
    killed += 1
    console.log(`✓  ${mutation.name}\n   → killed by: ${failures.slice(0, 3).join(', ')}`)
  } else {
    killed += 1
    console.log(
      `~  ${mutation.name}\n   → expected "${mutation.expect}"\n   → killed instead by: ${failures.slice(0, 3).join(', ')}`,
    )
  }
}

console.log(`\n${killed}/${MUTATIONS.length} mutations killed`)
if (survivors.length > 0) {
  for (const s of survivors) console.log(`  survivor: ${s}`)
  process.exit(1)
}
