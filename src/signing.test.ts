/**
 * The signing policy, exercised mostly by what it REFUSES.
 *
 * SD-16 lists "signing gate negative tests" as a continuous check, and SD-09's verification line
 * enumerates them: a deposit key attempting a transfer, a mismatched binding, a generic `evm` chain,
 * a sweep to an unpinned address. This file covers those plus the per-family allowlists — a Solana
 * `SetAuthority`, a Bitcoin PSBT with a foreign input, an XRP `Payment` with no `LastLedgerSequence`.
 *
 * Everything here is pure: a key, a payload, a policy. No database, no HTTP, no JWKS. That is
 * deliberate — a negative test that needs three fixtures to express is a negative test somebody
 * deletes the day it goes red, and these are the tests that must never be deleted.
 */

import assert from 'node:assert/strict'
import test from 'node:test'
import { ethers } from 'ethers'
import { Keypair, PublicKey, SystemProgram, Transaction as SolanaTransaction, TransactionInstruction } from '@solana/web3.js'
import * as bitcoin from 'bitcoinjs-lib'
import { Wallet as XrplWallet } from 'xrpl'
import { ECPair, bitcoinNetwork } from './chains.ts'
import { SignRefused, signBitcoin, signEvm, signSolana, signXrp } from './signing.ts'

const CHAIN_ID = 11_155_111

/* ------------------------------------------------------------------ EVM */

const evmWallet = ethers.Wallet.createRandom()
const TREASURY = ethers.Wallet.createRandom().address
const STRANGER = ethers.Wallet.createRandom().address

const transferTx = (overrides: Record<string, unknown> = {}) => ({
  to: TREASURY,
  value: '1000000000000000',
  nonce: 0,
  gasLimit: 21_000,
  chainId: CHAIN_ID,
  maxFeePerGas: '20000000000',
  maxPriorityFeePerGas: '1000000000',
  ...overrides,
})

const creationTx = (overrides: Record<string, unknown> = {}) => ({
  to: null,
  data: '0x6080604052',
  value: 0,
  nonce: 0,
  gasLimit: 1_500_000,
  chainId: CHAIN_ID,
  maxFeePerGas: '20000000000',
  maxPriorityFeePerGas: '1000000000',
  ...overrides,
})

async function refusal(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn()
  } catch (err) {
    assert.ok(err instanceof SignRefused, `expected a SignRefused, got ${String(err)}`)
    return (err as Error).message
  }
  assert.fail('expected a refusal')
}

test('EVM: a treasury key signs a plain transfer', async () => {
  const signed = await signEvm(evmWallet.privateKey, transferTx(), { chainId: CHAIN_ID, shape: 'transfer' })
  const parsed = ethers.Transaction.from(signed)
  assert.equal(parsed.from, evmWallet.address)
  assert.equal(parsed.chainId, BigInt(CHAIN_ID))
})

test('EVM: a deployer key signs a zero-value creation', async () => {
  const signed = await signEvm(evmWallet.privateKey, creationTx(), { chainId: CHAIN_ID, shape: 'creation' })
  assert.equal(ethers.Transaction.from(signed).to, null)
})

test('SD-09 §1 — a DEPOSIT key attempting a TRANSFER is refused', async () => {
  // The shape a deposit key gets is `sweep`, whose destination the vault chooses. Handing it a
  // transfer to an address of the caller's choosing is the whole attack the purpose gate exists for.
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: STRANGER }), {
      chainId: CHAIN_ID,
      shape: 'sweep',
      treasuryPin: TREASURY,
    }),
  )
  assert.match(message, /a sweep does not choose its own destination/)
})

test('SD-09 §1 — a DEPLOYER key attempting a transfer is refused', async () => {
  const message = await refusal(() => signEvm(evmWallet.privateKey, transferTx(), { chainId: CHAIN_ID, shape: 'creation' }))
  assert.match(message, /may only sign contract creations/)
})

test('SD-09 §1 — a TREASURY key attempting a contract creation is refused', async () => {
  const message = await refusal(() => signEvm(evmWallet.privateKey, creationTx(), { chainId: CHAIN_ID, shape: 'transfer' }))
  assert.match(message, /`to` must be a valid address/)
})

test('SD-09 §4 — a sweep to an UNPINNED address is refused', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: STRANGER }), {
      chainId: CHAIN_ID,
      shape: 'sweep',
      treasuryPin: TREASURY,
    }),
  )
  assert.match(message, /must be the treasury address pinned/)
})

test('SD-09 §4 — a sweep with NO pin at all is refused, not defaulted', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx(), { chainId: CHAIN_ID, shape: 'sweep', treasuryPin: '' }),
  )
  assert.match(message, /no usable treasury is pinned/)
})

test('a sweep TO the pin is signed, and that is the only destination there is', async () => {
  const signed = await signEvm(evmWallet.privateKey, transferTx({ to: TREASURY }), {
    chainId: CHAIN_ID,
    shape: 'sweep',
    treasuryPin: TREASURY,
  })
  assert.equal(ethers.Transaction.from(signed).to, TREASURY)
})

test('a sweep naming the pin in a different case gets its own, actionable refusal', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: TREASURY.toLowerCase() }), {
      chainId: CHAIN_ID,
      shape: 'sweep',
      treasuryPin: TREASURY,
    }),
  )
  assert.match(message, /different case/)
})

test("the `approve` test: calldata on a transfer is refused, so /sign is not a signing oracle", async () => {
  // `approve(attacker, 2^256-1)` is `to != null`, `value = 0` and 68 bytes of calldata — it passes
  // every other check in the file. Empty calldata is what makes this a policy rather than an oracle.
  const approve = `0x095ea7b3${'0'.repeat(24)}${STRANGER.slice(2)}${'f'.repeat(64)}`
  for (const shape of ['transfer', 'sweep'] as const) {
    const policy = shape === 'sweep' ? { chainId: CHAIN_ID, shape, treasuryPin: TREASURY } : { chainId: CHAIN_ID, shape }
    const message = await refusal(() =>
      signEvm(evmWallet.privateKey, transferTx({ to: TREASURY, data: approve }), policy),
    )
    assert.match(message, /`data` must be empty/)
  }
})

test('an unknown EVM field is refused — an unexpected field is a signature nobody asked for', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ accessList: [] }), { chainId: CHAIN_ID, shape: 'transfer' }),
  )
  assert.match(message, /carries a field this service does not sign/)
})

test('the chain id must be the one resolved from the row', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ chainId: 1 }), { chainId: CHAIN_ID, shape: 'transfer' }),
  )
  assert.match(message, /chainId must be 11155111/)
})

test('exactly one fee model, never both and never neither', async () => {
  assert.match(
    await refusal(() =>
      signEvm(evmWallet.privateKey, transferTx({ gasPrice: '10000000000' }), { chainId: CHAIN_ID, shape: 'transfer' }),
    ),
    /exactly one of/,
  )
  const neither = transferTx()
  delete (neither as Record<string, unknown>).maxFeePerGas
  delete (neither as Record<string, unknown>).maxPriorityFeePerGas
  assert.match(
    await refusal(() => signEvm(evmWallet.privateKey, neither, { chainId: CHAIN_ID, shape: 'transfer' })),
    /exactly one of/,
  )
})

test('the gasLimit × maxFee ceiling bounds what one signature can cost the address', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ maxFeePerGas: '10000000000000000', maxPriorityFeePerGas: '1' }), {
      chainId: CHAIN_ID,
      shape: 'transfer',
    }),
  )
  assert.match(message, /maximum fee exceeds/)
})

test('ember is legacy-only: an EIP-1559 transaction for it is bytes its node cannot parse', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ chainId: 7412 }), { chainId: 7412, shape: 'transfer', legacyOnly: true }),
  )
  assert.match(message, /legacy transactions only/)
})

test('an 18-decimal value arrives as a string and is exact; a lossy number is refused', async () => {
  const signed = await signEvm(evmWallet.privateKey, transferTx({ value: '1000000000000000000' }), {
    chainId: CHAIN_ID,
    shape: 'transfer',
  })
  assert.equal(ethers.Transaction.from(signed).value, 10n ** 18n)
  assert.match(
    await refusal(() => signEvm(evmWallet.privateKey, transferTx({ value: 1e18 }), { chainId: CHAIN_ID, shape: 'transfer' })),
    /not a non-negative integer/,
  )
})

test('the zero address is refused as a transfer destination', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: ethers.ZeroAddress }), { chainId: CHAIN_ID, shape: 'transfer' }),
  )
  assert.match(message, /must not be the zero address/)
})

/* ------------------------------------------------------------------ Solana */

const solKeypair = Keypair.generate()
const solSecret = Buffer.from(solKeypair.secretKey).toString('base64')
const solAddress = solKeypair.publicKey.toBase58()
const TOKEN_PROGRAM = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi'

function solanaTx(instructions: TransactionInstruction[], feePayer = solKeypair.publicKey): string {
  const tx = new SolanaTransaction({ feePayer, recentBlockhash: BLOCKHASH })
  for (const ix of instructions) tx.add(ix)
  return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64')
}

/** An SPL token-program instruction with a raw tag byte. Built by hand — see signing.ts on why. */
function splInstruction(tag: number, keys: PublicKey[]): TransactionInstruction {
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM,
    keys: keys.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
    data: Buffer.from([tag]),
  })
}

test('Solana: initializeMint2 and mintTo are signed', () => {
  const mint = Keypair.generate().publicKey
  const payload = solanaTx([
    splInstruction(20, [mint]),
    splInstruction(7, [mint, Keypair.generate().publicKey, solKeypair.publicKey]),
  ])
  const signed = signSolana(solSecret, payload, solAddress)
  assert.equal(SolanaTransaction.from(Buffer.from(signed, 'base64')).signatures.length, 1)
})

test('Solana: SetAuthority (tag 6) is REFUSED — it hands the mint to someone else permanently', () => {
  const payload = solanaTx([splInstruction(6, [Keypair.generate().publicKey, solKeypair.publicKey])])
  assert.throws(() => signSolana(solSecret, payload, solAddress), (err: unknown) => {
    assert.ok(err instanceof SignRefused)
    assert.match((err as Error).message, /SPL token instruction 6 is not one this service signs for/)
    return true
  })
})

test('Solana: every one of Transfer, Approve, SetAuthority, Burn and CloseAccount is refused', () => {
  // SD-09 names all five. They are every way to move or reassign what the address holds, so they are
  // asserted as a set rather than one at a time — a future widening that admitted one of them would
  // otherwise only fail a test somebody could read as being about SetAuthority.
  for (const tag of [3, 4, 6, 8, 9]) {
    const payload = solanaTx([splInstruction(tag, [solKeypair.publicKey, solKeypair.publicKey, solKeypair.publicKey])])
    assert.throws(() => signSolana(solSecret, payload, solAddress), SignRefused, `tag ${tag} was not refused`)
  }
})

test('Solana: a SystemProgram transfer is refused — there is no SOL transfer shape at all', () => {
  const payload = solanaTx([
    SystemProgram.transfer({
      fromPubkey: solKeypair.publicKey,
      toPubkey: Keypair.generate().publicKey,
      lamports: 1_000_000,
    }),
  ])
  assert.throws(() => signSolana(solSecret, payload, solAddress), SignRefused)
})

test('Solana: an unknown program is refused', () => {
  const payload = solanaTx([
    new TransactionInstruction({
      programId: Keypair.generate().publicKey,
      keys: [{ pubkey: solKeypair.publicKey, isSigner: true, isWritable: true }],
      data: Buffer.from([0]),
    }),
  ])
  assert.throws(() => signSolana(solSecret, payload, solAddress), SignRefused)
})

test('Solana: the fee payer must be this address', () => {
  const payload = solanaTx([splInstruction(20, [Keypair.generate().publicKey])], Keypair.generate().publicKey)
  assert.throws(
    () => signSolana(solSecret, payload, solAddress),
    (err: unknown) => err instanceof SignRefused && /fee payer must be the vault address/.test((err as Error).message),
  )
})

test('Solana: createAccount may only allocate an SPL mint account', () => {
  const payload = solanaTx([
    SystemProgram.createAccount({
      fromPubkey: solKeypair.publicKey,
      newAccountPubkey: Keypair.generate().publicKey,
      lamports: 1_000_000,
      // 165 bytes is a token ACCOUNT, not a mint — the shape that would let a deployer be funded
      // into something other than the one thing this service signs creations for.
      space: 165,
      programId: TOKEN_PROGRAM,
    }),
  ])
  assert.throws(
    () => signSolana(solSecret, payload, solAddress),
    (err: unknown) => err instanceof SignRefused && /only allocate an SPL mint account/.test((err as Error).message),
  )
})

/* ------------------------------------------------------------------ Bitcoin */

const btcNetwork = bitcoinNetwork('testnet')
const btcKey = ECPair.makeRandom({ network: btcNetwork })
const btcPayment = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(btcKey.publicKey), network: btcNetwork })
const foreignKey = ECPair.makeRandom({ network: btcNetwork })
const foreignPayment = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(foreignKey.publicKey), network: btcNetwork })

function psbt(options: { script?: Buffer; sighashType?: number; noWitnessUtxo?: boolean } = {}): string {
  const p = new bitcoin.Psbt({ network: btcNetwork })
  const input: Parameters<bitcoin.Psbt['addInput']>[0] = {
    hash: Buffer.alloc(32, 7),
    index: 0,
    ...(options.noWitnessUtxo ? {} : { witnessUtxo: { script: options.script ?? btcPayment.output!, value: 100_000 } }),
    ...(options.sighashType === undefined ? {} : { sighashType: options.sighashType }),
  }
  p.addInput(input)
  p.addOutput({ address: foreignPayment.address!, value: 90_000 })
  return p.toBase64()
}

test('Bitcoin: a PSBT spending this address is signed and finalised', () => {
  const hex = signBitcoin(btcKey.toWIF(), psbt(), btcPayment.address!, 'testnet')
  assert.match(hex, /^[0-9a-f]+$/)
})

test('Bitcoin: a PSBT with a FOREIGN input is refused', () => {
  // Every input must be a P2WPKH output of this very address, so the service can only ever spend its
  // own coins. `signAllInputs` signs all of them, so one foreign input would be signed too.
  assert.throws(
    () => signBitcoin(btcKey.toWIF(), psbt({ script: foreignPayment.output! }), btcPayment.address!, 'testnet'),
    (err: unknown) => err instanceof SignRefused && /does not spend this vault address/.test((err as Error).message),
  )
})

test('Bitcoin: an input with no witnessUtxo is refused — its value is unknown', () => {
  assert.throws(
    () => signBitcoin(btcKey.toWIF(), psbt({ noWitnessUtxo: true }), btcPayment.address!, 'testnet'),
    (err: unknown) => err instanceof SignRefused && /its value is unknown/.test((err as Error).message),
  )
})

test('Bitcoin: anything but SIGHASH_ALL is refused — it leaves the rest of the tx editable', () => {
  assert.throws(
    () =>
      signBitcoin(
        btcKey.toWIF(),
        psbt({ sighashType: bitcoin.Transaction.SIGHASH_SINGLE }),
        btcPayment.address!,
        'testnet',
      ),
    (err: unknown) => err instanceof SignRefused && /only SIGHASH_ALL is signed/.test((err as Error).message),
  )
})

test('Bitcoin: a raw transaction is refused — only a PSBT carries each input value', () => {
  assert.throws(
    () => signBitcoin(btcKey.toWIF(), { version: 2 }, btcPayment.address!, 'testnet'),
    (err: unknown) => err instanceof SignRefused && /must be a base64 PSBT/.test((err as Error).message),
  )
})

test('Bitcoin: the WIF carries the network, so a mainnet key cannot satisfy a testnet request', () => {
  const mainnetKey = ECPair.makeRandom({ network: bitcoinNetwork('mainnet') })
  // Not a SignRefused: a key that does not match the row is a fault in here, not the caller's fault.
  assert.throws(() => signBitcoin(mainnetKey.toWIF(), psbt(), btcPayment.address!, 'testnet'))
})

/* ------------------------------------------------------------------ XRP */

const xrpWallet = XrplWallet.generate()
const XRP_TREASURY = XrplWallet.generate().classicAddress

const payment = (overrides: Record<string, unknown> = {}) => ({
  TransactionType: 'Payment',
  Account: xrpWallet.classicAddress,
  Destination: XRP_TREASURY,
  Amount: '1000000',
  Fee: '12',
  Sequence: 1,
  LastLedgerSequence: 100,
  ...overrides,
})

test('XRP: a Payment with a bound Account, a fee under the ceiling and a LastLedgerSequence is signed', () => {
  const blob = signXrp(xrpWallet.seed!, payment(), xrpWallet.classicAddress, { shape: 'payment' })
  assert.match(blob, /^[0-9A-F]+$/)
})

test('XRP: a Payment with NO LastLedgerSequence is refused — the blob would stay submittable for ever', () => {
  const tx = payment()
  delete (tx as Record<string, unknown>).LastLedgerSequence
  assert.throws(
    () => signXrp(xrpWallet.seed!, tx, xrpWallet.classicAddress, { shape: 'payment' }),
    (err: unknown) => err instanceof SignRefused && /LastLedgerSequence` is required/.test((err as Error).message),
  )
})

test('XRP: only a Payment. SetRegularKey, SignerListSet and AccountSet hand the account away', () => {
  for (const type of ['SetRegularKey', 'SignerListSet', 'AccountSet', 'OfferCreate', 'TrustSet']) {
    assert.throws(
      () => signXrp(xrpWallet.seed!, payment({ TransactionType: type }), xrpWallet.classicAddress, { shape: 'payment' }),
      SignRefused,
      `${type} was not refused`,
    )
  }
})

test('XRP: a field outside the allowlist is refused — Paths and SendMax make it a currency order', () => {
  for (const field of ['Paths', 'SendMax', 'DeliverMin', 'TicketSequence', 'NetworkID']) {
    assert.throws(
      () => signXrp(xrpWallet.seed!, payment({ [field]: 'x' }), xrpWallet.classicAddress, { shape: 'payment' }),
      SignRefused,
      `${field} was not refused`,
    )
  }
})

test('XRP: the Account must be this address', () => {
  assert.throws(
    () =>
      signXrp(xrpWallet.seed!, payment({ Account: XRP_TREASURY }), xrpWallet.classicAddress, { shape: 'payment' }),
    (err: unknown) => err instanceof SignRefused && /`Account` must be the vault address/.test((err as Error).message),
  )
})

test('XRP: an issued-currency Amount is refused; only drops', () => {
  assert.throws(
    () =>
      signXrp(xrpWallet.seed!, payment({ Amount: { currency: 'USD', value: '1', issuer: XRP_TREASURY } }), xrpWallet.classicAddress, {
        shape: 'payment',
      }),
    SignRefused,
  )
})

test('XRP: the fee ceiling is a burn ceiling, not an estimate', () => {
  assert.throws(
    () => signXrp(xrpWallet.seed!, payment({ Fee: '2000000' }), xrpWallet.classicAddress, { shape: 'payment' }),
    (err: unknown) => err instanceof SignRefused && /Fee` exceeds/.test((err as Error).message),
  )
})

test('XRP: tfPartialPayment is refused — the delivered amount would not be the signed amount', () => {
  assert.throws(
    () => signXrp(xrpWallet.seed!, payment({ Flags: 0x00020000 }), xrpWallet.classicAddress, { shape: 'payment' }),
    SignRefused,
  )
})

test('XRP: a sweep may only pay the pin', () => {
  const stranger = XrplWallet.generate().classicAddress
  assert.throws(
    () =>
      signXrp(xrpWallet.seed!, payment({ Destination: stranger }), xrpWallet.classicAddress, {
        shape: 'sweep',
        treasuryPin: XRP_TREASURY,
      }),
    (err: unknown) => err instanceof SignRefused && /a sweep does not choose its own destination/.test((err as Error).message),
  )
  assert.doesNotThrow(() =>
    signXrp(xrpWallet.seed!, payment(), xrpWallet.classicAddress, { shape: 'sweep', treasuryPin: XRP_TREASURY }),
  )
})

test('XRP: a sweep with no pin is refused rather than defaulted', () => {
  assert.throws(
    () => signXrp(xrpWallet.seed!, payment(), xrpWallet.classicAddress, { shape: 'sweep', treasuryPin: '' }),
    (err: unknown) => err instanceof SignRefused && /no usable treasury is pinned/.test((err as Error).message),
  )
})
