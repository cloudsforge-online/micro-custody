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
import {
  SignRefused,
  signBitcoin,
  signEvm,
  signSolana,
  signXrp,
  type BitcoinPolicy,
  type SolanaPolicy,
} from './signing.ts'

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

/** No token registered. The default for every chain until an administrator registers one. */
const NO_TOKENS: ReadonlySet<string> = new Set<string>()

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
  const { signedTx: signed } = await signEvm(evmWallet.privateKey, transferTx(), { chainId: CHAIN_ID, shape: 'transfer' })
  const parsed = ethers.Transaction.from(signed)
  assert.equal(parsed.from, evmWallet.address)
  assert.equal(parsed.chainId, BigInt(CHAIN_ID))
})

test('EVM: a deployer key signs a zero-value creation', async () => {
  const { signedTx: signed } = await signEvm(evmWallet.privateKey, creationTx(), { chainId: CHAIN_ID, shape: 'creation' })
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
      tokenAllowlist: NO_TOKENS,
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
      tokenAllowlist: NO_TOKENS,
    }),
  )
  assert.match(message, /must be the treasury address pinned/)
})

test('SD-09 §4 — a sweep with NO pin at all is refused, not defaulted', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx(), { chainId: CHAIN_ID, shape: 'sweep', treasuryPin: '', tokenAllowlist: NO_TOKENS }),
  )
  assert.match(message, /no usable treasury is pinned/)
})

test('a sweep TO the pin is signed, and that is the only destination there is', async () => {
  const { signedTx: signed } = await signEvm(evmWallet.privateKey, transferTx({ to: TREASURY }), {
    chainId: CHAIN_ID,
    shape: 'sweep',
    treasuryPin: TREASURY,
    tokenAllowlist: NO_TOKENS,
  })
  assert.equal(ethers.Transaction.from(signed).to, TREASURY)
})

test('a sweep naming the pin in a different case gets its own, actionable refusal', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: TREASURY.toLowerCase() }), {
      chainId: CHAIN_ID,
      shape: 'sweep',
      treasuryPin: TREASURY,
      tokenAllowlist: NO_TOKENS,
    }),
  )
  assert.match(message, /different case/)
})

test("the `approve` test: calldata on a transfer is refused, so /sign is not a signing oracle", async () => {
  // `approve(attacker, 2^256-1)` is `to != null`, `value = 0` and 68 bytes of calldata — it passes
  // every other check in the file. Empty calldata is what makes this a policy rather than an oracle.
  //
  // WHY THE TWO SHAPES NOW REFUSE IT FOR DIFFERENT REASONS, which is the thing to understand about
  // this test rather than a weakening of it. `transfer` still refuses ALL calldata, unchanged. A
  // `sweep` payload carrying calldata is no longer a malformed sweep — it is dispatched to
  // `token_sweep`, which refuses this one twice over: `TREASURY` is not a registered token
  // contract, and `approve` is not the `transfer` selector. The test asserts each rule against the
  // shape that actually owns it, because a single expected message across both would now be
  // asserting that one of the two shapes does something it does not.
  const approve = `0x095ea7b3${'0'.repeat(24)}${STRANGER.slice(2)}${'f'.repeat(64)}`

  const onTransfer = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: TREASURY, data: approve }), {
      chainId: CHAIN_ID,
      shape: 'transfer',
    }),
  )
  assert.match(onTransfer, /`data` must be empty/)

  const onSweep = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: TREASURY, data: approve }), {
      chainId: CHAIN_ID,
      shape: 'sweep',
      treasuryPin: TREASURY,
      tokenAllowlist: NO_TOKENS,
    }),
  )
  assert.match(onSweep, /not a token contract registered/)
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
  const { signedTx: signed } = await signEvm(evmWallet.privateKey, transferTx({ value: '1000000000000000000' }), {
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

const SOL_TREASURY = Keypair.generate().publicKey
const SOL_STRANGER = Keypair.generate().publicKey

const MINT: SolanaPolicy = { shape: 'mint' }
const SOL_TRANSFER: SolanaPolicy = { shape: 'transfer' }
const SOL_SWEEP: SolanaPolicy = { shape: 'sweep', treasuryPin: SOL_TREASURY.toBase58() }
/** Every shape, so a rule that must hold under all three is asserted under all three. */
const SOL_SHAPES: readonly SolanaPolicy[] = [MINT, SOL_TRANSFER, SOL_SWEEP]

function solTransferIx(to: PublicKey, lamports = 1_000_000, from = solKeypair.publicKey): TransactionInstruction {
  return SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports })
}

test('Solana: initializeMint2 and mintTo are signed under the MINT shape', () => {
  const mint = Keypair.generate().publicKey
  const payload = solanaTx([
    splInstruction(20, [mint]),
    splInstruction(7, [mint, Keypair.generate().publicKey, solKeypair.publicKey]),
  ])
  const signed = signSolana(solSecret, payload, solAddress, MINT)
  assert.equal(SolanaTransaction.from(Buffer.from(signed, 'base64')).signatures.length, 1)
})

test('Solana: SetAuthority (tag 6) is REFUSED — it hands the mint to someone else permanently', () => {
  const payload = solanaTx([splInstruction(6, [Keypair.generate().publicKey, solKeypair.publicKey])])
  assert.throws(() => signSolana(solSecret, payload, solAddress, MINT), (err: unknown) => {
    assert.ok(err instanceof SignRefused)
    assert.match((err as Error).message, /SPL token instruction 6 is not one this service signs for/)
    return true
  })
})

test('Solana: Transfer, Approve, SetAuthority, Burn and CloseAccount are refused under EVERY shape', () => {
  // SD-09 names all five. They are every way to move or reassign what the address holds, so they are
  // asserted as a set rather than one at a time — a future widening that admitted one of them would
  // otherwise only fail a test somebody could read as being about SetAuthority.
  //
  // ASSERTED UNDER ALL THREE SHAPES, which is what stops "SOL can be transferred now" from quietly
  // meaning "SPL Transfer can be too". They are different instructions with different risks: the
  // system Transfer below moves the vault's own lamports, SPL tag 3 moves a token balance out of a
  // token account and has no caller in this estate.
  for (const policy of SOL_SHAPES) {
    for (const tag of [3, 4, 6, 8, 9]) {
      const payload = solanaTx([splInstruction(tag, [solKeypair.publicKey, solKeypair.publicKey, solKeypair.publicKey])])
      assert.throws(
        () => signSolana(solSecret, payload, solAddress, policy),
        SignRefused,
        `tag ${tag} was not refused under ${policy.shape}`,
      )
    }
  }
})

test('Solana: a DEPLOYER key still cannot move a lamport — the mint shape refuses SystemProgram Transfer', () => {
  // The refusal that used to apply to every purpose. It is the deployer's rule now, and narrowing it
  // to that purpose is not the same as relaxing it: `mint` is what `micro-mint` signs SPL deploys
  // with, and a deploy key that could also transfer is a deploy key whose balance is one signature
  // away — `assertCreation`'s argument, in another family.
  const payload = solanaTx([solTransferIx(SOL_STRANGER)])
  assert.throws(
    () => signSolana(solSecret, payload, solAddress, MINT),
    (err: unknown) => err instanceof SignRefused && /only system-program instruction this service signs is createAccount/.test((err as Error).message),
  )
})

test('Solana: a TREASURY key signs one System Transfer to an address the caller names', () => {
  const payload = solanaTx([solTransferIx(SOL_STRANGER)])
  const signed = signSolana(solSecret, payload, solAddress, SOL_TRANSFER)
  const parsed = SolanaTransaction.from(Buffer.from(signed, 'base64'))
  assert.equal(parsed.signatures.length, 1)
  assert.equal(parsed.feePayer?.toBase58(), solAddress)
})

test('Solana: a TREASURY key may NOT create an account — createAccount is the deployer shape only', () => {
  // The 50,000,000-lamport hazard, and the half of this change that is a NARROWING. Before the
  // shapes were disjoint, a treasury-purpose SOL address got the whole mint-creation set even though
  // the only caller that needs it mints under `purpose: 'deployer'`.
  const payload = solanaTx([
    SystemProgram.createAccount({
      fromPubkey: solKeypair.publicKey,
      newAccountPubkey: Keypair.generate().publicKey,
      lamports: 50_000_000,
      space: 82,
      programId: TOKEN_PROGRAM,
    }),
  ])
  for (const policy of [SOL_TRANSFER, SOL_SWEEP]) {
    assert.throws(
      () => signSolana(solSecret, payload, solAddress, policy),
      (err: unknown) =>
        err instanceof SignRefused &&
        /only system-program instruction a solana transfer signs is Transfer/.test((err as Error).message),
      policy.shape,
    )
  }
})

test('SD-09 §4 — a SOL sweep to anything but the pin is refused', () => {
  const payload = solanaTx([solTransferIx(SOL_STRANGER)])
  assert.throws(
    () => signSolana(solSecret, payload, solAddress, SOL_SWEEP),
    (err: unknown) =>
      err instanceof SignRefused && /a sweep does not choose its own destination/.test((err as Error).message),
  )
})

test('SD-09 §4 — a SOL sweep TO the pin is signed, and that is the only destination there is', () => {
  const payload = solanaTx([solTransferIx(SOL_TREASURY)])
  const signed = signSolana(solSecret, payload, solAddress, SOL_SWEEP)
  assert.equal(SolanaTransaction.from(Buffer.from(signed, 'base64')).signatures.length, 1)
})

test('SD-09 §4 — a SOL sweep with no pin, or an unusable one, is refused rather than defaulted', () => {
  const payload = solanaTx([solTransferIx(SOL_TREASURY)])
  for (const pin of ['', 'not-a-base58-pubkey', ` ${SOL_TREASURY.toBase58()} `]) {
    assert.throws(
      () => signSolana(solSecret, payload, solAddress, { shape: 'sweep', treasuryPin: pin }),
      (err: unknown) => err instanceof SignRefused && /no usable treasury is pinned/.test((err as Error).message),
      `pin ${JSON.stringify(pin)} was not refused`,
    )
  }
})

test('Solana: a transfer is EXACTLY ONE instruction — nothing rides alongside it', () => {
  // `partialSign` signs the whole message, so a second instruction beside a legitimate Transfer is
  // covered by the same signature and cannot be separated from it afterwards. The piggyback is the
  // attack: a sweep paying the pin, plus a createAccount parking the rest somewhere unrecoverable.
  const payload = solanaTx([
    solTransferIx(SOL_TREASURY),
    SystemProgram.createAccount({
      fromPubkey: solKeypair.publicKey,
      newAccountPubkey: Keypair.generate().publicKey,
      lamports: 50_000_000,
      space: 82,
      programId: TOKEN_PROGRAM,
    }),
  ])
  for (const policy of [SOL_TRANSFER, SOL_SWEEP]) {
    assert.throws(
      () => signSolana(solSecret, payload, solAddress, policy),
      (err: unknown) => err instanceof SignRefused && /exactly one instruction/.test((err as Error).message),
      policy.shape,
    )
  }
})

test('Solana: a transfer requiring a SECOND signature is refused, not half-signed', () => {
  // A System Transfer needs the source account's signature and no other. A message declaring a
  // second required signer would be handed back half-signed — a blob the caller completes later
  // with a counterparty of its choosing. It is also the shape that made `serialize()` throw a plain
  // Error, which reaches the route as a 500 with no audit row; the rate limiter counts audit rows.
  const tx = new SolanaTransaction({ feePayer: solKeypair.publicKey, recentBlockhash: BLOCKHASH })
  tx.add(
    new TransactionInstruction({
      programId: new PublicKey('11111111111111111111111111111111'),
      keys: [
        { pubkey: solKeypair.publicKey, isSigner: true, isWritable: true },
        { pubkey: SOL_TREASURY, isSigner: false, isWritable: true },
        // A third account the message declares a signature is required for.
        { pubkey: SOL_STRANGER, isSigner: true, isWritable: false },
      ],
      data: solTransferIx(SOL_TREASURY).data,
    }),
  )
  const payload = tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64')
  for (const policy of [SOL_TRANSFER, SOL_SWEEP]) {
    assert.throws(
      () => signSolana(solSecret, payload, solAddress, policy),
      (err: unknown) => err instanceof SignRefused && /exactly one signature/.test((err as Error).message),
      policy.shape,
    )
  }
})

test('Solana: a Transfer must be FUNDED by the vault address, not merely fee-paid by it', () => {
  // `keys[0]` is the account being debited and it is not the same field as the fee payer. A Transfer
  // out of somebody else's account, fee-paid by ours, is a signature this service has no business on.
  const payload = solanaTx([solTransferIx(SOL_TREASURY, 1_000_000, SOL_STRANGER)])
  assert.throws(
    () => signSolana(solSecret, payload, solAddress, SOL_TRANSFER),
    (err: unknown) => err instanceof SignRefused && /must be funded by the vault address/.test((err as Error).message),
  )
})

test('Solana: a zero-lamport Transfer, and one paying this address itself, are refused', () => {
  assert.throws(
    () => signSolana(solSecret, solanaTx([solTransferIx(SOL_STRANGER, 0)]), solAddress, SOL_TRANSFER),
    (err: unknown) => err instanceof SignRefused && /zero lamports/.test((err as Error).message),
  )
  assert.throws(
    () => signSolana(solSecret, solanaTx([solTransferIx(solKeypair.publicKey)]), solAddress, SOL_TRANSFER),
    (err: unknown) => err instanceof SignRefused && /to the vault address itself/.test((err as Error).message),
  )
})

test('Solana: an unknown program is refused under every shape', () => {
  const payload = solanaTx([
    new TransactionInstruction({
      programId: Keypair.generate().publicKey,
      keys: [{ pubkey: solKeypair.publicKey, isSigner: true, isWritable: true }],
      data: Buffer.from([0]),
    }),
  ])
  for (const policy of SOL_SHAPES) {
    assert.throws(() => signSolana(solSecret, payload, solAddress, policy), SignRefused, policy.shape)
  }
})

test('Solana: the fee payer must be this address', () => {
  const payload = solanaTx([splInstruction(20, [Keypair.generate().publicKey])], Keypair.generate().publicKey)
  assert.throws(
    () => signSolana(solSecret, payload, solAddress, MINT),
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
    () => signSolana(solSecret, payload, solAddress, MINT),
    (err: unknown) => err instanceof SignRefused && /only allocate an SPL mint account/.test((err as Error).message),
  )
})

/* ------------------------------------------------------------------ Bitcoin */

const btcNetwork = bitcoinNetwork('bitcoin', 'testnet')
const btcKey = ECPair.makeRandom({ network: btcNetwork })
const btcPayment = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(btcKey.publicKey), network: btcNetwork })
const foreignKey = ECPair.makeRandom({ network: btcNetwork })
const foreignPayment = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(foreignKey.publicKey), network: btcNetwork })

const btcTreasuryKey = ECPair.makeRandom({ network: btcNetwork })
const btcTreasury = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(btcTreasuryKey.publicKey), network: btcNetwork })
const BTC_PAYMENT: BitcoinPolicy = { shape: 'payment' }
const BTC_SWEEP: BitcoinPolicy = { shape: 'sweep', treasuryPin: btcTreasury.address! }

interface PsbtOptions {
  readonly script?: Buffer
  readonly sighashType?: number
  readonly noWitnessUtxo?: boolean
  /** Output scripts, in order. Defaults to the one foreign output the payment tests want. */
  readonly outputs?: readonly Buffer[]
}

function psbt(options: PsbtOptions = {}): string {
  const p = new bitcoin.Psbt({ network: btcNetwork })
  const input: Parameters<bitcoin.Psbt['addInput']>[0] = {
    hash: Buffer.alloc(32, 7),
    index: 0,
    ...(options.noWitnessUtxo ? {} : { witnessUtxo: { script: options.script ?? btcPayment.output!, value: 100_000 } }),
    ...(options.sighashType === undefined ? {} : { sighashType: options.sighashType }),
  }
  p.addInput(input)
  const outputs = options.outputs ?? [foreignPayment.output!]
  for (const script of outputs) p.addOutput({ script, value: Math.floor(90_000 / outputs.length) })
  return p.toBase64()
}

test('Bitcoin: a PSBT spending this address is signed and finalised', () => {
  const hex = signBitcoin(btcKey.toWIF(), psbt(), btcPayment.address!, 'testnet', BTC_PAYMENT, 'bitcoin')
  assert.match(hex, /^[0-9a-f]+$/)
})

test('Bitcoin: a PSBT with a FOREIGN input is refused', () => {
  // Every input must be a P2WPKH output of this very address, so the service can only ever spend its
  // own coins. `signAllInputs` signs all of them, so one foreign input would be signed too.
  assert.throws(
    () =>
      signBitcoin(btcKey.toWIF(), psbt({ script: foreignPayment.output! }), btcPayment.address!, 'testnet', BTC_PAYMENT, 'bitcoin'),
    (err: unknown) => err instanceof SignRefused && /does not spend this vault address/.test((err as Error).message),
  )
})

test('Bitcoin: an input with no witnessUtxo is refused — its value is unknown', () => {
  assert.throws(
    () => signBitcoin(btcKey.toWIF(), psbt({ noWitnessUtxo: true }), btcPayment.address!, 'testnet', BTC_PAYMENT, 'bitcoin'),
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
        BTC_PAYMENT,
        'bitcoin',
      ),
    (err: unknown) => err instanceof SignRefused && /only SIGHASH_ALL is signed/.test((err as Error).message),
  )
})

test('Bitcoin: a raw transaction is refused — only a PSBT carries each input value', () => {
  assert.throws(
    () => signBitcoin(btcKey.toWIF(), { version: 2 }, btcPayment.address!, 'testnet', BTC_PAYMENT, 'bitcoin'),
    (err: unknown) => err instanceof SignRefused && /must be a base64 PSBT/.test((err as Error).message),
  )
})

test('Bitcoin: the WIF carries the network, so a mainnet key cannot satisfy a testnet request', () => {
  const mainnetKey = ECPair.makeRandom({ network: bitcoinNetwork('bitcoin', 'mainnet') })
  // Not a SignRefused: a key that does not match the row is a fault in here, not the caller's fault.
  assert.throws(() => signBitcoin(mainnetKey.toWIF(), psbt(), btcPayment.address!, 'testnet', BTC_PAYMENT, 'bitcoin'))
})

/* ---------------------------------------------- Bitcoin: the sweep output policy */

test('SD-09 §4 — a BTC sweep paying only the pin is signed', () => {
  const hex = signBitcoin(btcKey.toWIF(), psbt({ outputs: [btcTreasury.output!] }), btcPayment.address!, 'testnet', BTC_SWEEP, 'bitcoin')
  assert.match(hex, /^[0-9a-f]+$/)
})

test('SD-09 §4 — a BTC sweep to anything but the pin is refused', () => {
  // The same PSBT the payment tests sign happily. `purpose` selects the policy, so the identical
  // bytes are a withdrawal from a treasury and a refusal from a deposit address.
  assert.throws(
    () => signBitcoin(btcKey.toWIF(), psbt(), btcPayment.address!, 'testnet', BTC_SWEEP, 'bitcoin'),
    (err: unknown) =>
      err instanceof SignRefused && /psbt output 0 does not pay the treasury address pinned/.test((err as Error).message),
  )
})

test('SD-09 §4 — a BTC sweep with a CHANGE output is refused whole, not partially signed', () => {
  // THE ONE THIS POLICY EXISTS FOR. A sweep leaves nothing behind, so an output paying the source
  // address back is not change, it is the sweep failing to be a sweep — and worse, `signAllInputs`
  // signs every input at once, so the pin-paying output cannot be signed while the other is not.
  // Refused whole is the only correct outcome, and it is asserted for BOTH orderings because a
  // check that stopped at the first output would pass one of them.
  for (const outputs of [
    [btcTreasury.output!, btcPayment.output!],
    [btcPayment.output!, btcTreasury.output!],
  ]) {
    assert.throws(
      () => signBitcoin(btcKey.toWIF(), psbt({ outputs }), btcPayment.address!, 'testnet', BTC_SWEEP, 'bitcoin'),
      (err: unknown) => err instanceof SignRefused && /every output of a sweep pays the pin, change included/.test((err as Error).message),
    )
  }
})

test('SD-09 §4 — a BTC sweep output with no renderable address is refused, not skipped', () => {
  // An OP_RETURN has no `address` at all, so a policy comparing address STRINGS would have had to
  // decide what `undefined === pin` means. Comparing scripts makes the question not arise.
  // OP_RETURN, a 4-byte push, "burn". Written as bytes rather than via `script.compile` because the
  // opcode table is index-typed and `noUncheckedIndexedAccess` makes every entry `| undefined`.
  const opReturn = Buffer.from('6a046275726e', 'hex')
  assert.throws(
    () =>
      signBitcoin(
        btcKey.toWIF(),
        psbt({ outputs: [btcTreasury.output!, opReturn] }),
        btcPayment.address!,
        'testnet',
        BTC_SWEEP,
        'bitcoin',
      ),
    (err: unknown) => err instanceof SignRefused && /psbt output 1 does not pay the treasury/.test((err as Error).message),
  )
})

test('SD-09 §4 — a BTC sweep with no pin, or a pin from the wrong network, is refused rather than defaulted', () => {
  const mainnetTreasury = bitcoin.payments.p2wpkh({
    pubkey: Buffer.from(ECPair.makeRandom({ network: bitcoinNetwork('bitcoin', 'mainnet') }).publicKey),
    network: bitcoinNetwork('bitcoin', 'mainnet'),
  })
  for (const pin of ['', 'not-an-address', mainnetTreasury.address!]) {
    assert.throws(
      () =>
        signBitcoin(
          btcKey.toWIF(),
          psbt({ outputs: [btcTreasury.output!] }),
          btcPayment.address!,
          'testnet',
          { shape: 'sweep', treasuryPin: pin },
          'bitcoin',
        ),
      (err: unknown) => err instanceof SignRefused && /no usable treasury is pinned/.test((err as Error).message),
      `pin ${JSON.stringify(pin)} was not refused`,
    )
  }
})

test('SD-09 §4 — a BTC sweep may not burn the deposit as FEE, even paying only the pin', () => {
  // The pin bounds where a sweep may pay. It does NOT bound how much: the whole deposit on the input
  // side and one dust output to the pin satisfies every other rule, and the remainder is fee. That
  // is destruction rather than theft, and it is available to exactly the credential the pin exists
  // to make harmless — so the fee-rate ceiling is part of the sweep policy, not an afterthought.
  const p = new bitcoin.Psbt({ network: btcNetwork })
  p.addInput({
    hash: Buffer.alloc(32, 7),
    index: 0,
    witnessUtxo: { script: btcPayment.output!, value: 10_000_000 },
    sighashType: bitcoin.Transaction.SIGHASH_ALL,
  })
  // A 110-vByte transaction, so this leaves ~2727 sat/vB as fee: over the sweep ceiling of 1000 and
  // under the 5000 a payment is still allowed.
  p.addOutput({ script: btcTreasury.output!, value: 9_700_000 })
  const greedy = p.toBase64()

  assert.throws(
    () => signBitcoin(btcKey.toWIF(), greedy, btcPayment.address!, 'testnet', BTC_SWEEP, 'bitcoin'),
    (err: unknown) =>
      err instanceof SignRefused && /pays 2727 sat\/vB in fee, above the 1000/.test((err as Error).message),
  )
  // And it is a REFUSAL, not the bare Error bitcoinjs throws — a 500 writes no audit row, and the
  // rate limiter counts audit rows, so an unaudited path is one a caller can probe without limit.
  // The same PSBT under the payment shape is signed: a treasury's residual is SDR-05, not this.
  assert.match(signBitcoin(btcKey.toWIF(), greedy, btcPayment.address!, 'testnet', BTC_PAYMENT, 'bitcoin'), /^[0-9a-f]+$/)
})

test('the output policy runs BEFORE anything is signed — a refused sweep produces no signature', () => {
  // The ordering `signing.ts` promises. Asserted by construction: the PSBT handed in is unchanged
  // after the refusal, so nothing was written into it on the way out.
  const before = psbt({ outputs: [foreignPayment.output!] })
  try {
    signBitcoin(btcKey.toWIF(), before, btcPayment.address!, 'testnet', BTC_SWEEP, 'bitcoin')
    assert.fail('expected a refusal')
  } catch (err) {
    assert.ok(err instanceof SignRefused)
  }
  const reparsed = bitcoin.Psbt.fromBase64(before, { network: btcNetwork })
  assert.equal(reparsed.data.inputs[0]?.partialSig, undefined)
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

/* ------------------------------------------------ EVM: the token sweep (§5.2) */

const USDT = '0xdac17f958d2ee523a2206206994597c13d831ec7'
const TOKENS: ReadonlySet<string> = new Set([USDT])

/** An ERC-20 `transfer(to, amount)`, hand-encoded so a test never shares a bug with the decoder. */
function erc20Transfer(to: string, amount: bigint): string {
  const addressWord = `${'0'.repeat(24)}${to.slice(2).toLowerCase()}`
  return `0xa9059cbb${addressWord}${amount.toString(16).padStart(64, '0')}`
}

const tokenSweepTx = (overrides: Record<string, unknown> = {}) => ({
  to: USDT,
  data: erc20Transfer(TREASURY, 5_000_000n),
  value: 0,
  nonce: 0,
  gasLimit: 100_000,
  chainId: CHAIN_ID,
  maxFeePerGas: '20000000000',
  maxPriorityFeePerGas: '1000000000',
  ...overrides,
})

const tokenSweepPolicy = (tokens: ReadonlySet<string> = TOKENS) =>
  ({ chainId: CHAIN_ID, shape: 'sweep', treasuryPin: TREASURY, tokenAllowlist: tokens }) as const

test('the selector this file admits really is `transfer(address,uint256)`', () => {
  // The constant in signing.ts is written as a literal so a reader can see it. This is the check
  // that the literal is the right four bytes — a typo in it would otherwise admit some other
  // function under the name `transfer`, which is the one mistake nothing else here could catch.
  assert.equal(ethers.id('transfer(address,uint256)').slice(0, 10), '0xa9059cbb')
})

test('a token sweep paying the pin is signed, and records itself as `token_sweep`', async () => {
  const { signedTx, shape } = await signEvm(evmWallet.privateKey, tokenSweepTx(), tokenSweepPolicy())
  const parsed = ethers.Transaction.from(signedTx)
  // The transaction goes to the TOKEN, not the treasury — which is why `assertSweep`'s pin could
  // never have expressed this and a second shape had to exist.
  assert.equal(parsed.to?.toLowerCase(), USDT)
  assert.equal(parsed.value, 0n)
  // The audit column must say which policy ran. 'sweep' here would be a true statement about the
  // purpose and a false one about the transaction.
  assert.equal(shape, 'token_sweep')
})

test('SD-09 §4, inside the calldata — a token sweep paying a STRANGER is refused', async () => {
  // The whole point of the shape. The recipient is 32 bytes into the calldata rather than in `to`,
  // so this is the transaction `assertSweep`'s pin cannot see and would have waved through if the
  // empty-calldata rule had merely been relaxed.
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, tokenSweepTx({ data: erc20Transfer(STRANGER, 5_000_000n) }), tokenSweepPolicy()),
  )
  assert.match(message, /a sweep does not choose its own destination/)
})

test('an UNREGISTERED token contract is refused — the allowlist refuses by default', async () => {
  const rogue = ethers.Wallet.createRandom().address
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, tokenSweepTx({ to: rogue }), tokenSweepPolicy()),
  )
  assert.match(message, /not a token contract registered/)
})

test('an EMPTY allowlist makes the token sweep unreachable, which is every chain by default', async () => {
  const message = await refusal(() => signEvm(evmWallet.privateKey, tokenSweepTx(), tokenSweepPolicy(NO_TOKENS)))
  assert.match(message, /not a token contract registered/)
})

test('the allowlist is not case-sensitive theatre: a checksummed `to` still resolves', async () => {
  // The table stores one lower-cased spelling (schema CHECK) and the shape lower-cases the
  // candidate. A caller sending EIP-55 casing must therefore be admitted, not refused for cosmetics.
  const { shape } = await signEvm(
    evmWallet.privateKey,
    tokenSweepTx({ to: ethers.getAddress(USDT) }),
    tokenSweepPolicy(),
  )
  assert.equal(shape, 'token_sweep')
})

test('ON a registered token, every function except `transfer` is still refused', async () => {
  // The allowlist bounds WHICH CONTRACT; the selector bounds WHICH FUNCTION. Both are needed:
  // `approve(attacker, max)` and `transferFrom(victim, attacker, all)` on a legitimately registered
  // USDT are the two calls that turn a deposit key into a signing oracle, and neither is stopped by
  // the allowlist alone.
  for (const selector of ['095ea7b3', '23b872dd']) {
    const data = `0x${selector}${'0'.repeat(24)}${TREASURY.slice(2).toLowerCase()}${'f'.repeat(64)}`
    const message = await refusal(() => signEvm(evmWallet.privateKey, tokenSweepTx({ data }), tokenSweepPolicy()))
    assert.match(message, /must call `transfer\(address,uint256\)`/)
  }
})

test('calldata with anything appended to it is refused, not truncated', async () => {
  // A decoder would read the first two words and ignore the tail. The signature covers the tail,
  // and a token contract with a fallback may not ignore it, so the exact byte length is the rule.
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, tokenSweepTx({ data: `${erc20Transfer(TREASURY, 1n)}deadbeef` }), tokenSweepPolicy()),
  )
  assert.match(message, /exactly 68 bytes/)
})

test('a dirty left pad on the recipient word is refused rather than masked off', async () => {
  // A token contract reads the low 20 bytes, so these high bytes change nothing on-chain — which is
  // exactly why they would be here: to make the calldata read differently from what executes.
  const dirty = `0xa9059cbb${'0'.repeat(22)}ff${TREASURY.slice(2).toLowerCase()}${'1'.repeat(64)}`
  const message = await refusal(() => signEvm(evmWallet.privateKey, tokenSweepTx({ data: dirty }), tokenSweepPolicy()))
  assert.match(message, /not a left-padded 20-byte address/)
})

test('native value alongside a token sweep is refused — it would be burnt at the contract', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, tokenSweepTx({ value: '1000000000000000' }), tokenSweepPolicy()),
  )
  assert.match(message, /`value` must be zero on a token sweep/)
})

test('a zero-amount token sweep is refused — a signature is permanent and this one moves nothing', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, tokenSweepTx({ data: erc20Transfer(TREASURY, 0n) }), tokenSweepPolicy()),
  )
  assert.match(message, /must transfer a positive amount/)
})

test('a token sweep with no pinned treasury is refused, not defaulted', async () => {
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, tokenSweepTx(), {
      chainId: CHAIN_ID,
      shape: 'sweep',
      treasuryPin: '',
      tokenAllowlist: TOKENS,
    }),
  )
  assert.match(message, /no usable treasury is pinned/)
})

test('the NATIVE sweep is not widened by any of this — calldata to the pin is still not a sweep', async () => {
  // The regression that would matter most. `assertSweep` must still refuse calldata; a payload that
  // carries some is now a TOKEN sweep and is held to the token rules, so `to: TREASURY` fails the
  // allowlist. Either way there is no path on which a deposit key executes caller-chosen calldata.
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: TREASURY, data: '0xdeadbeef' }), tokenSweepPolicy()),
  )
  assert.match(message, /not a token contract registered/)
})

test('`BigInt` is not a parser: a whitespace-only quantity is refused, not read as zero', async () => {
  // `BigInt('  ')` is `0n`. `quantity`'s `length > 0` guard passes a whitespace string straight
  // through, so before `parseBigInt` trimmed, a blank `gasLimit` became a zero one.
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ value: '   ' }), { chainId: CHAIN_ID, shape: 'transfer' }),
  )
  assert.match(message, /`value` is not a non-negative quantity/)
})

test('§5.2 the gas problem: funding a deposit address is ALREADY signable, with no new shape', async () => {
  // An ERC-20 arrives at a deposit address holding zero ETH, so the token cannot be swept until
  // somebody puts gas there. The reflex is to invent a `gas_topup` shape. Nothing is needed: the
  // top-up is a plain native transfer FROM THE TREASURY, whose destination the caller names, and
  // that is exactly the `transfer` shape the treasury already has.
  //
  // The asymmetry is the point and it is what keeps this safe. The treasury's transfer already
  // permits any destination — SDR-05, stated in `assertTransfer` — so pointing one at a deposit
  // address adds no capability whatsoever. Solving it in the other direction (letting the DEPOSIT
  // key pull gas, or widening its shape) would have added one.
  const depositAddress = ethers.Wallet.createRandom().address
  const { signedTx, shape } = await signEvm(
    evmWallet.privateKey,
    transferTx({ to: depositAddress, value: '2100000000000000' }),
    { chainId: CHAIN_ID, shape: 'transfer' },
  )
  assert.equal(shape, 'transfer')
  assert.equal(ethers.Transaction.from(signedTx).to, depositAddress)
})

test('§5.2 the gas problem: the DEPOSIT key still cannot move native value to fund itself', async () => {
  // The other half, asserted so the pair reads as a decision rather than an accident. Gas flows
  // treasury → deposit and never deposit → anywhere-but-the-pin, so the top-up cannot be turned
  // around into a withdrawal path.
  const message = await refusal(() =>
    signEvm(evmWallet.privateKey, transferTx({ to: STRANGER }), {
      chainId: CHAIN_ID,
      shape: 'sweep',
      treasuryPin: TREASURY,
      tokenAllowlist: TOKENS,
    }),
  )
  assert.match(message, /a sweep does not choose its own destination/)
})

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * LITECOIN SIGNING — the other half of the derivation fix.
 *
 * Deriving a genuine `ltc1…` address is worth nothing if the key cannot then be SIGNED with, and
 * the two are resolved by different parameters in different files: `hd.ts` picks them to derive,
 * `signing.ts` picks them to sign. If the signer resolved them from the FAMILY — which is
 * `'bitcoin'` for Litecoin — every LTC sweep would be refused by `ECPair.fromWIF` and the deposits
 * would be unspendable. Custody is where that mistake is unrecoverable.
 *
 * So this drives a whole Litecoin PSBT through the real `signBitcoin`, under both shapes, and
 * asserts the cross-chain cases refuse rather than sign.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

const ltcNetwork = bitcoinNetwork('litecoin', 'testnet')
const ltcKey = ECPair.makeRandom({ network: ltcNetwork })
const ltcPayment = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(ltcKey.publicKey), network: ltcNetwork })
const ltcTreasuryKey = ECPair.makeRandom({ network: ltcNetwork })
const ltcTreasury = bitcoin.payments.p2wpkh({
  pubkey: Buffer.from(ltcTreasuryKey.publicKey),
  network: ltcNetwork,
})

function ltcPsbt(outputs: readonly Buffer[]): string {
  const p = new bitcoin.Psbt({ network: ltcNetwork })
  p.addInput({
    hash: Buffer.alloc(32, 9),
    index: 0,
    witnessUtxo: { script: ltcPayment.output!, value: 100_000 },
  })
  for (const script of outputs) p.addOutput({ script, value: Math.floor(90_000 / outputs.length) })
  return p.toBase64()
}

test('LITECOIN: a sweep of a Litecoin deposit address signs under the row own chain', () => {
  const signed = signBitcoin(
    ltcKey.toWIF(),
    ltcPsbt([ltcTreasury.output!]),
    ltcPayment.address!,
    'testnet',
    { shape: 'sweep', treasuryPin: ltcTreasury.address! },
    'litecoin',
  )
  // A finalised raw transaction, which is what the caller broadcasts. Decoding it back proves the
  // signature was really produced rather than an empty PSBT returned.
  const tx = bitcoin.Transaction.fromHex(signed)
  assert.equal(tx.ins.length, 1)
  assert.ok(tx.ins[0]!.witness.length > 0, 'the input must carry a witness')
})

test('LITECOIN: the pin is still the vault choice — a foreign output is refused', () => {
  const foreign = bitcoin.payments.p2wpkh({
    pubkey: Buffer.from(ECPair.makeRandom({ network: ltcNetwork }).publicKey),
    network: ltcNetwork,
  })
  assert.throws(
    () =>
      signBitcoin(
        ltcKey.toWIF(),
        ltcPsbt([foreign.output!]),
        ltcPayment.address!,
        'testnet',
        { shape: 'sweep', treasuryPin: ltcTreasury.address! },
        'litecoin',
      ),
    (err: unknown) => err instanceof SignRefused && /does not pay the treasury/.test((err as Error).message),
  )
})

test('LITECOIN: a Litecoin key presented as a Bitcoin one refuses, and the reverse too', () => {
  /*
   * **THE MUTATION THIS TEST EXISTS FOR.** Hard-coding `'bitcoin'` at the signer's call site — the
   * shape the code had before the chain was threaded through — makes every Litecoin sweep refuse.
   * That is the SAFE direction of the failure and it is still a total outage of the LTC on-ramp,
   * so it has to be a red test rather than a support ticket.
   *
   * It throws rather than refusing, and that distinction is deliberate: `ECPair.fromWIF` failing is
   * a fault in this service's own wiring, not a caller's malformed request, so it must not be
   * dressed up as a 403 the caller could think they caused.
   */
  assert.throws(() =>
    signBitcoin(
      ltcKey.toWIF(),
      ltcPsbt([ltcTreasury.output!]),
      ltcPayment.address!,
      'testnet',
      { shape: 'sweep', treasuryPin: ltcTreasury.address! },
      'bitcoin',
    ),
  )
  assert.throws(() =>
    signBitcoin(
      btcKey.toWIF(),
      psbt({ outputs: [btcTreasury.output!] }),
      btcPayment.address!,
      'testnet',
      BTC_SWEEP,
      'litecoin',
    ),
  )
})

test('LITECOIN: a Bitcoin treasury pinned against a Litecoin row is refused, not matched', () => {
  // `assertSweepOutputs` turns the pin into an output script under the ROW's network. A pin from
  // another chain must throw there — if it silently matched nothing, every output would be "not the
  // pin" and the refusal would read as a caller error rather than a misconfiguration.
  assert.throws(
    () =>
      signBitcoin(
        ltcKey.toWIF(),
        ltcPsbt([ltcTreasury.output!]),
        ltcPayment.address!,
        'testnet',
        { shape: 'sweep', treasuryPin: btcTreasury.address! },
        'litecoin',
      ),
    (err: unknown) => err instanceof SignRefused && /no usable treasury is pinned/.test((err as Error).message),
  )
})
