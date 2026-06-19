import { modInverse, modPow, randomBigInt, randomCoprime } from './numbers'
import type { PaillierPublicKey } from './paillier'

/**
 * Zero-knowledge proof that a Paillier ciphertext encrypts either 0 or 1 —
 * without revealing which. This is the missing ingredient that turns the
 * voting demo from "trust the voter" into a real protocol: a malicious voter
 * cannot stuff the ballot box by encrypting 5, because the tally only accepts
 * ciphertexts that come with a valid 0/1 proof.
 *
 * Construction: a Cramer–Damgård–Schoenmakers (CDS) OR-composition of two
 * Σ-protocols. Each branch proves "c · g^(-v) is an N-th residue" (i.e. equals
 * r^N), which holds exactly when the plaintext is v. The prover runs the real
 * branch honestly and simulates the other, so a verifier cannot tell which of
 * {0, 1} is the true value. Made non-interactive with Fiat–Shamir.
 */
export interface BitProof {
  a0: bigint
  a1: bigint
  e0: bigint
  e1: bigint
  z0: bigint
  z1: bigint
}

/**
 * Challenge bound A. For special soundness the challenge must be smaller than
 * the smallest prime factor of N, so we cap it at 2^(bits(N)/2 - 1) — always
 * below p and q — and at 2^256 for large keys where that is plenty.
 */
export function challengeBound(pub: PaillierPublicKey): bigint {
  const t = Math.min(256, Math.max(1, Math.floor(pub.bitLength / 2) - 1))
  return 1n << BigInt(t)
}

/**
 * Soundness error of a single proof: the probability a cheating prover slips a
 * non-bit past the verifier, ≈ 1/A. Negligible for real keys, but visibly
 * non-zero in TOY mode — a concrete lesson in why challenge spaces are large.
 */
export function soundnessError(pub: PaillierPublicKey): { bound: bigint; oneIn: bigint } {
  const bound = challengeBound(pub)
  return { bound, oneIn: bound }
}

/** Uniform random value in [0, bound). */
function randomBelow(bound: bigint): bigint {
  if (bound <= 1n) {
    return 0n
  }
  return randomBigInt(bound + 1n) - 1n
}

/** u_v = c · g^(-v) mod N^2. Equals r^N iff the plaintext is v. */
function residueTarget(ciphertext: bigint, v: bigint, pub: PaillierPublicKey): bigint {
  const { N2, g } = pub
  const gv = modPow(g, v, N2)
  return (ciphertext * modInverse(gv, N2)) % N2
}

/** Fiat–Shamir challenge: SHA-256 over the transcript, reduced mod the bound. */
async function fiatShamir(values: bigint[], bound: bigint): Promise<bigint> {
  const encoded = new TextEncoder().encode(values.map((v) => v.toString(16)).join('|'))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoded))
  let h = 0n
  for (const byte of digest) {
    h = (h << 8n) | BigInt(byte)
  }
  return h % bound
}

/**
 * Prove that `ciphertext` encrypts `realBranch` (0 or 1), using the encryption
 * randomness `r` (where ciphertext = g^realBranch · r^N mod N^2) as the witness.
 * If the ciphertext does not actually encrypt `realBranch`, the resulting proof
 * will fail verification — that is the soundness guarantee in action.
 */
export async function proveBit(
  realBranch: 0 | 1,
  ciphertext: bigint,
  r: bigint,
  pub: PaillierPublicKey,
): Promise<BitProof> {
  const { N, N2 } = pub
  const A = challengeBound(pub)

  const u = [residueTarget(ciphertext, 0n, pub), residueTarget(ciphertext, 1n, pub)]
  const fake = (realBranch ^ 1) as 0 | 1

  // Simulate the branch we do NOT have a witness for: pick its challenge and
  // response first, then back out a commitment that makes the check pass.
  const eFake = randomBelow(A)
  const zFake = randomCoprime(N)
  const aFake = (modPow(zFake, N, N2) * modInverse(modPow(u[fake], eFake, N2), N2)) % N2

  // Run the real branch honestly: commit to s^N before learning the challenge.
  const s = randomCoprime(N)
  const aReal = modPow(s, N, N2)

  const a: bigint[] = []
  a[realBranch] = aReal
  a[fake] = aFake

  // Fiat–Shamir over (N, c, a0, a1); split so e0 + e1 = e (mod A).
  const e = await fiatShamir([N, ciphertext, a[0], a[1]], A)
  const eReal = (((e - eFake) % A) + A) % A
  const zReal = (s * modPow(r, eReal, N)) % N

  const eArr: bigint[] = []
  eArr[realBranch] = eReal
  eArr[fake] = eFake
  const zArr: bigint[] = []
  zArr[realBranch] = zReal
  zArr[fake] = zFake

  return { a0: a[0], a1: a[1], e0: eArr[0], e1: eArr[1], z0: zArr[0], z1: zArr[1] }
}

/**
 * Verify a 0/1 proof against a ciphertext and public key. Learns nothing about
 * the plaintext beyond "it is 0 or 1".
 */
export async function verifyBit(
  proof: BitProof,
  ciphertext: bigint,
  pub: PaillierPublicKey,
): Promise<boolean> {
  const { N2 } = pub
  const A = challengeBound(pub)
  const u = [residueTarget(ciphertext, 0n, pub), residueTarget(ciphertext, 1n, pub)]

  const e = await fiatShamir([pub.N, ciphertext, proof.a0, proof.a1], A)
  if (((proof.e0 + proof.e1) % A) !== e) {
    return false
  }

  const check0 = modPow(proof.z0, pub.N, N2) === (proof.a0 * modPow(u[0], proof.e0, N2)) % N2
  const check1 = modPow(proof.z1, pub.N, N2) === (proof.a1 * modPow(u[1], proof.e1, N2)) % N2
  return check0 && check1
}
