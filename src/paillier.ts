import {
  gcd,
  generatePrime,
  lcm,
  modInverse,
  modPow,
  randomCoprime,
} from './numbers'

export interface PaillierPublicKey {
  N: bigint
  g: bigint
  N2: bigint
  bitLength: number
}

export interface PaillierPrivateKey {
  lambda: bigint
  mu: bigint
  p: bigint
  q: bigint
}

export interface PaillierKeyPair {
  publicKey: PaillierPublicKey
  privateKey: PaillierPrivateKey
}

function bigintBitLength(value: bigint): number {
  if (value <= 0n) {
    return 0
  }
  return value.toString(2).length
}

function normalizeMod(value: bigint, modulus: bigint): bigint {
  const modded = value % modulus
  return modded >= 0n ? modded : modded + modulus
}

/**
 * The L function: L(x) = (x - 1) / N.
 * Integer division. If (x-1) mod N != 0, throws.
 */
export function L(x: bigint, N: bigint): bigint {
  const numerator = x - 1n
  if (numerator % N !== 0n) {
    throw new Error('Invalid L input: (x - 1) is not divisible by N')
  }
  return numerator / N
}

/**
 * Generate a Paillier keypair with N of the specified bit length.
 * bitLength options: 512 (toy), 1024 (weak/educational), 2048 (production),
 *                    3072 (stronger).
 * Reports progress during prime generation.
 */
export async function generateKeyPair(
  bitLength: number,
  onProgress?: (stage: string, percent: number) => void,
): Promise<PaillierKeyPair> {
  if (bitLength < 12 || bitLength % 2 !== 0) {
    throw new Error('bitLength must be an even number >= 12')
  }

  const primeBits = bitLength / 2

  let pAttempts = 0
  onProgress?.(`Searching for prime p (${primeBits} bits)...`, 5)
  const p = generatePrime(primeBits, (attempts) => {
    pAttempts = attempts
    const progress = Math.min(35, 5 + Math.floor(Math.log2(attempts + 1) * 4))
    onProgress?.(`Searching for prime p (${primeBits} bits)... attempt ${attempts}`, progress)
  })

  onProgress?.(`Prime p found after ${pAttempts} attempts`, 40)

  let qAttempts = 0
  let q = p
  while (q === p) {
    onProgress?.(`Searching for prime q (${primeBits} bits)...`, 45)
    q = generatePrime(primeBits, (attempts) => {
      qAttempts = attempts
      const progress = Math.min(75, 45 + Math.floor(Math.log2(attempts + 1) * 4))
      onProgress?.(`Searching for prime q (${primeBits} bits)... attempt ${attempts}`, progress)
    })
  }

  onProgress?.(`Prime q found after ${qAttempts} attempts`, 80)

  onProgress?.('Computing N = p * q', 85)
  const N = p * q
  const N2 = N * N
  const g = N + 1n

  onProgress?.('Computing lambda = lcm(p-1, q-1)', 90)
  const lambda = lcm(p - 1n, q - 1n)

  onProgress?.('Computing mu = lambda^-1 mod N', 95)
  if (gcd(lambda, N) !== 1n) {
    throw new Error('Invalid key material: gcd(lambda, N) != 1')
  }
  const mu = modInverse(lambda, N)

  onProgress?.('Keypair generated', 100)

  return {
    publicKey: {
      N,
      g,
      N2,
      bitLength: bigintBitLength(N),
    },
    privateKey: {
      lambda,
      mu,
      p,
      q,
    },
  }
}

/**
 * Encrypt a plaintext m in [0, N-1].
 *
 *   c = g^m * r^N mod N^2
 *
 * Uses fresh random r for each encryption.
 */
export function encrypt(
  message: bigint,
  publicKey: PaillierPublicKey,
): { ciphertext: bigint; r: bigint } {
  const { N, N2 } = publicKey
  if (message < 0n || message >= N) {
    throw new Error('Message must be in [0, N-1]')
  }

  const r = randomCoprime(N)
  const gm = (1n + message * N) % N2
  const rN = modPow(r, N, N2)
  const ciphertext = (gm * rN) % N2

  return { ciphertext, r }
}

/**
 * Decrypt a ciphertext c in [0, N^2-1].
 *
 *   u = c^lambda mod N^2
 *   L(u) = (u - 1) / N
 *   m = L(u) * mu mod N
 */
export function decrypt(ciphertext: bigint, keyPair: PaillierKeyPair): bigint {
  const { publicKey, privateKey } = keyPair
  const { N, N2 } = publicKey
  if (ciphertext < 0n || ciphertext >= N2) {
    throw new Error('Ciphertext must be in [0, N^2-1]')
  }

  const u = modPow(ciphertext, privateKey.lambda, N2)
  const l = L(u, N)
  return normalizeMod(l * privateKey.mu, N)
}

/**
 * Homomorphic addition:
 *   c1 * c2 mod N^2 = encrypt(m1 + m2)
 */
export function addCiphertexts(
  c1: bigint,
  c2: bigint,
  publicKey: PaillierPublicKey,
): bigint {
  return (normalizeMod(c1, publicKey.N2) * normalizeMod(c2, publicKey.N2)) % publicKey.N2
}

/**
 * Homomorphic addition with plaintext:
 *   c * g^k mod N^2 = encrypt(m + k)
 */
export function addPlaintext(
  ciphertext: bigint,
  plaintext: bigint,
  publicKey: PaillierPublicKey,
): bigint {
  const k = normalizeMod(plaintext, publicKey.N)
  const gk = modPow(publicKey.g, k, publicKey.N2)
  return (normalizeMod(ciphertext, publicKey.N2) * gk) % publicKey.N2
}

/**
 * Homomorphic scalar multiplication:
 *   c^k mod N^2 = encrypt(k * m)
 */
export function multiplyByScalar(
  ciphertext: bigint,
  scalar: bigint,
  publicKey: PaillierPublicKey,
): bigint {
  if (scalar < 0n) {
    throw new Error('Scalar must be non-negative')
  }
  return modPow(normalizeMod(ciphertext, publicKey.N2), scalar, publicKey.N2)
}

/**
 * Re-randomize a ciphertext without knowing the plaintext.
 *   c' = c * r^N mod N^2 (fresh r)
 */
export function rerandomize(ciphertext: bigint, publicKey: PaillierPublicKey): bigint {
  const r = randomCoprime(publicKey.N)
  const rN = modPow(r, publicKey.N, publicKey.N2)
  return (normalizeMod(ciphertext, publicKey.N2) * rN) % publicKey.N2
}
