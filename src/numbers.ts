function assertPositiveModulus(m: bigint): void {
  if (m <= 0n) {
    throw new Error('Modulus must be positive')
  }
}

/**
 * Greatest common divisor.
 */
export function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a
  let y = b < 0n ? -b : b
  while (y !== 0n) {
    const t = x % y
    x = y
    y = t
  }
  return x
}

/**
 * Extended Euclidean algorithm.
 * Returns { gcd, x, y } such that a*x + b*y = gcd(a, b).
 */
export function extendedGcd(a: bigint, b: bigint): {
  gcd: bigint
  x: bigint
  y: bigint
} {
  let oldR = a
  let r = b
  let oldS = 1n
  let s = 0n
  let oldT = 0n
  let t = 1n

  while (r !== 0n) {
    const q = oldR / r
    ;[oldR, r] = [r, oldR - q * r]
    ;[oldS, s] = [s, oldS - q * s]
    ;[oldT, t] = [t, oldT - q * t]
  }

  return { gcd: oldR < 0n ? -oldR : oldR, x: oldS, y: oldT }
}

/**
 * Least common multiple.
 * lcm(a, b) = |a*b| / gcd(a, b)
 */
export function lcm(a: bigint, b: bigint): bigint {
  if (a === 0n || b === 0n) {
    return 0n
  }
  const g = gcd(a, b)
  const result = (a / g) * b
  return result < 0n ? -result : result
}

/**
 * Modular exponentiation: base^exp mod m.
 * Square-and-multiply - O(log exp).
 * REQUIRED for Paillier since exponents are hundreds of bits.
 */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  assertPositiveModulus(m)
  if (exp < 0n) {
    throw new Error('Exponent must be non-negative')
  }

  let result = 1n
  let b = ((base % m) + m) % m
  let e = exp

  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % m
    }
    b = (b * b) % m
    e >>= 1n
  }

  return result
}

/**
 * Modular inverse: a^-1 mod m.
 * Throws if gcd(a, m) != 1 (inverse does not exist).
 */
export function modInverse(a: bigint, m: bigint): bigint {
  assertPositiveModulus(m)
  const { gcd: g, x } = extendedGcd(a, m)
  if (g !== 1n) {
    throw new Error(`Inverse does not exist for ${a} mod ${m}`)
  }
  return ((x % m) + m) % m
}

function bitLength(n: bigint): number {
  if (n <= 0n) {
    return 0
  }
  return n.toString(2).length
}

function randomBytes(byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return bytes
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte)
  }
  return value
}

/**
 * Cryptographically random BigInt in [1, max).
 * Rejection sampling to avoid modulo bias.
 */
export function randomBigInt(max: bigint): bigint {
  if (max <= 1n) {
    throw new Error('max must be greater than 1')
  }

  const bits = bitLength(max - 1n)
  const bytes = Math.ceil(bits / 8)
  const limit = 1n << BigInt(bits)

  while (true) {
    const candidate = bytesToBigInt(randomBytes(bytes))
    if (candidate >= limit) {
      continue
    }
    if (candidate > 0n && candidate < max) {
      return candidate
    }
  }
}

/**
 * Random BigInt coprime to N.
 * Rejects values where gcd(r, N) > 1 (extremely rare for large N).
 */
export function randomCoprime(N: bigint): bigint {
  if (N <= 2n) {
    throw new Error('N must be greater than 2')
  }
  while (true) {
    const r = randomBigInt(N)
    if (gcd(r, N) === 1n) {
      return r
    }
  }
}

/**
 * Miller-Rabin probable prime test. k rounds.
 * Default k=40 for cryptographic use.
 */
export function isProbablePrime(n: bigint, k = 40): boolean {
  if (n < 2n) {
    return false
  }

  const smallPrimes = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]
  for (const p of smallPrimes) {
    if (n === p) {
      return true
    }
    if (n % p === 0n) {
      return false
    }
  }

  let d = n - 1n
  let s = 0
  while ((d & 1n) === 0n) {
    d >>= 1n
    s += 1
  }

  for (let i = 0; i < k; i += 1) {
    const a = randomBigInt(n - 3n) + 2n
    let x = modPow(a, d, n)

    if (x === 1n || x === n - 1n) {
      continue
    }

    let witnessFound = true
    for (let r = 1; r < s; r += 1) {
      x = modPow(x, 2n, n)
      if (x === n - 1n) {
        witnessFound = false
        break
      }
    }

    if (witnessFound) {
      return false
    }
  }

  return true
}

/**
 * Generate a probable prime of the given bit length.
 * Uses Miller-Rabin with k=40.
 * May take several seconds for 1024-bit primes (for N=2048).
 * Report progress via optional callback.
 */
export function generatePrime(
  bits: number,
  onProgress?: (attempts: number) => void,
): bigint {
  if (bits < 2) {
    throw new Error('bits must be >= 2')
  }

  const byteLength = Math.ceil(bits / 8)
  const topBit = 1n << BigInt(bits - 1)
  const lowBit = 1n
  const lowerBound = 1n << BigInt(bits - 1)
  const upperBound = 1n << BigInt(bits)

  let attempts = 0
  while (true) {
    attempts += 1
    onProgress?.(attempts)

    const bytes = randomBytes(byteLength)
    let candidate = bytesToBigInt(bytes)

    candidate |= topBit
    candidate |= lowBit

    if (candidate < lowerBound || candidate >= upperBound) {
      continue
    }

    if (isProbablePrime(candidate, 40)) {
      return candidate
    }
  }
}
