import { performance } from 'node:perf_hooks'
import { gcd, generatePrime, isProbablePrime, lcm, modInverse, modPow } from '../src/numbers'
import {
  addCiphertexts,
  addPlaintext,
  decrypt,
  encrypt,
  generateKeyPair,
  multiplyByScalar,
} from '../src/paillier'
import { simulatePrivateAggregation, simulatePrivateElection } from '../src/aggregation'

function check(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message)
  }
}

async function main(): Promise<void> {
  const results: Array<{ id: number; description: string; pass: boolean; detail: string }> = []

  try {
    check(modPow(3n, 100n, 7n) === 4n, 'modPow mismatch')
    check(modInverse(17n, 3120n) === 2753n, 'modInverse mismatch')
    check(gcd(48n, 18n) === 6n, 'gcd mismatch')
    check(lcm(4n, 6n) === 12n, 'lcm mismatch')
    check(isProbablePrime(997n) === true, 'isProbablePrime(997) failed')
    check(isProbablePrime(1000n) === false, 'isProbablePrime(1000) failed')
    const p512 = generatePrime(512)
    check(p512.toString(2).length === 512, 'generatePrime(512) bit length failed')
    check(isProbablePrime(p512, 40), 'generatePrime(512) primality check failed')
    results.push({ id: 2, description: 'Number theory primitives pass all test cases', pass: true, detail: 'OK' })

    const toy = await generateKeyPair(12)
    const toyRoundtrip = decrypt(encrypt(42n, toy.publicKey).ciphertext, toy)
    check(toyRoundtrip === 42n, 'Toy roundtrip failed')
    results.push({ id: 3, description: 'Toy keygen -> encrypt 42 -> decrypt -> 42', pass: true, detail: 'OK' })

    const start2048 = performance.now()
    const prod = await generateKeyPair(2048)
    const elapsedSec = (performance.now() - start2048) / 1000
    check(elapsedSec < 30, `2048-bit keygen too slow: ${elapsedSec.toFixed(2)}s`) 
    results.push({ id: 4, description: '2048-bit keygen succeeds in < 30 seconds', pass: true, detail: `${elapsedSec.toFixed(2)}s` })

    const cAdd = addCiphertexts(
      encrypt(7n, prod.publicKey).ciphertext,
      encrypt(13n, prod.publicKey).ciphertext,
      prod.publicKey,
    )
    check(decrypt(cAdd, prod) === 20n, 'Homomorphic addition failed')
    results.push({ id: 5, description: 'decrypt(E(7) * E(13)) === 20', pass: true, detail: 'OK' })

    const cAddPlain = addPlaintext(encrypt(10n, prod.publicKey).ciphertext, 5n, prod.publicKey)
    check(decrypt(cAddPlain, prod) === 15n, 'Plaintext addition failed')
    results.push({ id: 6, description: 'decrypt(E(10) * g^5) === 15', pass: true, detail: 'OK' })

    const cScalar = multiplyByScalar(encrypt(6n, prod.publicKey).ciphertext, 7n, prod.publicKey)
    check(decrypt(cScalar, prod) === 42n, 'Scalar multiplication failed')
    results.push({ id: 7, description: 'decrypt(E(6)^7) === 42', pass: true, detail: 'OK' })

    const aggregation = simulatePrivateAggregation([10n, 25n, 17n, 8n, 30n], prod.publicKey)
    check(decrypt(aggregation.encryptedTotal, prod) === 90n, 'Hospital aggregation failed')
    results.push({ id: 8, description: '5-hospital aggregation decrypts to 90', pass: true, detail: 'OK' })

    const election = simulatePrivateElection([1, 1, 0, 1, 0, 1, 0, 1, 1, 0], prod.publicKey)
    check(decrypt(election.encryptedTally, prod) === 6n, 'Election tally failed')
    results.push({ id: 9, description: '10-voter election tally decrypts to 6', pass: true, detail: 'OK' })

    for (const result of results) {
      console.log(`${result.id}. ${result.description}: PASS (${result.detail})`)
    }
  } catch (error) {
    for (const result of results) {
      console.log(`${result.id}. ${result.description}: PASS (${result.detail})`)
    }
    console.error(`Verification failed: ${(error as Error).message}`)
    process.exit(1)
  }
}

main().catch((error) => {
  console.error(`Verification failed: ${(error as Error).message}`)
  process.exit(1)
})
