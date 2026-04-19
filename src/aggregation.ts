import { addCiphertexts, encrypt, multiplyByScalar, type PaillierPublicKey } from './paillier'

export interface HospitalData {
  id: string
  privateCount: bigint
  encryptedCount: bigint
}

export function simulatePrivateAggregation(
  privateCounts: bigint[],
  publicKey: PaillierPublicKey,
): {
  hospitals: HospitalData[]
  encryptedTotal: bigint
} {
  const hospitals: HospitalData[] = privateCounts.map((count, index) => {
    if (count < 0n || count >= publicKey.N) {
      throw new Error('Hospital count must be in [0, N-1]')
    }
    return {
      id: `Hospital ${String.fromCharCode(65 + index)}`,
      privateCount: count,
      encryptedCount: encrypt(count, publicKey).ciphertext,
    }
  })

  const encryptedTotal = hospitals.reduce(
    (acc, hospital) => addCiphertexts(acc, hospital.encryptedCount, publicKey),
    1n,
  )

  return { hospitals, encryptedTotal }
}

export interface Vote {
  voterId: string
  encryptedVote: bigint
}

export function simulatePrivateElection(
  votes: number[],
  publicKey: PaillierPublicKey,
): {
  encryptedVotes: Vote[]
  encryptedTally: bigint
} {
  const encryptedVotes = votes.map((vote, index) => {
    if (vote !== 0 && vote !== 1) {
      throw new Error('Votes must be 0 or 1')
    }
    return {
      voterId: `Voter ${index + 1}`,
      encryptedVote: encrypt(BigInt(vote), publicKey).ciphertext,
    }
  })

  const encryptedTally = encryptedVotes.reduce(
    (acc, vote) => addCiphertexts(acc, vote.encryptedVote, publicKey),
    1n,
  )

  return { encryptedVotes, encryptedTally }
}

export function weightedSum(
  encryptedValues: bigint[],
  weights: bigint[],
  publicKey: PaillierPublicKey,
): bigint {
  if (encryptedValues.length !== weights.length) {
    throw new Error('encryptedValues and weights must have the same length')
  }

  let total = 1n
  for (let i = 0; i < encryptedValues.length; i += 1) {
    const weight = weights[i]
    if (weight < 0n) {
      throw new Error('weights must be non-negative')
    }
    const weighted = multiplyByScalar(encryptedValues[i], weight, publicKey)
    total = addCiphertexts(total, weighted, publicKey)
  }

  return total
}
