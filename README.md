# crypto-lab-paillier-gate

Browser-based Paillier cryptosystem demo implementing Pascal Paillier's 1999 additive homomorphic public-key encryption scheme.

## What It Is
Browser-based Paillier cryptosystem demo implementing Pascal Paillier's 1999 additive homomorphic public-key encryption scheme. Supports keypair generation at 12/1024/2048-bit levels, encryption/decryption, homomorphic addition of ciphertexts, addition of public plaintext to ciphertext, scalar multiplication of ciphertexts, and ciphertext re-randomization. All arithmetic uses BigInt with square-and-multiply modular exponentiation. Includes simulated private aggregation (5-hospital patient count) and private voting (10-voter election) scenarios that use only the homomorphic property; no individual values are ever decrypted.

## When to Use It
- Understanding why Paillier is the workhorse of private aggregation systems: e-voting, healthcare analytics, federated counting.
- Teaching the difference between additive and multiplicative homomorphism (see ElGamal demo for contrast).
- Learning why threshold ECDSA protocols like GG20 use Paillier under the hood.
- Distinguishing Paillier from fully homomorphic encryption: different tradeoffs, different deployment profiles.
- Not for generic file encryption (use AES-GCM). Paillier ciphertexts are roughly 2x the modulus bit length, so use hybrid encryption for bulk data.

## Live Demo
https://systemslibrarian.github.io/crypto-lab-paillier-gate/

## What Can Go Wrong
- Paillier encryption is not chosen-ciphertext secure (IND-CCA). An adversary can manipulate ciphertexts homomorphically in ways the scheme does not authenticate. Production deployments with adversarial parties require zero-knowledge proofs of correct ciphertext structure.
- Key generation for 2048-bit N takes several seconds in-browser due to Miller-Rabin primality testing.
- Toy mode uses 12-bit N and is completely insecure. It exists for visualization only.
- Security relies on decisional composite residuosity hardness and therefore falls with large-scale quantum factoring (Shor), similar to RSA.

## Real-World Usage
Pascal Paillier introduced this cryptosystem at Eurocrypt 1999. It became a standard primitive for additive homomorphic encryption in deployed systems. Usage examples include the Helios voting system, ElectionGuard, threshold ECDSA wallets (GG20/GG18/Lindell variants), federated healthcare analytics, and private telemetry aggregation. The GG20 wallet demo in this suite uses Paillier internally for threshold signing.

## Development
- Install dependencies: `npm ci`
- Run locally: `npm run dev`
- Build: `npm run build`
