# crypto-lab-hqc-timing-break

## What It Is
This demo is a browser implementation of the Paillier cryptosystem with additive homomorphism, implemented with BigInt arithmetic in TypeScript. It demonstrates public-key encryption and decryption, ciphertext addition, public plaintext addition, public scalar multiplication, and re-randomization without decrypting intermediate values. The core problem it solves is private summation: computing totals while keeping individual inputs hidden. Its security model is asymmetric cryptography based on the decisional composite residuosity assumption, with toy-size parameters included only for education.

## When to Use It
- Private vote tallying where each vote is encrypted as 0/1 and only the final sum is decrypted, because Paillier supports ciphertext aggregation by multiplication.
- Multi-party count aggregation across organizations, because each contributor can encrypt locally and share only ciphertexts.
- Public weighted sum workflows in analytics, because ciphertexts can be raised to public weights and combined homomorphically.
- Teaching additive-only homomorphism in applied cryptography courses, because the demo exposes both cryptographic operations and verification outputs.
- Do not use this scheme for bulk file encryption, because Paillier ciphertexts are large and the primitive is designed for small numeric messages and aggregation.

## Live Demo
https://systemslibrarian.github.io/crypto-lab-hqc-timing-break/

In the live page you can generate keypairs at multiple key sizes, then encrypt and decrypt values directly in the browser. You can also run homomorphic operations to verify that decrypted results match expected sums and scalar products. Controls include key size selection, message input, homomorphic operation inputs, voting inputs, and hospital aggregation inputs.

## How to Run Locally
```bash
git clone https://github.com/systemslibrarian/crypto-lab-hqc-timing-break
cd crypto-lab-hqc-timing-break
npm install
npm run dev
```

No environment variables are required.

## Part of the Crypto-Lab Suite
One of 60+ live browser demos at [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
