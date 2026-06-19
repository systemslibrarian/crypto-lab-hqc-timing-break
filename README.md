# crypto-lab-hqc-timing-break

## What It Is
This demo is a browser implementation of the Paillier cryptosystem with additive homomorphism, implemented with BigInt arithmetic in TypeScript. It demonstrates public-key encryption and decryption, ciphertext addition, public plaintext addition, public scalar multiplication, and re-randomization without decrypting intermediate values. It also includes a zero-knowledge proof (a Cramer–Damgård–Schoenmakers OR-proof) that a ciphertext encrypts a valid 0/1 ballot, so a tally can reject ballot-stuffing without ever learning a vote. The core problem it solves is private summation: computing totals while keeping individual inputs hidden. Its security model is asymmetric cryptography based on the decisional composite residuosity assumption, with toy-size parameters included only for education.

## When to Use It
- Private vote tallying where each vote is encrypted as 0/1 and only the final sum is decrypted, because Paillier supports ciphertext aggregation by multiplication.
- Multi-party count aggregation across organizations, because each contributor can encrypt locally and share only ciphertexts.
- Public weighted sum workflows in analytics, because ciphertexts can be raised to public weights and combined homomorphically.
- Teaching additive-only homomorphism in applied cryptography courses, because the demo exposes both cryptographic operations and verification outputs.
- Do not use this scheme for bulk file encryption, because Paillier ciphertexts are large and the primitive is designed for small numeric messages and aggregation.

## Live Demo
https://systemslibrarian.github.io/crypto-lab-hqc-timing-break/

In the live page you can generate keypairs at multiple key sizes, then encrypt and decrypt values directly in the browser. You can also run homomorphic operations to verify that decrypted results match expected sums and scalar products. Controls include key size selection, message input, homomorphic operation inputs, voting inputs, and hospital aggregation inputs.

## How to Learn From It
The page is built to be understood, not just watched:
- **Start with "The Big Idea."** It derives the one identity the whole scheme rests on — `E(a)·E(b) = E(a+b)` — in three lines, plus why `g = N + 1` makes `gᵐ` a single multiply.
- **Switch to TOY (12-bit) mode.** Every value prints in full decimal with a step-by-step trace, so you can recompute `c = gᵐ · rᴺ mod N²` on a calculator and confirm it. The private panel even reveals the real `p`, `q`, `λ`, and `μ`.
- **Encrypt the same number twice.** Two unrelated-looking ciphertexts both decrypt to the same value — semantic security from the fresh random `r`.
- **Open the "Why this works" notes** under each exhibit for the reasoning, and read "What you cannot do" for the honest limits (no ciphertext × ciphertext; sums are mod N).
- **Try the zero-knowledge exhibit.** Enter `1` to see a ballot proven valid and accepted; enter `5` to watch the same proof get rejected — homomorphic tallying only becomes a real protocol once every ballot is provably a 0 or 1.

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
