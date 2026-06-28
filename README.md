# crypto-lab-hqc-timing-break

## What It Is

An interactive demonstration of the **2026 compiler-induced cache-timing attack on HQC** (Dong & Guo, IACR ePrint 2026/693) — the first cache-timing *full-decryption oracle* key-recovery attack reported against a post-quantum scheme. HQC (Hamming Quasi-Cyclic), the code-based KEM NIST selected for standardisation in 2025, ships an optimized implementation written in constant-time style: secret values are combined with **mask-based conditional selection**, never branched on. The twist is that the *compiler* breaks it. At `-O3`, the optimizer proves the mask is really a boolean and rewrites the branchless select into an `if/else`, so the inner Reed–Muller decoder now touches a **secret-dependent cache line**. An unprivileged, co-located attacker reads those lines with **Flush+Reload**, and because each read is noisy, a reliability-aware **Soft Information Set Decoding (Soft-ISD)** step turns the per-position predicates into the full recovered plaintext. This lab models the *shape* of that attack: an abstract cache hit/miss channel, a repetition code standing in for the inner Reed–Muller code, and a side-by-side of hard-decision vs Soft-ISD recovery — so the leak is visible without a full HQC build. Flip the binary back to constant-time and the channel goes silent.

## When to Use It

- **Teaching "constant-time source ≠ constant-time binary"** — the canonical, concrete example of an optimizer reintroducing a side channel the source had removed.
- **Explaining Flush+Reload** — show how a shared cache line becomes a one-bit oracle, and how averaging many probes beats measurement noise.
- **Motivating binary-level verification** — argue for checking the compiled artifact (and gating it in CI) across compilers and flags, not just reviewing the C.
- **Showing why Soft-ISD matters** — demonstrate that reliability-weighted decoding recovers the key where a plain majority vote fails.
- **Do NOT treat this as a working HQC exploit** — it is a teaching simulation with an abstract cache model and tiny parameters.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hqc-timing-break](https://systemslibrarian.github.io/crypto-lab-hqc-timing-break/)**

Set the secret message size, the inner-code redundancy, the cache noise, and how many Flush+Reload probes to average per position, then run the attack. The chart shows the per-position cache hit-rate — on the optimized binary, bars split above and below the 50% line by secret bit; bars are green when read correctly, red when noise flipped them. The recovery panel compares **Soft-ISD** against plain **hard-decision** majority and reports both accuracies and the total probe count. Toggle **Constant-time binary** and re-run: every select now touches the probed line, every bar pins near 100%, and recovery drops to chance. Below the lab, a "Same Source, Two Binaries" panel shows the exact mask-select C source and the branchy code the optimizer emits, followed by the timeline of HQC's four documented timing/cache leaks and a do/don't guide to keeping the binary honest.

## What Can Go Wrong

- **Optimizer rewrites a branchless select into a branch** — the root cause here; the source is constant-time but the emitted binary is not.
- **Secret-dependent memory access** — even with flat wall-clock time, a data-dependent cache line is observable via Flush+Reload, Prime+Probe, or Evict+Time.
- **Trusting source-level review** — "this function is constant-time" describes the C, not the machine code a given compiler/flag combination produces.
- **Single-toolchain testing** — a different compiler or `-O` level can reintroduce the leak; constant-timeness is a property of each shipped binary.
- **Assuming PQC math implies PQC safety** — a hard code/lattice problem does nothing to stop a side channel that ignores the math entirely.

## Real-World Usage

- **HQC standardisation** — NIST selected HQC in 2025 as a code-based KEM for algorithmic diversity alongside lattice-based ML-KEM; its implementation security is under active scrutiny.
- **Binary-level constant-time verification** — dynamic and static checkers (dudect-style timing tests, ctgrind, Binsec/Rel) run on the compiled artifact, motivated directly by compiler-induced leaks like this one.
- **Optimization barriers** — `value-barrier` helpers, `volatile`, and inline-asm fences that stop the optimizer from inferring a mask is boolean and rewriting the select.
- **Flush+Reload hardening** — cache partitioning, constant-time gadgets, and avoiding secret-indexed memory, the standard responses to shared-cache side channels.
- **Soft Information Set Decoding (Soft-ISD)** — reliability-aware decoding used by the attack to convert noisy side-channel predicates into a full key, and studied defensively to understand attacker capability.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hqc-timing-break
cd crypto-lab-hqc-timing-break
npm install
npm run dev
```

Vite + TypeScript, zero runtime dependencies. `src/engine.ts` models the Flush+Reload cache channel and the hard-decision vs Soft-ISD recovery; `src/data.ts` holds the source/compiled diff, the attack steps, the HQC leak timeline, and the defenses; `src/ui.ts` is the interactive lab. Dark mode follows your OS preference on first load and is toggleable + persisted. The UI is mobile-first, keyboard-accessible (skip link, visible focus, ARIA labels), and respects `prefers-reduced-motion`, `forced-colors`, and print.

`npm run build` type-checks and produces a production build to `dist/`. GitHub Pages deployment runs on every push to `main` via `.github/workflows/deploy.yml` (build → upload artifact → deploy).

## Related Demos

- [crypto-lab-hqc-timing](https://systemslibrarian.github.io/crypto-lab-hqc-timing/) — HQC's BCH-decoder timing oracle, the constant-time sibling of this cache attack.
- [crypto-lab-hqc-vault](https://systemslibrarian.github.io/crypto-lab-hqc-vault/) — the HQC KEM whose optimized decoder this attack targets.
- [crypto-lab-kyberslash](https://systemslibrarian.github.io/crypto-lab-kyberslash/) — a timing attack on ML-KEM from variable-time division, the same class of implementation bug.
- [crypto-lab-lattice-fault](https://systemslibrarian.github.io/crypto-lab-lattice-fault/) — fault-injection key recovery against ML-KEM/ML-DSA, another implementation-level PQC break.
- [crypto-lab-timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) — the general timing/cache side-channel pattern this attack is an instance of.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
