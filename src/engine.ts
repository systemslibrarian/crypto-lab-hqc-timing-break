// engine.ts — simulation of the 2026 compiler-induced cache-timing attack on HQC.
//
// FAITHFUL MODEL (not a full HQC implementation). Dong & Guo (IACR ePrint
// 2026/693) showed that the official optimized HQC implementation, although
// written in constant-time style with mask-based conditional selection, is
// rewritten by the compiler's optimizer (e.g. Clang -O3) into a *branch*. That
// branch makes the inner Reed–Muller decoder touch a secret-dependent cache
// line, which an unprivileged co-located attacker reads with Flush+Reload. The
// recovered per-position predicates are noisy, so a reliability-aware Soft
// Information Set Decoding (Soft-ISD) step turns them into a full plaintext /
// key recovery — the first cache-timing full-decryption oracle on a PQC scheme.
//
// We model:
//   * a secret message (the plaintext a full-decryption oracle recovers)
//   * an inner code (repetition stand-in for HQC's Reed–Muller code) so each
//     message bit is carried by several codeword positions
//   * a per-position conditional select whose branch, when the binary is NOT
//     constant-time, leaks the codeword bit through a cache hit/miss
//   * Flush+Reload measurements with cache noise -> a noisy hit-rate per position
//   * two recoveries: hard-decision majority vs reliability-weighted Soft-ISD
//   * a "verified constant-time binary" mode where the select touches the same
//     line every time, so every probe hits and the channel carries no signal.
//
// All randomness flows through an injectable RNG so a seed reproduces the same
// secret + the same measurement noise — required for a fair vulnerable-vs-fixed
// comparison.

export type Rng = () => number;

export interface SimParams {
	messageBits: number; // k: secret plaintext bits to recover (small, for teaching)
	repeats: number; // R: inner-code redundancy (repetition stand-in for Reed–Muller)
	cacheNoise: number; // 0..1: probability a single Flush+Reload probe is misread
	probes: number; // Flush+Reload measurements per codeword position
	optimized: boolean; // true = compiler rewrote the select into a leaking branch
	rng?: Rng;
}

export interface PositionObs {
	position: number; // codeword position index
	messageBit: number; // which message bit this position carries
	trueBit: number; // the codeword bit the decoder actually computed
	hitRate: number; // fraction of probes that were cache hits (0..1)
	reliability: number; // |hitRate - 0.5| * 2  (0 = ambiguous, 1 = certain)
	hardBit: number; // hitRate > 0.5 ? 1 : 0
}

export interface AttackResult {
	observations: PositionObs[];
	recoveredHard: Uint8Array; // majority vote per message bit
	recoveredSoft: Uint8Array; // reliability-weighted (Soft-ISD) per message bit
	accuracyHard: number;
	accuracySoft: number;
	bitsCorrectHard: number;
	bitsCorrectSoft: number;
	totalProbes: number;
	codewordLength: number;
}

// Mulberry32 — small, fast, good enough for visualization.
export function createRng(seed: number): Rng {
	let a = (seed >>> 0) || 1;
	return function () {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

export function randomSeed(): number {
	return (Math.random() * 0xffffffff) >>> 0;
}

export function formatSeed(seed: number): string {
	return '0x' + (seed >>> 0).toString(16).padStart(8, '0');
}

export function makeMessage(k: number, rng: Rng = Math.random): Uint8Array {
	const m = new Uint8Array(Math.max(0, k));
	for (let i = 0; i < m.length; i++) m[i] = rng() < 0.5 ? 1 : 0;
	return m;
}

// One codeword position's Flush+Reload trace -> a hit-rate over `probes` reads.
// optimized binary: the branch touches the probed line iff the codeword bit is 1,
//   so P(hit) = 1 - cacheNoise when trueBit=1, and cacheNoise when trueBit=0.
// constant-time binary: the mask-select always touches the probed line, so every
//   probe is a hit (P(hit)=1) regardless of the secret — no discrimination.
function probeRate(trueBit: number, params: SimParams, rng: Rng): number {
	const pHit = params.optimized ? (trueBit === 1 ? 1 - params.cacheNoise : params.cacheNoise) : 1;
	let hits = 0;
	for (let p = 0; p < params.probes; p++) if (rng() < pHit) hits++;
	return params.probes > 0 ? hits / params.probes : 0;
}

export function runAttack(message: Uint8Array, params: SimParams): AttackResult {
	const k = message.length;
	const R = Math.max(1, params.repeats);
	const rng = params.rng ?? Math.random;
	const n = k * R;

	const observations: PositionObs[] = [];
	for (let i = 0; i < k; i++) {
		for (let r = 0; r < R; r++) {
			const trueBit = message[i] ?? 0;
			const hitRate = probeRate(trueBit, params, rng);
			observations.push({
				position: i * R + r,
				messageBit: i,
				trueBit,
				hitRate,
				reliability: Math.min(1, Math.abs(hitRate - 0.5) * 2),
				hardBit: hitRate > 0.5 ? 1 : 0,
			});
		}
	}

	const recoveredHard = new Uint8Array(k);
	const recoveredSoft = new Uint8Array(k);
	for (let i = 0; i < k; i++) {
		const group = observations.filter((o) => o.messageBit === i);
		// Hard-decision: unweighted majority of thresholded bits.
		const ones = group.reduce((acc, o) => acc + o.hardBit, 0);
		recoveredHard[i] = ones * 2 > group.length ? 1 : 0;
		// Soft-ISD: each position votes by how far its hit-rate sits from 0.5,
		// so ambiguous (noisy) positions barely count — exactly what lets the
		// reliability-aware decoder beat a plain majority.
		const score = group.reduce((acc, o) => acc + (o.hitRate - 0.5), 0);
		recoveredSoft[i] = score > 0 ? 1 : 0;
	}

	let correctHard = 0;
	let correctSoft = 0;
	for (let i = 0; i < k; i++) {
		if (recoveredHard[i] === message[i]) correctHard++;
		if (recoveredSoft[i] === message[i]) correctSoft++;
	}

	return {
		observations,
		recoveredHard,
		recoveredSoft,
		accuracyHard: k ? correctHard / k : 0,
		accuracySoft: k ? correctSoft / k : 0,
		bitsCorrectHard: correctHard,
		bitsCorrectSoft: correctSoft,
		totalProbes: n * params.probes,
		codewordLength: n,
	};
}
