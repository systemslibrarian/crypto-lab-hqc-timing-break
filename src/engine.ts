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
//   * HETEROGENEOUS per-position cache noise: real Flush+Reload traces are not
//     i.i.d. — some codeword positions land on a quiet, reliably-timed line and
//     others on a contended line that is nearly always ambiguous. Each position
//     therefore gets its own flip probability drawn from a range. This is what
//     makes the reliability-aware Soft-ISD decoder genuinely dominate a plain
//     unweighted majority vote: majority lets a cluster of high-noise positions
//     outvote the reliable ones, whereas Soft-ISD down-weights them by |p-0.5|.
//   * Flush+Reload measurements with that per-position noise -> a noisy hit-rate
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
	cacheNoise: number; // 0..1: MEAN probability a single Flush+Reload probe is misread
	probes: number; // Flush+Reload measurements per codeword position
	optimized: boolean; // true = compiler rewrote the select into a leaking branch
	// noiseSpread: how unevenly cache noise is distributed across positions (0..1).
	// 0 = homogeneous (every position equally noisy, the old symmetric model);
	// >0 = a fraction of positions land on a heavily-CONTENDED cache line and
	// become nearly-ambiguous (flip prob near 0.5), while the rest stay clean.
	// This heavy-tailed, per-line contention is the realistic case — and the one
	// where reliability-aware Soft-ISD beats a plain majority vote, because a
	// cluster of ambiguous positions can win a head-count but not an LLR-weighted
	// vote. See drawFlipProb for the exact mixture.
	noiseSpread?: number;
	rng?: Rng;
}

export interface PositionObs {
	position: number; // codeword position index
	messageBit: number; // which message bit this position carries
	trueBit: number; // the codeword bit the decoder actually computed
	flipProb: number; // this position's per-probe misread probability (heterogeneous)
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

// Draw a per-position flip probability from a two-component contention mixture.
//
// With spread=0 every position gets exactly the mean noise (homogeneous — the
// old symmetric model). With spread>0 the population splits:
//   * a fraction `spread` of positions land on a heavily-CONTENDED line and get
//     a flip prob near 0.5 (nearly ambiguous — almost no signal), and
//   * the remaining positions land on a QUIET line and get a flip prob well
//     below the mean (very reliable).
// The mixture is calibrated so the population mean stays ~`mean`, so raising
// unevenness redistributes noise rather than simply adding it. This heavy tail
// of ambiguous positions is what a plain majority vote cannot cope with (they
// vote at full weight and can form a winning bloc) but an LLR-weighted Soft-ISD
// decoder shrugs off (their votes carry almost no weight).
export function drawFlipProb(mean: number, spread: number, rng: Rng): number {
	const s = Math.max(0, Math.min(1, spread));
	if (s <= 0) return Math.max(0, Math.min(0.5, mean));
	const contendedCenter = 0.5; // ambiguous line
	// Choose the quiet-line noise so the two-component mean equals `mean`:
	//   mean = s * contendedCenter + (1 - s) * quiet   =>   quiet = (mean - s*0.5)/(1-s)
	const quiet = Math.max(0, (mean - s * contendedCenter) / (1 - s));
	if (rng() < s) {
		// Contended: jitter just below 0.5 so it is ambiguous but still finite.
		return Math.max(0, Math.min(0.5, contendedCenter - 0.03 * rng()));
	}
	// Quiet: small jitter around the (low) quiet-line noise.
	return Math.max(0, Math.min(0.5, quiet * (0.5 + rng())));
}

// Log-likelihood ratio of "bit == 1" from an observed hit-rate. This is the
// per-position soft weight the Soft-ISD decoder sums. A hit-rate of 0.5 gives
// LLR 0 (no vote); confident hit-rates give a large-magnitude vote whose weight
// grows super-linearly toward the ends. The hit-rate is clamped away from
// {0, 1} so the log stays finite (a single trace never proves certainty).
export function llr(hitRate: number): number {
	const eps = 1e-3;
	const p = Math.max(eps, Math.min(1 - eps, hitRate));
	return Math.log(p / (1 - p));
}

// One codeword position's Flush+Reload trace -> a hit-rate over `probes` reads.
// optimized binary: the branch touches the probed line iff the codeword bit is 1,
//   so P(hit) = 1 - flipProb when trueBit=1, and flipProb when trueBit=0.
// constant-time binary: the mask-select always touches the probed line, so every
//   probe is a hit (P(hit)=1) regardless of the secret — no discrimination.
export function probeRate(trueBit: number, flipProb: number, params: SimParams, rng: Rng): number {
	const pHit = params.optimized ? (trueBit === 1 ? 1 - flipProb : flipProb) : 1;
	let hits = 0;
	for (let p = 0; p < params.probes; p++) if (rng() < pHit) hits++;
	return params.probes > 0 ? hits / params.probes : 0;
}

export function runAttack(message: Uint8Array, params: SimParams): AttackResult {
	const k = message.length;
	const R = Math.max(1, params.repeats);
	const rng = params.rng ?? Math.random;
	const spread = params.noiseSpread ?? 0;
	const n = k * R;

	const observations: PositionObs[] = [];
	for (let i = 0; i < k; i++) {
		for (let r = 0; r < R; r++) {
			const trueBit = message[i] ?? 0;
			// Each position's own reliability, fixed before probing it.
			const flipProb = drawFlipProb(params.cacheNoise, spread, rng);
			const hitRate = probeRate(trueBit, flipProb, params, rng);
			observations.push({
				position: i * R + r,
				messageBit: i,
				trueBit,
				flipProb,
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
		// Hard-decision: unweighted majority of thresholded bits. Every position
		// counts the same, so a cluster of noisy positions can outvote the clean
		// ones — this is what fails under heterogeneous reliability.
		const ones = group.reduce((acc, o) => acc + o.hardBit, 0);
		recoveredHard[i] = ones * 2 > group.length ? 1 : 0;
		// Soft-ISD: each position casts a log-likelihood-ratio vote. Treating the
		// observed hit-rate as an estimate of P(bit=1), the LLR log(p/(1-p)) is the
		// statistically optimal weight: near-0.5 (ambiguous) positions contribute
		// almost nothing, while confident positions dominate super-linearly. That
		// is exactly why the reliability-aware decoder beats a plain unweighted
		// majority once per-position reliability varies — a noisy cluster can win a
		// head-count but cannot outweigh a handful of confident, clean positions.
		const score = group.reduce((acc, o) => acc + llr(o.hitRate), 0);
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
