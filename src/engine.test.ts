import { describe, it, expect } from 'vitest';
import {
	createRng,
	makeMessage,
	drawFlipProb,
	probeRate,
	runAttack,
	formatSeed,
	type SimParams,
} from './engine.ts';

// A deterministic seed keeps every assertion reproducible.
const SEED = 0xc0ffee;

function baseParams(over: Partial<SimParams> = {}): SimParams {
	return {
		messageBits: 8,
		repeats: 5,
		cacheNoise: 0.12,
		probes: 16,
		optimized: true,
		noiseSpread: 0,
		rng: createRng(SEED),
		...over,
	};
}

describe('createRng', () => {
	it('is deterministic for a given seed', () => {
		const a = createRng(42);
		const b = createRng(42);
		const seqA = Array.from({ length: 8 }, () => a());
		const seqB = Array.from({ length: 8 }, () => b());
		expect(seqA).toEqual(seqB);
	});

	it('produces values in [0, 1)', () => {
		const r = createRng(7);
		for (let i = 0; i < 1000; i++) {
			const v = r();
			expect(v).toBeGreaterThanOrEqual(0);
			expect(v).toBeLessThan(1);
		}
	});

	it('differs across seeds', () => {
		expect(createRng(1)()).not.toBe(createRng(2)());
	});
});

describe('formatSeed', () => {
	it('renders an 8-hex-digit prefixed seed', () => {
		expect(formatSeed(0xdeadbeef)).toBe('0xdeadbeef');
		expect(formatSeed(1)).toBe('0x00000001');
	});
});

describe('makeMessage', () => {
	it('returns a Uint8Array of the requested length with only 0/1 bits', () => {
		const m = makeMessage(20, createRng(SEED));
		expect(m).toBeInstanceOf(Uint8Array);
		expect(m.length).toBe(20);
		for (const b of m) expect(b === 0 || b === 1).toBe(true);
	});

	it('clamps negative lengths to empty', () => {
		expect(makeMessage(-5).length).toBe(0);
	});

	it('is reproducible under a seeded rng', () => {
		const a = Array.from(makeMessage(32, createRng(SEED)));
		const b = Array.from(makeMessage(32, createRng(SEED)));
		expect(a).toEqual(b);
	});
});

describe('drawFlipProb', () => {
	it('returns exactly the mean when spread is 0 (homogeneous noise)', () => {
		const r = createRng(SEED);
		for (let i = 0; i < 100; i++) {
			expect(drawFlipProb(0.12, 0, r)).toBe(0.12);
		}
	});

	it('never exceeds 0.5 (a fully ambiguous line) even at max spread', () => {
		const r = createRng(SEED);
		for (let i = 0; i < 5000; i++) {
			const p = drawFlipProb(0.4, 1, r);
			expect(p).toBeGreaterThanOrEqual(0);
			expect(p).toBeLessThanOrEqual(0.5);
		}
	});

	it('actually spreads: with spread>0 some positions are cleaner and some noisier than the mean', () => {
		const r = createRng(SEED);
		const mean = 0.2;
		const samples = Array.from({ length: 2000 }, () => drawFlipProb(mean, 0.9, r));
		const below = samples.filter((p) => p < mean - 0.02).length;
		const above = samples.filter((p) => p > mean + 0.02).length;
		expect(below).toBeGreaterThan(50);
		expect(above).toBeGreaterThan(50);
	});
});

describe('probeRate', () => {
	it('a noiseless optimized probe reads the true bit perfectly', () => {
		const p = baseParams({ cacheNoise: 0 });
		// trueBit=1 -> all hits (rate 1); trueBit=0 -> all misses (rate 0)
		expect(probeRate(1, 0, p, createRng(SEED))).toBe(1);
		expect(probeRate(0, 0, p, createRng(SEED))).toBe(0);
	});

	it('constant-time binary pins every probe to a hit regardless of the secret bit', () => {
		const p = baseParams({ optimized: false, cacheNoise: 0.3 });
		expect(probeRate(0, 0.3, p, createRng(SEED))).toBe(1);
		expect(probeRate(1, 0.3, p, createRng(SEED))).toBe(1);
	});

	it('a flipProb of 0.5 gives a hit-rate near chance', () => {
		const p = baseParams({ probes: 4000 });
		const rate = probeRate(1, 0.5, p, createRng(SEED));
		expect(Math.abs(rate - 0.5)).toBeLessThan(0.05);
	});
});

describe('runAttack — constant-time binary (defense holds)', () => {
	it('pins every hit-rate to 1 and yields no discriminating signal', () => {
		const message = makeMessage(8, createRng(SEED));
		const res = runAttack(message, baseParams({ optimized: false, noiseSpread: 0.9 }));
		for (const o of res.observations) {
			expect(o.hitRate).toBe(1);
			expect(o.hardBit).toBe(1); // > 0.5
		}
	});

	it('recovers no better than a constant guess (all-ones), so accuracy tracks the message weight', () => {
		// With every hitRate pinned to 1, hard picks all-ones and soft's score is
		// always > 0, also all-ones. Accuracy == fraction of message bits that are 1.
		const message = Uint8Array.from([1, 0, 1, 0, 1, 0, 1, 0]);
		const res = runAttack(message, baseParams({ optimized: false }));
		expect(Array.from(res.recoveredHard)).toEqual([1, 1, 1, 1, 1, 1, 1, 1]);
		expect(Array.from(res.recoveredSoft)).toEqual([1, 1, 1, 1, 1, 1, 1, 1]);
		expect(res.accuracyHard).toBeCloseTo(0.5, 5);
		expect(res.accuracySoft).toBeCloseTo(0.5, 5);
	});
});

describe('runAttack — optimized binary (leak present)', () => {
	it('recovers the full message with low noise and many probes', () => {
		const message = makeMessage(8, createRng(SEED));
		const res = runAttack(message, baseParams({ cacheNoise: 0.05, probes: 32, repeats: 7, noiseSpread: 0.3 }));
		expect(res.accuracySoft).toBe(1);
		expect(Array.from(res.recoveredSoft)).toEqual(Array.from(message));
	});

	it('is reproducible: same seed -> identical observations and recovery', () => {
		const message = makeMessage(8, createRng(SEED));
		const a = runAttack(message, baseParams({ rng: createRng(999) }));
		const b = runAttack(message, baseParams({ rng: createRng(999) }));
		expect(a.observations.map((o) => o.hitRate)).toEqual(b.observations.map((o) => o.hitRate));
		expect(Array.from(a.recoveredSoft)).toEqual(Array.from(b.recoveredSoft));
	});

	it('emits k*R observations and reports the codeword length and probe budget', () => {
		const message = makeMessage(6, createRng(SEED));
		const res = runAttack(message, baseParams({ messageBits: 6, repeats: 4, probes: 10 }));
		expect(res.observations.length).toBe(6 * 4);
		expect(res.codewordLength).toBe(6 * 4);
		expect(res.totalProbes).toBe(6 * 4 * 10);
	});

	it('reports the per-position heterogeneous flip probability on each observation', () => {
		const message = makeMessage(8, createRng(SEED));
		const res = runAttack(message, baseParams({ noiseSpread: 0.9 }));
		const probs = new Set(res.observations.map((o) => o.flipProb));
		// Heterogeneous noise -> many distinct flip probabilities.
		expect(probs.size).toBeGreaterThan(5);
	});
});

describe('the honesty fix: Soft-ISD must genuinely dominate hard-decision under heterogeneous noise', () => {
	// This is the regression test for the specific overclaim that was fixed:
	// under a SYMMETRIC repetition code with i.i.d. noise, soft and hard are
	// near-equivalent. The claim "reliability-aware decoding recovers the key
	// where a plain majority vote fails" is only honest when reliability varies
	// across positions. We assert Soft-ISD wins ON AVERAGE across many secrets
	// with spread>0, and is (near) tied when spread==0.

	function meanAccuracies(spread: number, trials: number) {
		let soft = 0;
		let hard = 0;
		for (let t = 0; t < trials; t++) {
			const msgRng = createRng(0x1000 + t);
			const noiseRng = createRng(0x9000 + t);
			const message = makeMessage(10, msgRng);
			const res = runAttack(message, {
				messageBits: 10,
				repeats: 11,
				cacheNoise: 0.3,
				probes: 12,
				optimized: true,
				noiseSpread: spread,
				rng: noiseRng,
			});
			soft += res.accuracySoft;
			hard += res.accuracyHard;
		}
		return { soft: soft / trials, hard: hard / trials };
	}

	it('with heterogeneous noise (spread=0.9), soft accuracy MATERIALLY exceeds hard on average', () => {
		const { soft, hard } = meanAccuracies(0.9, 200);
		expect(soft).toBeGreaterThan(hard);
		// The edge is substantial — this is the honesty fix. A near-zero gap would
		// mean the "Soft-ISD beats majority" narrative is unsupported (the old bug).
		expect(soft - hard).toBeGreaterThan(0.05);
	});

	it('with homogeneous noise (spread=0), soft and hard are near-equivalent (honest baseline)', () => {
		const { soft, hard } = meanAccuracies(0, 200);
		expect(Math.abs(soft - hard)).toBeLessThan(0.02);
	});

	it('soft never does dramatically worse than hard even in the homogeneous case', () => {
		const { soft, hard } = meanAccuracies(0, 200);
		expect(soft).toBeGreaterThanOrEqual(hard - 0.02);
	});
});

describe('runAttack — edge cases', () => {
	it('handles an empty message', () => {
		const res = runAttack(new Uint8Array(0), baseParams({ messageBits: 0 }));
		expect(res.observations.length).toBe(0);
		expect(res.accuracyHard).toBe(0);
		expect(res.accuracySoft).toBe(0);
		expect(res.bitsCorrectHard).toBe(0);
	});

	it('handles a single-bit message', () => {
		const res = runAttack(Uint8Array.from([1]), baseParams({ messageBits: 1, cacheNoise: 0.02, probes: 32, repeats: 5 }));
		expect(res.observations.length).toBe(5);
		expect(res.recoveredSoft[0]).toBe(1);
	});

	it('clamps repeats below 1 up to at least 1 position per bit', () => {
		const res = runAttack(Uint8Array.from([1, 0]), baseParams({ messageBits: 2, repeats: 0 }));
		expect(res.observations.length).toBe(2); // 2 bits * max(1, 0)
	});

	it('zero probes yields a degenerate hit-rate of 0 without throwing', () => {
		const res = runAttack(makeMessage(4, createRng(SEED)), baseParams({ messageBits: 4, probes: 0 }));
		for (const o of res.observations) expect(o.hitRate).toBe(0);
		expect(res.totalProbes).toBe(0);
	});
});
