// data.ts — narrative content for the HQC compiler-induced cache-timing lab.

export const FACTS = {
	scheme: 'HQC (Hamming Quasi-Cyclic)',
	status: 'NIST-selected code-based KEM (2025)',
	target: 'Official optimized (AVX2) implementation',
	channel: 'Flush+Reload cache side-channel',
	result: 'First cache-timing full-decryption oracle on a PQC scheme',
};

// The crux: source-level constant-time, broken by the optimizer.
export interface CodeView {
	label: string;
	tone: 'safe' | 'danger';
	caption: string;
	code: string;
}

export const SOURCE_VIEW: CodeView = {
	label: 'C source — constant-time',
	tone: 'safe',
	caption:
		'Mask-based conditional select: both candidate values are always read and combined with a bitmask. No branch on the secret, so every call touches the same memory — constant-time by construction.',
	code: `// bit is secret; mask = 0x00 or 0xFF
mask = -(bit & 1);              // 0 -> 0x00, 1 -> 0xFF
out  = (a & mask) | (b & ~mask); // reads BOTH a and b`,
};

export const COMPILED_VIEW: CodeView = {
	label: 'Clang -O3 — rewritten to a branch',
	tone: 'danger',
	caption:
		'The optimizer proves the mask equals a boolean and "helpfully" replaces the branchless select with an if/else. Now only one side is read per call, so the cache line touched depends on the secret bit — a leak the source never had.',
	code: `// optimizer rewrites the select into control flow
if (bit) out = a;   // touches cache line for a
else     out = b;   // touches cache line for b
// secret-dependent memory access -> Flush+Reload`,
};

export interface Step {
	num: number;
	title: string;
	body: string;
}

export const STEPS: Step[] = [
	{ num: 1, title: 'Flush', body: 'Attacker evicts the probed cache line from shared library memory (clflush).' },
	{ num: 2, title: 'Decode', body: 'Victim runs HQC decapsulation; the rewritten Reed–Muller select touches one line based on a secret bit.' },
	{ num: 3, title: 'Reload', body: 'Attacker re-reads the line and times it — fast = it was cached (branch taken), slow = a miss.' },
	{ num: 4, title: 'Soft-ISD', body: 'Noisy per-position predicates plus reliability weights are decoded into the full plaintext, then the key.' },
];

export interface TimelineEntry {
	year: string;
	title: string;
	leak: string;
	body: string;
	source?: { label: string; url: string };
}

export const TIMELINE: TimelineEntry[] = [
	{
		year: '2020',
		title: 'BCH decoder weight leak',
		leak: 'Runtime ∝ error weight',
		body: 'Wafo-Tapa et al. showed the non-constant-time BCH decoder’s runtime correlated with the error weight, giving a chosen-ciphertext timing oracle. The fix was a constant-time decoder.',
		source: { label: 'IACR ePrint 2020/1450', url: 'https://eprint.iacr.org/2020/1450' },
	},
	{
		year: '2023',
		title: 'Cache-timing on the decoder',
		leak: 'Data-dependent memory',
		body: 'Guo et al. (TCHES) demonstrated a cache-timing attack against HQC, recovering the key from data-dependent memory access in the decoding step — moving the threat from wall-clock timing to the cache.',
		source: { label: 'Guo et al., TCHES (ePrint 2023/102)', url: 'https://eprint.iacr.org/2023/102' },
	},
	{
		year: '2024',
		title: 'Divide and Surrender',
		leak: 'Variable-time division',
		body: 'Schröder et al. (USENIX) exploited a variable-time CPU division instruction in sampling. The fix: manual Barrett reduction so the step runs in constant time.',
		source: { label: '“Divide and Surrender”, USENIX 2024', url: 'https://www.usenix.org/conference/usenixsecurity24' },
	},
	{
		year: '2026',
		title: 'Compiler-induced cache leak',
		leak: 'Optimizer breaks constant-time',
		body: 'Dong & Guo showed the official optimized implementation — written in constant-time style — was rewritten by the compiler into a secret-dependent branch in the Reed–Muller decoder. A Flush+Reload oracle plus reliability-aware Soft-ISD gives the first cache-timing full-decryption key recovery on a PQC scheme. Constant-time source is not enough; the binary must preserve it.',
		source: { label: 'Dong & Guo, IACR ePrint 2026/693', url: 'https://eprint.iacr.org/2026/693' },
	},
];

export interface DefenseItem {
	title: string;
	body: string;
	good: boolean;
}

export const DEFENSES: DefenseItem[] = [
	{ good: true, title: 'Verify the binary, not just the source', body: 'Inspect the compiled output (and gate it in CI) for secret-dependent branches and memory accesses — the optimizer can undo source-level constant-time.' },
	{ good: true, title: 'Block harmful optimizations', body: 'Use compiler barriers, volatile/asm fences, or value-barrier helpers so the optimizer cannot infer the mask is a boolean and rewrite the select.' },
	{ good: true, title: 'Constant-time tooling', body: 'Run dynamic/static constant-time checkers (e.g. dudect-style, ctgrind, binsec/rel) on the shipped artifact across compilers and flags.' },
	{ good: false, title: 'Trust the source comment', body: '“This function is constant-time” in C says nothing about the binary the optimizer actually emits.' },
	{ good: false, title: 'Test one compiler / one flag set', body: 'A different compiler or -O level can reintroduce the branch; constant-timeness is per-binary, not per-source.' },
	{ good: false, title: 'Assume PQC math implies PQC safety', body: 'A hard lattice/code problem does not protect a leaky implementation; side channels ignore the math.' },
];

export interface Preset {
	id: string;
	label: string;
	desc: string;
	cacheNoise: number;
	probes: number;
	optimized: boolean;
}

export const PRESETS: Preset[] = [
	{ id: 'clean', label: 'Clean break', desc: 'Optimized binary, low cache noise, many probes. Full recovery.', cacheNoise: 0.08, probes: 24, optimized: true },
	{ id: 'noisy', label: 'Noisy co-tenant', desc: 'Optimized binary, heavy cache contention. Soft-ISD earns its keep.', cacheNoise: 0.32, probes: 16, optimized: true },
	{ id: 'few', label: 'Few probes', desc: 'Optimized but only a handful of Flush+Reload reads per position.', cacheNoise: 0.18, probes: 4, optimized: true },
	{ id: 'fixed', label: 'Constant-time binary', desc: 'Optimizer tamed — every probe hits, the channel is silent.', cacheNoise: 0.08, probes: 24, optimized: false },
];
