// ui.ts — HQC compiler-induced cache-timing attack lab.
import { runAttack, makeMessage, createRng, randomSeed, formatSeed, llr } from './engine.ts';
import type { SimParams, AttackResult, PositionObs } from './engine.ts';
import { SOURCE_VIEW, COMPILED_VIEW, STEPS, TIMELINE, DEFENSES, PRESETS } from './data.ts';
import type { Preset, CodeView } from './data.ts';

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, html?: string): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (html !== undefined) node.innerHTML = html;
	return node;
}

function esc(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

let announceTimer: number | null = null;
function announce(message: string): void {
	const live = document.getElementById('live-status');
	if (!live) return;
	if (announceTimer !== null) window.clearTimeout(announceTimer);
	live.textContent = '';
	announceTimer = window.setTimeout(() => {
		live.textContent = message;
		announceTimer = null;
	}, 50);
}

function renderHero(): HTMLElement {
	// A labeled <section> (region landmark), not a second <header>/banner — the
	// shared site bar is the page's only banner. The inner .cl-hero is a plain
	// div (not <header>) so it adds no second banner landmark.
	const hero = el('section', 'hero-panel');
	hero.setAttribute('aria-labelledby', 'hero-heading');
	hero.innerHTML = `
    <div class="cl-hero">
      <div class="cl-hero-main">
        <h1 id="hero-heading" class="cl-hero-title">HQC Cache-Timing Break</h1>
        <p class="cl-hero-sub">HQC · Compiler-Induced Flush+Reload · IACR 2026/693</p>
        <p class="cl-hero-desc">Run a Flush+Reload oracle against a <code class="mono-inline">-O3</code> HQC binary whose constant-time mask-select the compiler rewrote into a secret-dependent branch, then watch reliability-weighted Soft-ISD decoding turn the noisy cache probes into full plaintext recovery.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">A source audited to be constant-time is not enough: the optimizer can silently reintroduce the leak in the shipped binary. This was the first cache-timing full-decryption oracle on a NIST post-quantum scheme, so hardening PQC means verifying the compiled artifact.</p>
      </aside>
    </div>
  `;
	return hero;
}

function codeCard(v: CodeView): string {
	return `
    <div class="panel-card">
      <div class="panel-header">
        <h3>${v.label}</h3>
        <span class="vs-chip ${v.tone === 'safe' ? 'vs-chip--stark' : 'vs-chip--snark'}">${v.tone === 'safe' ? 'no branch' : 'leaks'}</span>
      </div>
      <pre class="code-block" tabindex="0" role="region" aria-label="${v.label} source (scrollable)"><code>${esc(v.code)}</code></pre>
      <p class="panel-copy">${v.caption}</p>
    </div>`;
}

function renderDiff(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'diff-heading');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">The root cause</p>
        <h2 id="diff-heading">Same Source, Two Binaries</h2>
        <p class="section-footnote">
          The vulnerability is not in the algorithm or the C source — it is created by the optimizer.
          Identical source compiles to a constant-time binary or a leaking one depending on the flags.
        </p>
      </div>
    </div>
    <div class="reuse-grid">
      ${codeCard(SOURCE_VIEW)}
      ${codeCard(COMPILED_VIEW)}
    </div>
  `;
	return section;
}

function renderLab(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'playground-heading');
	section.id = 'lab';
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Live attack</p>
        <h2 id="playground-heading">Flush+Reload Oracle</h2>
        <p class="section-footnote">
          Each codeword position runs a secret-dependent select. On the optimized binary that select
          is a branch, so a Flush+Reload probe hits when the secret bit is 1 and misses when it is 0.
          Positions differ in how noisy their line is (set by <em>Noise unevenness</em>): a plain
          majority vote lets a cluster of ambiguous positions outvote the clean ones, while Soft-ISD
          weights each vote by its reliability. Raise unevenness and Soft-ISD pulls ahead of hard-decision.
        </p>
      </div>
    </div>

    <div class="preset-row" role="group" aria-label="Preset scenarios">
      <span class="preset-label">Start here:</span>
      ${PRESETS.map(
				(p) => `
        <button type="button" class="preset-chip" data-preset="${p.id}" aria-label="${p.label}: ${p.desc}">
          <span class="preset-chip-title">${p.label}</span>
          <span class="preset-chip-desc">${p.desc}</span>
        </button>`,
			).join('')}
    </div>

    <ol class="how-steps" aria-label="How the attack works">
      ${STEPS.map(
				(s) => `
      <li class="how-step">
        <span class="how-step-num" aria-hidden="true">${s.num}</span>
        <div><h3>${s.title}</h3><p>${s.body}</p></div>
      </li>`,
			).join('')}
    </ol>

    <div class="cache-primer" role="note" aria-labelledby="cache-primer-title">
      <p class="cache-primer-title" id="cache-primer-title">Why a cache <em>hit</em> leaks a secret</p>
      <p class="cache-primer-body">
        Attacker and victim share the same library page in memory. The attacker
        <strong>flushes</strong> that line out of cache (<code class="mono-inline mono-inline--tiny">clflush</code>),
        lets the victim's branch run, then <strong>re-reads</strong> the line and times it. If the victim's
        branch touched the line, it is back in cache and the re-read is <strong>fast</strong> — a
        <span class="fs-tag fs-tag--hit">HIT</span>. If not, the re-read pulls from RAM and is
        <strong>slow</strong> — a <span class="fs-tag fs-tag--miss">miss</span>. So a hit means
        <em>someone else touched this line recently</em>, and that "someone" is the secret-dependent branch.
      </p>
      <div class="fs-strip" aria-hidden="true">
        <div class="fs-lane fs-lane--hit">
          <span class="fs-lane-label"><span class="fs-tag fs-tag--hit">HIT</span> branch touched the line</span>
          <span class="fs-track"><span class="fs-marker fs-marker--fast">fast</span></span>
          <span class="fs-scale">← ~50 cycles (L1/L2)</span>
        </div>
        <div class="fs-lane fs-lane--miss">
          <span class="fs-lane-label"><span class="fs-tag fs-tag--miss">miss</span> branch skipped it</span>
          <span class="fs-track"><span class="fs-marker fs-marker--slow">slow</span></span>
          <span class="fs-scale">~200+ cycles (RAM) →</span>
        </div>
      </div>
      <p class="cache-primer-note">A single read is noisy, so the attacker repeats it many times per position — the <em>Probes per position</em> slider below.</p>
    </div>

    <form class="control-bar" id="lab-controls" aria-label="Attack simulation controls" onsubmit="return false">
      <div class="control-group">
        <label for="bits">Secret message bits
          <span class="control-help">plaintext the oracle recovers</span>
        </label>
        <div class="slider-row">
          <input id="bits" name="bits" type="range" min="4" max="12" value="8" />
          <output id="bits-val" class="mono-inline" for="bits">8</output>
        </div>
      </div>

      <div class="control-group">
        <label for="repeats">Inner-code redundancy
          <span class="control-help">positions per bit (Reed–Muller stand-in)</span>
        </label>
        <div class="slider-row">
          <input id="repeats" name="repeats" type="range" min="1" max="7" value="5" />
          <output id="repeats-val" class="mono-inline" for="repeats">5</output>
        </div>
      </div>

      <div class="control-group">
        <label for="noise">Cache noise
          <span class="control-help">probability a probe is misread</span>
        </label>
        <div class="slider-row">
          <input id="noise" name="noise" type="range" min="0" max="40" value="12" step="1" />
          <output id="noise-val" class="mono-inline" for="noise">0.12</output>
        </div>
      </div>

      <div class="control-group">
        <label for="probes">Probes per position
          <span class="control-help">Flush+Reload reads averaged</span>
        </label>
        <div class="slider-row">
          <input id="probes" name="probes" type="range" min="1" max="32" value="16" step="1" />
          <output id="probes-val" class="mono-inline" for="probes">16</output>
        </div>
      </div>

      <div class="control-group">
        <label for="spread">Noise unevenness
          <span class="control-help">how much per-position reliability varies — where Soft-ISD wins</span>
        </label>
        <div class="slider-row">
          <input id="spread" name="spread" type="range" min="0" max="100" value="60" step="1" />
          <output id="spread-val" class="mono-inline" for="spread">0.60</output>
        </div>
      </div>

      <div class="control-group control-group--toggle">
        <label class="toggle-wrap" for="ct">
          <input id="ct" name="ct" type="checkbox" />
          <span class="toggle-text">
            <span class="toggle-title">Constant-time binary</span>
            <span class="control-help">tame the optimizer — select touches both lines</span>
          </span>
        </label>
      </div>

      <div class="seed-row" role="group" aria-label="Run reproducibility">
        <span class="seed-label">Seed</span>
        <span id="seed-value" class="seed-value" aria-live="polite">—</span>
        <button id="seed-lock" type="button" class="seed-button" aria-pressed="false" aria-label="Lock seed so the same secret is reused on each run">
          <span class="seed-icon" aria-hidden="true">🔓</span>
          <span class="seed-button-text">Lock</span>
        </button>
        <button id="seed-copy" type="button" class="seed-button" aria-label="Copy seed to clipboard">
          <span class="seed-icon" aria-hidden="true">⧉</span>
          <span class="seed-button-text">Copy</span>
        </button>
      </div>

      <div class="control-group control-group--actions">
        <button id="reroll" class="ghost-button" type="button" aria-label="Generate a new random secret and re-run">
          <span aria-hidden="true">↻</span><span>New secret</span>
        </button>
        <button id="run" class="action-button" type="submit">
          <span aria-hidden="true">▶</span><span>Run Flush+Reload</span>
        </button>
      </div>
    </form>

    <div id="lab-results" class="lab-results lab-results--single" aria-live="off"></div>
  `;

	const $ = (id: string) => section.querySelector('#' + id) as HTMLElement;
	const bits = $('bits') as HTMLInputElement;
	const repeats = $('repeats') as HTMLInputElement;
	const noise = $('noise') as HTMLInputElement;
	const probes = $('probes') as HTMLInputElement;
	const spread = $('spread') as HTMLInputElement;
	const ct = $('ct') as HTMLInputElement;
	const runBtn = $('run') as HTMLButtonElement;
	const rerollBtn = $('reroll') as HTMLButtonElement;
	const seedLockBtn = $('seed-lock') as HTMLButtonElement;
	const seedCopyBtn = $('seed-copy') as HTMLButtonElement;
	const seedValue = $('seed-value');
	const labResults = $('lab-results');
	const form = $('lab-controls') as HTMLFormElement;

	const sync = () => {
		$('bits-val').textContent = bits.value;
		$('repeats-val').textContent = repeats.value;
		$('noise-val').textContent = (parseInt(noise.value, 10) / 100).toFixed(2);
		$('probes-val').textContent = probes.value;
		$('spread-val').textContent = (parseInt(spread.value, 10) / 100).toFixed(2);
	};
	[bits, repeats, noise, probes, spread].forEach((i) => i.addEventListener('input', sync));

	let currentSeed = randomSeed();
	let seedLocked = false;

	function refreshSeedChip(): void {
		seedValue.textContent = formatSeed(currentSeed);
		seedLockBtn.setAttribute('aria-pressed', seedLocked ? 'true' : 'false');
		seedLockBtn.classList.toggle('is-locked', seedLocked);
		const icon = seedLockBtn.querySelector('.seed-icon');
		const text = seedLockBtn.querySelector('.seed-button-text');
		if (icon) icon.textContent = seedLocked ? '🔒' : '🔓';
		if (text) text.textContent = seedLocked ? 'Locked' : 'Lock';
	}

	function chart(res: AttackResult, params: SimParams): string {
		const bars = res.observations
			.map((o, idx) => {
				const h = Math.max(2, o.hitRate * 100);
				const cls = o.hardBit === o.trueBit ? 'bar--hit' : 'bar--miss';
				const label = `Position ${o.position} (message bit ${o.messageBit}): secret bit ${o.trueBit}, hit-rate ${(o.hitRate * 100).toFixed(0)}%, read as ${o.hardBit}${o.hardBit === o.trueBit ? ', correct' : ', wrong'}`;
				return `<button type="button" class="bar ${cls}" style="--bar-height:${h}%" data-idx="${idx}" title="pos ${o.position}: secret ${o.trueBit}, ${(o.hitRate * 100).toFixed(0)}% ${o.hardBit === o.trueBit ? '✓' : '✗'}" aria-label="${label}"></button>`;
			})
			.join('');
		const footnote = params.optimized
			? 'Optimized binary: a probe mostly hits for secret bit 1 and misses for 0 — bars split above and below the 50% line.'
			: 'Constant-time binary: the select touches the probed line every time, so every bar pins near 100% — no information about the secret.';
		// [HIGH] Bridge: a compact copy of the compiled branch that lights up per
		// hovered/focused bar, tying one bar to one firing of the leaking select.
		return `
      <div class="timing-chart">
        <p class="chart-encoding" id="chart-encoding">
          <strong>Reading a bar.</strong> Height = probe hit-rate:
          <span class="enc-key enc-key--tall">tall = secret bit 1</span>,
          <span class="enc-key enc-key--short">short = secret bit 0</span>.
          Color = did noise flip the read:
          <span class="enc-key enc-key--hit">green = correct</span>,
          <span class="enc-key enc-key--miss">red = wrong</span>.
        </p>
        <div class="chart-area" aria-describedby="chart-encoding">
          <div class="threshold-line" style="bottom:50%"><span>hit / miss</span></div>
          ${bars}
        </div>
        <p class="section-footnote">${footnote}</p>
        <div class="bar-bridge" data-optimized="${params.optimized ? '1' : '0'}">
          <p class="bar-bridge-title">This bar is one firing of the leaking select</p>
          <pre class="bar-bridge-code" aria-hidden="true"><code><span class="bb-line" data-line="1">if (bit) out = a;   <span class="bb-note">// touches cache line for a</span></span>
<span class="bb-line" data-line="0">else     out = b;   <span class="bb-note">// touches cache line for b</span></span></code></pre>
          <p class="bar-bridge-say" id="bar-bridge-say" aria-live="polite">Hover or focus a bar to trace it back to the branch.</p>
        </div>
      </div>`;
	}

	function recovery(res: AttackResult, message: Uint8Array, params: SimParams): string {
		const soft = Array.from(res.recoveredSoft);
		const truth = Array.from(message);
		const cells = soft
			.map((b, i) => {
				const ok = b === truth[i];
				const cls = `bit ${b ? 'bit--set' : ''} ${ok ? '' : 'bit--wrong'}`.trim();
				return `<span class="${cls}" role="listitem" aria-label="Message bit ${i}: recovered ${b}${ok ? '' : ' (wrong)'}">${b}</span>`;
			})
			.join('');
		const truthCells = truth
			.map((b, i) => `<span class="bit ${b ? 'bit--set' : ''}" role="listitem" aria-label="Message bit ${i}: actual ${b}">${b}</span>`)
			.join('');
		const k = truth.length;
		const softPct = (res.accuracySoft * 100).toFixed(0);
		const hardPct = (res.accuracyHard * 100).toFixed(0);
		const softBeatsHard = res.bitsCorrectSoft > res.bitsCorrectHard;
		const edge = softBeatsHard
			? ` Reliability weighting recovered ${res.bitsCorrectSoft - res.bitsCorrectHard} more bit${res.bitsCorrectSoft - res.bitsCorrectHard === 1 ? '' : 's'} than a plain majority vote here.`
			: '';
		const verdict = !params.optimized
			? 'Defense held — the channel is silent, recovery is no better than guessing.'
			: res.accuracySoft === 1
				? 'Full plaintext recovered — a complete decryption oracle.' + edge
				: res.accuracySoft > 0.8
					? 'Most of the message recovered; add probes or redundancy to finish.' + edge
					: 'Weak signal — raise probes/redundancy or lower cache noise.' + edge;
		return `
      <ul class="confusion-row" aria-label="Recovery comparison">
        <li class="confusion-cell confusion-cell--tp"><span class="confusion-val">${res.bitsCorrectSoft}/${k}</span><span class="confusion-label">Soft-ISD</span></li>
        <li class="confusion-cell confusion-cell--fn"><span class="confusion-val">${res.bitsCorrectHard}/${k}</span><span class="confusion-label">hard-decision</span></li>
        <li class="confusion-cell confusion-cell--fp"><span class="confusion-val">${res.totalProbes.toLocaleString()}</span><span class="confusion-label">probes</span></li>
      </ul>
      <details class="bit-details">
        <summary>Show bit-by-bit recovery</summary>
        <p class="hero-metric-label hero-metric-label--spaced">Recovered (Soft-ISD)</p>
        <div class="bit-row" role="list" aria-label="Recovered message bits">${cells}</div>
        <p class="hero-metric-label hero-metric-label--spaced">Actual message</p>
        <div class="bit-row" role="list" aria-label="Actual message bits">${truthCells}</div>
      </details>
      <p class="recovery-stat"><strong>${softPct}%</strong> Soft-ISD · ${hardPct}% hard-decision</p>
      <p class="panel-copy">${verdict}</p>
    `;
	}

	// [HIGH] Soft-ISD explainer. For ONE message bit, expose the per-position
	// evidence the decoder actually uses: observed hit-rate, the reliability
	// weight |p-0.5|, and the signed LLR vote log(p/(1-p)). Then contrast the two
	// tallies the engine computes — a plain head-count (majority) vs the summed
	// LLR (Soft-ISD) — so the learner can SEE why weighting wins, not take it on
	// faith. Everything here is derived from the same observations runAttack
	// produced; nothing is fabricated.
	function pickInstructiveBit(res: AttackResult, message: Uint8Array): number {
		const k = message.length;
		if (k === 0) return 0;
		// Prefer a bit where Soft-ISD is right AND hard-decision is wrong: the
		// headline "reliability weighting rescues a bit majority loses" case.
		for (let i = 0; i < k; i++) {
			if (res.recoveredSoft[i] === message[i] && res.recoveredHard[i] !== message[i]) return i;
		}
		// Otherwise the bit whose positions have the widest reliability spread —
		// where the mechanism is most visible even if both decoders agree.
		let best = 0;
		let bestSpread = -1;
		for (let i = 0; i < k; i++) {
			const g = res.observations.filter((o) => o.messageBit === i);
			if (!g.length) continue;
			const rels = g.map((o) => o.reliability);
			const spread = Math.max(...rels) - Math.min(...rels);
			if (spread > bestSpread) {
				bestSpread = spread;
				best = i;
			}
		}
		return best;
	}

	function softVote(res: AttackResult, message: Uint8Array, params: SimParams): string {
		const k = message.length;
		if (k === 0 || !params.optimized) return '';
		const bitIdx = pickInstructiveBit(res, message);
		const group: PositionObs[] = res.observations.filter((o) => o.messageBit === bitIdx);
		if (!group.length) return '';

		const trueBit = message[bitIdx] ?? 0;
		const maxAbsLlr = Math.max(1e-6, ...group.map((o) => Math.abs(llr(o.hitRate))));
		const ones = group.reduce((a, o) => a + o.hardBit, 0);
		const zeros = group.length - ones;
		const majorityBit = ones * 2 > group.length ? 1 : 0;
		const llrSum = group.reduce((a, o) => a + llr(o.hitRate), 0);
		const softBit = llrSum > 0 ? 1 : 0;

		const rows = group
			.map((o) => {
				const l = llr(o.hitRate);
				const votesOne = l > 0;
				const rel = Math.min(1, o.reliability); // |p-0.5|*2 in 0..1
				const relPct = (rel * 100).toFixed(0);
				const llrPct = (Math.min(1, Math.abs(l) / maxAbsLlr) * 100).toFixed(0);
				const hardOne = o.hardBit === 1;
				return `
        <tr>
          <td class="sv-hit">${(o.hitRate * 100).toFixed(0)}%</td>
          <td>
            <span class="sv-chip ${hardOne ? 'sv-chip--one' : 'sv-chip--zero'}">reads ${o.hardBit}</span>
          </td>
          <td class="sv-barcell">
            <span class="sv-weight"><span class="sv-weight-fill" style="width:${relPct}%"></span></span>
            <span class="sv-num">${rel.toFixed(2)}</span>
          </td>
          <td class="sv-barcell">
            <span class="sv-llr sv-llr--${votesOne ? 'one' : 'zero'}"><span class="sv-llr-fill" style="width:${llrPct}%"></span></span>
            <span class="sv-num">${l >= 0 ? '+' : '−'}${Math.abs(l).toFixed(2)}</span>
          </td>
        </tr>`;
			})
			.join('');

		const majorityOk = majorityBit === trueBit;
		const softOk = softBit === trueBit;
		const rescued = softOk && !majorityOk;
		const note = rescued
			? `Here a cluster of low-reliability positions <strong>won the head-count</strong> (majority read ${majorityBit}) but their votes carry almost no weight, so the summed LLR still lands on the true bit ${trueBit}. That is the whole point of Soft-ISD.`
			: majorityBit === softBit
				? `On this bit both tallies agree (${softBit}). Raise <em>Noise unevenness</em> and re-run: as reliabilities spread out, look for a bit where the head-count and the weighted sum split.`
				: `The head-count and weighted sum disagree on this bit — reliability weighting overrides the raw vote count.`;

		return `
      <details class="soft-vote">
        <summary>Why Soft-ISD beats majority vote — trace one bit</summary>
        <p class="soft-vote-intro">
          Message bit <strong>${bitIdx}</strong> is carried by ${group.length} codeword positions.
          Each position reads a noisy 0 or 1. <strong>Majority vote</strong> counts those reads at full weight.
          <strong>Soft-ISD</strong> instead weights each by its reliability <span class="mono-inline mono-inline--tiny">|p−0.5|</span>
          and sums the signed log-likelihood vote <span class="mono-inline mono-inline--tiny">log(p/(1−p))</span>.
        </p>
        <div class="soft-vote-scroll" tabindex="0" role="region" aria-label="Per-position votes for the traced message bit (scrollable)">
          <table class="soft-vote-table">
            <caption class="sr-only">Per-position hit-rate, hard read, reliability weight, and signed LLR vote for message bit ${bitIdx}</caption>
            <thead>
              <tr>
                <th scope="col">Hit-rate</th>
                <th scope="col">Hard read</th>
                <th scope="col">Reliability |p−0.5|</th>
                <th scope="col">LLR vote</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <ul class="tally-row" aria-label="Tally comparison">
          <li class="tally-cell ${majorityOk ? 'tally-cell--ok' : 'tally-cell--bad'}">
            <span class="tally-label">Majority (head-count)</span>
            <span class="tally-val">${ones}×&hairsp;1 vs ${zeros}×&hairsp;0 → <strong>${majorityBit}</strong></span>
            <span class="tally-flag">${majorityOk ? '✓ matches secret' : '✗ wrong'}</span>
          </li>
          <li class="tally-cell ${softOk ? 'tally-cell--ok' : 'tally-cell--bad'}">
            <span class="tally-label">Soft-ISD (Σ LLR)</span>
            <span class="tally-val">Σ = ${llrSum >= 0 ? '+' : '−'}${Math.abs(llrSum).toFixed(2)} → <strong>${softBit}</strong></span>
            <span class="tally-flag">${softOk ? '✓ matches secret' : '✗ wrong'}</span>
          </li>
        </ul>
        <p class="soft-vote-note">${note}</p>
      </details>`;
	}

	function chipFor(res: AttackResult, params: SimParams): { cls: string; text: string } {
		if (!params.optimized) return { cls: 'vs-chip vs-chip--stark', text: 'Defended' };
		if (res.accuracySoft === 1) return { cls: 'vs-chip vs-chip--snark', text: 'Full recovery' };
		return { cls: 'vs-chip vs-chip--tie', text: 'Partial' };
	}

	// [HIGH] Attach hover/focus behavior to each bar so it lights up the matching
	// branch line in the mini compiled panel and narrates the causal chain for
	// that one position: secret bit -> which line the branch touches -> hit/miss.
	function wireBarBridge(res: AttackResult, params: SimParams): void {
		const bridge = labResults.querySelector('.bar-bridge');
		const say = labResults.querySelector('#bar-bridge-say');
		const bars = labResults.querySelectorAll<HTMLButtonElement>('.bar');
		if (!bridge || !say) return;
		const codeLines = bridge.querySelectorAll<HTMLElement>('.bb-line');
		const clear = () => {
			bridge.classList.remove('is-active');
			codeLines.forEach((c) => c.classList.remove('bb-line--hot'));
			say.textContent = params.optimized
				? 'Hover or focus a bar to trace it back to the branch.'
				: 'Constant-time binary: the select touches both lines regardless of the secret — no bar reveals a bit.';
		};
		const activate = (idx: number) => {
			const o = res.observations[idx];
			if (!o) return;
			bridge.classList.add('is-active');
			const line = o.trueBit === 1 ? 1 : 0;
			codeLines.forEach((c) => c.classList.toggle('bb-line--hot', c.dataset['line'] === String(line)));
			const touched = o.trueBit === 1 ? 'a' : 'b';
			const outcome = o.hardBit === o.trueBit ? 'read correctly' : 'flipped by noise';
			say.innerHTML = params.optimized
				? `Position ${o.position}: <strong>secret bit = ${o.trueBit}</strong> → branch touches line <strong>${touched}</strong> → probe ${o.trueBit === 1 ? '<span class="bb-hit">HIT</span>' : '<span class="bb-miss">miss</span>'} (${(o.hitRate * 100).toFixed(0)}% over ${params.probes} reads, ${outcome}).`
				: `Position ${o.position}: the constant-time select touches <strong>both</strong> lines, so this probe hits regardless of the secret bit — the bar carries no information.`;
		};
		bars.forEach((bar) => {
			const idx = parseInt(bar.dataset['idx'] ?? '-1', 10);
			bar.addEventListener('mouseenter', () => activate(idx));
			bar.addEventListener('focus', () => activate(idx));
			bar.addEventListener('mouseleave', clear);
			bar.addEventListener('blur', clear);
		});
		clear();
	}

	function render(message: Uint8Array, res: AttackResult, params: SimParams): void {
		const chip = chipFor(res, params);
		labResults.innerHTML = `
      <div class="result-column">
        <div class="panel-card panel-card--wide">
          <div class="panel-header">
            <h3>Per-position cache hit-rate</h3>
            <span class="${chip.cls}" role="status">${chip.text}</span>
          </div>
          <ul class="chart-legend" aria-label="Chart legend">
            <li><span class="legend-swatch legend-swatch--hit" aria-hidden="true"></span>Read correctly</li>
            <li><span class="legend-swatch legend-swatch--miss" aria-hidden="true"></span>Misread</li>
            <li><span class="legend-swatch legend-swatch--thr" aria-hidden="true"></span>50% hit/miss line</li>
          </ul>
          ${chart(res, params)}
        </div>
        <div class="panel-card">
          <h3>Recovery</h3>
          <div class="recovery-out">${recovery(res, message, params)}</div>
          ${softVote(res, message, params)}
        </div>
      </div>`;
		wireBarBridge(res, params);
		announce(
			params.optimized
				? `Attack complete. Soft-ISD recovered ${res.bitsCorrectSoft} of ${message.length} message bits, ${(res.accuracySoft * 100).toFixed(0)}%.`
				: `Constant-time binary: channel silent, ${(res.accuracySoft * 100).toFixed(0)}% — no better than chance.`,
		);
	}

	function run(): void {
		if (!seedLocked) currentSeed = randomSeed();
		refreshSeedChip();
		runBtn.disabled = true;
		runBtn.classList.add('is-running');
		runBtn.setAttribute('aria-busy', 'true');
		announce('Running Flush+Reload…');
		window.setTimeout(() => {
			try {
				const k = parseInt(bits.value, 10);
				const secret = makeMessage(k, createRng(currentSeed));
				const params: SimParams = {
					messageBits: k,
					repeats: parseInt(repeats.value, 10),
					cacheNoise: parseInt(noise.value, 10) / 100,
					probes: parseInt(probes.value, 10),
					noiseSpread: parseInt(spread.value, 10) / 100,
					optimized: !ct.checked,
					rng: createRng((currentSeed ^ 0xa5a5a5a5) >>> 0),
				};
				const res = runAttack(secret, params);
				render(secret, res, params);
			} finally {
				runBtn.disabled = false;
				runBtn.classList.remove('is-running');
				runBtn.removeAttribute('aria-busy');
			}
		}, 0);
	}

	form.addEventListener('submit', (e) => {
		e.preventDefault();
		run();
	});
	runBtn.addEventListener('click', (e) => {
		e.preventDefault();
		run();
	});
	rerollBtn.addEventListener('click', (e) => {
		e.preventDefault();
		currentSeed = randomSeed();
		const wasLocked = seedLocked;
		seedLocked = false;
		run();
		seedLocked = wasLocked;
		refreshSeedChip();
	});
	seedLockBtn.addEventListener('click', () => {
		seedLocked = !seedLocked;
		refreshSeedChip();
	});
	seedCopyBtn.addEventListener('click', async () => {
		try {
			await navigator.clipboard.writeText(formatSeed(currentSeed));
			const t = seedCopyBtn.querySelector('.seed-button-text');
			if (t) {
				const prev = t.textContent;
				t.textContent = 'Copied';
				window.setTimeout(() => {
					t.textContent = prev;
				}, 1200);
			}
		} catch (e) {
			// clipboard unavailable; non-fatal
		}
	});

	function applyPreset(p: Preset): void {
		noise.value = String(Math.round(p.cacheNoise * 100));
		probes.value = String(p.probes);
		spread.value = String(Math.round(p.noiseSpread * 100));
		ct.checked = !p.optimized;
		sync();
		section.querySelectorAll<HTMLButtonElement>('.preset-chip').forEach((b) => {
			const isActive = b.dataset['preset'] === p.id;
			b.classList.toggle('is-active', isActive);
			b.setAttribute('aria-pressed', isActive ? 'true' : 'false');
		});
		run();
	}
	section.querySelectorAll<HTMLButtonElement>('.preset-chip').forEach((btn) => {
		btn.addEventListener('click', () => {
			const preset = PRESETS.find((p) => p.id === btn.dataset['preset']);
			if (preset) applyPreset(preset);
		});
	});

	refreshSeedChip();
	queueMicrotask(() => applyPreset(PRESETS[0]!));
	return section;
}

function renderTimeline(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'timeline-heading');
	const items = TIMELINE.map((t) => {
		const cite = t.source
			? `<p class="attack-source"><a href="${t.source.url}" rel="noopener" target="_blank">${t.source.label} <span aria-hidden="true">↗</span></a></p>`
			: '';
		return `
    <article class="attack-step">
      <div class="attack-year" aria-hidden="true">${t.year}</div>
      <div class="attack-body">
        <div class="panel-header">
          <h3><span class="sr-only">${t.year}: </span>${t.title}</h3>
          <span class="vs-chip vs-chip--tie">${t.leak}</span>
        </div>
        <p class="panel-copy">${t.body}</p>
        ${cite}
      </div>
    </article>`;
	}).join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Real history</p>
        <h2 id="timeline-heading">How HQC Got Here</h2>
        <p class="section-footnote">Four documented timing/cache side-channels on HQC — the 2026 compiler-induced leak is the one this lab models, and the first cache-timing full-decryption oracle on PQC.</p>
      </div>
    </div>
    <div class="attack-flow">${items}</div>
  `;
	return section;
}

function renderDefenses(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'defenses-heading');
	const good = DEFENSES.filter((d) => d.good).map((d) => `<li><strong>${d.title}.</strong> ${d.body}</li>`).join('');
	const bad = DEFENSES.filter((d) => !d.good).map((d) => `<li><strong>${d.title}.</strong> ${d.body}</li>`).join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Mitigation</p>
        <h2 id="defenses-heading">Keeping the Binary Honest</h2>
      </div>
    </div>
    <div class="reuse-grid">
      <div class="panel-card">
        <h3 id="defenses-do"><span class="sr-only">Recommended: </span>Do</h3>
        <ul class="trait-list trait-list--good" aria-labelledby="defenses-do">${good}</ul>
      </div>
      <div class="panel-card">
        <h3 id="defenses-dont"><span class="sr-only">Avoid: </span>Don’t</h3>
        <ul class="trait-list trait-list--bad" aria-labelledby="defenses-dont">${bad}</ul>
      </div>
    </div>
    <div class="warning-banner" role="note">
      <span class="warning-icon" aria-hidden="true">⚠️</span>
      <span>Teaching simulation with an abstract cache model and tiny parameters — it shows the <em>shape</em> of the Dong &amp; Guo attack, not a working HQC exploit. Production HQC uses far larger parameters and a real Reed–Muller decoder.</span>
    </div>
  `;
	return section;
}

function renderFooter(): HTMLElement {
	const footer = el('footer', 'lab-section lab-section--footer');
	footer.setAttribute('role', 'contentinfo');
	footer.innerHTML = `
    <p class="section-footnote">
      Cache model is abstract: each codeword position gets its own misread probability (mean set by
      cache-noise, scattered by noise-unevenness to mimic quiet vs contended cache lines); a
      Flush+Reload probe then hits with probability (1 − that position's flip-prob) when the leaked
      codeword bit is 1 and with (flip-prob) when it is 0. A constant-time binary pins every probe to
      a hit. Because reliability genuinely varies across positions, the reliability-weighted Soft-ISD
      step meaningfully beats a plain majority vote — mirroring the documented attack's structure.
      The inner code here is a plain repetition code standing in for HQC's real Reed–Muller code, so
      the decoding is illustrative, not a faithful RM decoder. Educational use only.
    </p>
    <nav class="footer-related" aria-label="Related demos">
      <span class="footer-related-label">Related demos:</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-hqc-timing/" rel="noopener">HQC timing oracle</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-hqc-vault/" rel="noopener">HQC vault</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-kyberslash/" rel="noopener">KyberSlash</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-lattice-fault/" rel="noopener">Lattice fault</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-timing-oracle/" rel="noopener">Timing oracle</a>
    </nav>
    <p class="footer-links">
      <a href="https://github.com/systemslibrarian/crypto-lab-hqc-timing-break" rel="noopener">Source on GitHub</a>
      <span aria-hidden="true">·</span>
      <a href="https://github.com/systemslibrarian?tab=repositories&q=crypto-lab" rel="noopener">More crypto-lab demos</a>
    </p>
    <p class="scripture">“So whether you eat or drink or whatever you do, do it all for the glory of God.” — 1 Corinthians 10:31</p>
  `;
	return footer;
}

export function mountApp(root: HTMLDivElement): void {
	const shell = el('div', 'page-shell');
	shell.append(renderHero(), renderDiff(), renderLab(), renderTimeline(), renderDefenses(), renderFooter());
	root.appendChild(shell);
}
