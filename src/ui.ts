// ui.ts — HQC compiler-induced cache-timing attack lab.
import { runAttack, makeMessage, createRng, randomSeed, formatSeed } from './engine.ts';
import type { SimParams, AttackResult } from './engine.ts';
import { FACTS, SOURCE_VIEW, COMPILED_VIEW, STEPS, TIMELINE, DEFENSES, PRESETS } from './data.ts';
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
	// shared site bar is the page's only banner.
	const hero = el('section', 'hero-panel');
	hero.setAttribute('aria-labelledby', 'hero-heading');
	hero.innerHTML = `
    <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light mode" aria-pressed="true">
      <span aria-hidden="true">\u{1F319}</span>
    </button>
    <div class="hero-copy">
      <a class="portfolio-badge" href="https://github.com/systemslibrarian?tab=repositories&q=crypto-lab" rel="noopener">
        <span aria-hidden="true">❖</span> crypto-lab · portfolio
      </a>
      <p class="eyebrow">Post-Quantum · Compiler &amp; Cache</p>
      <h1 id="hero-heading">HQC Cache-Timing Break</h1>
      <p class="hero-text">
        The official HQC implementation is written to be constant-time — but the compiler
        <em>optimizes the safety away</em>. At <code class="mono-inline">-O3</code> the mask-based
        select in the Reed–Muller decoder becomes a secret-dependent branch, leaking one cache
        line per bit. A <strong>Flush+Reload</strong> oracle reads those bits, and reliability-aware
        <strong>Soft-ISD</strong> turns the noise into a full plaintext recovery. Flip the binary
        back to constant-time and the channel goes silent.
      </p>
      <details class="why-details">
        <summary><span class="why-summary-text">Is this a real attack?</span></summary>
        <p>
          Yes. Dong &amp; Guo (IACR ePrint 2026/693, 2026) reported the first cache-timing
          <em>full-decryption oracle</em> key-recovery attack on a post-quantum scheme, against
          the official optimized HQC implementation. The leak is introduced by the compiler, not
          the source: secure mask-based selection is rewritten into data-dependent control flow.
          This lab models the <em>shape</em> of that attack with an abstract cache model and tiny
          parameters.
        </p>
      </details>
    </div>
    <aside class="hero-metric-card" aria-label="Attack at a glance">
      <p class="hero-metric-label">${FACTS.scheme}</p>
      <dl class="hero-stats">
        <div class="hero-stat-row"><dt>Status</dt><dd>${FACTS.status}</dd></div>
        <div class="hero-stat-row"><dt>Target</dt><dd>Optimized (AVX2) build</dd></div>
        <div class="hero-stat-row"><dt>Channel</dt><dd>Flush+Reload</dd></div>
        <div class="hero-stat-row"><dt>Result</dt><dd>Full-decryption oracle</dd></div>
      </dl>
      <p class="hero-metric-note">Constant-time source ≠ constant-time binary.</p>
    </aside>
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
      <pre class="code-block"><code>${esc(v.code)}</code></pre>
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
          Average enough probes, weight by reliability, and Soft-ISD reconstructs the message.
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
	};
	[bits, repeats, noise, probes].forEach((i) => i.addEventListener('input', sync));

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
			.map((o) => {
				const h = Math.max(2, o.hitRate * 100);
				const cls = o.hardBit === o.trueBit ? 'bar--hit' : 'bar--miss';
				const label = `Position ${o.position} (message bit ${o.messageBit}): hit-rate ${(o.hitRate * 100).toFixed(0)}%, read as ${o.hardBit}${o.hardBit === o.trueBit ? ', correct' : ', wrong'}`;
				return `<div class="bar ${cls}" style="--bar-height:${h}%" title="pos ${o.position}: ${(o.hitRate * 100).toFixed(0)}% ${o.hardBit === o.trueBit ? '✓' : '✗'}" aria-label="${label}"></div>`;
			})
			.join('');
		const footnote = params.optimized
			? 'Optimized binary: a probe mostly hits for secret bit 1 and misses for 0 — bars split above and below the 50% line.'
			: 'Constant-time binary: the select touches the probed line every time, so every bar pins near 100% — no information about the secret.';
		return `
      <div class="timing-chart">
        <div class="chart-area">
          <div class="threshold-line" style="bottom:50%"><span>hit / miss</span></div>
          ${bars}
        </div>
        <p class="section-footnote">${footnote}</p>
      </div>`;
	}

	function recovery(res: AttackResult, message: Uint8Array, params: SimParams): string {
		const soft = Array.from(res.recoveredSoft);
		const truth = Array.from(message);
		const cells = soft
			.map((b, i) => {
				const ok = b === truth[i];
				const cls = `bit ${b ? 'bit--set' : ''} ${ok ? '' : 'bit--wrong'}`.trim();
				return `<span class="${cls}" role="img" aria-label="Message bit ${i}: recovered ${b}${ok ? '' : ' (wrong)'}">${b}</span>`;
			})
			.join('');
		const truthCells = truth
			.map((b, i) => `<span class="bit ${b ? 'bit--set' : ''}" role="img" aria-label="Message bit ${i}: actual ${b}">${b}</span>`)
			.join('');
		const k = truth.length;
		const softPct = (res.accuracySoft * 100).toFixed(0);
		const hardPct = (res.accuracyHard * 100).toFixed(0);
		const verdict = !params.optimized
			? 'Defense held — the channel is silent, recovery is no better than guessing.'
			: res.accuracySoft === 1
				? 'Full plaintext recovered — a complete decryption oracle.'
				: res.accuracySoft > 0.8
					? 'Most of the message recovered; add probes or redundancy to finish.'
					: 'Weak signal — raise probes/redundancy or lower cache noise.';
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

	function chipFor(res: AttackResult, params: SimParams): { cls: string; text: string } {
		if (!params.optimized) return { cls: 'vs-chip vs-chip--stark', text: 'Defended' };
		if (res.accuracySoft === 1) return { cls: 'vs-chip vs-chip--snark', text: 'Full recovery' };
		return { cls: 'vs-chip vs-chip--tie', text: 'Partial' };
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
        </div>
      </div>`;
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
      Cache model is abstract: a Flush+Reload probe hits with probability (1 − cache-noise) when the
      leaked codeword bit is 1 and with probability (cache-noise) when it is 0; a constant-time binary
      pins every probe to a hit. The recovery contrasts plain majority with a reliability-weighted
      Soft-ISD step, mirroring the documented attack’s structure. Educational use only.
    </p>
    <p class="footer-links">
      <a href="https://github.com/systemslibrarian/crypto-lab-hqc-timing-break" rel="noopener">Source on GitHub</a>
      <span aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-hqc-timing/" rel="noopener">Sibling: HQC timing oracle</a>
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
