import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate for the load-bearing claims of the HQC cache-timing lab.
 *
 * The a11y spec proves the page is reachable; this one proves it is HONEST:
 * every headline verdict, counter and narration is checked against numbers the
 * page itself computed and rendered, not against strings hardcoded here. Where
 * a value must be hardcoded (the noiseless full-break case) the configuration
 * makes the outcome deterministic — flip probability 0 means every probe reads
 * the secret bit exactly, so "12/12" is forced by the model rather than hoped for.
 *
 * Nothing here asserts wall-clock timing; the "timing" in this lab is a
 * simulated cache hit-rate, so all assertions are on ordering and internal
 * consistency and are machine-independent.
 */

const BAR_RE =
  /^Position (\d+) \(message bit (\d+)\): secret bit ([01]), hit-rate (\d+)%, read as ([01]), (correct|wrong)$/;

interface Bar {
  position: number;
  messageBit: number;
  secretBit: number;
  hitPct: number;
  readAs: number;
  correct: boolean;
  green: boolean;
  heightPct: number;
}

interface Tally {
  ones: number;
  zeros: number;
  bit: number;
  ok: boolean;
}

interface RawBar {
  label: string;
  green: boolean;
  red: boolean;
  height: number;
}

interface LabStateBase {
  chip: string;
  verdict: string;
  soft: number;
  hard: number;
  k: number;
  probes: number;
  softPct: number;
  hardPct: number;
  chartFootnote: string;
  bridgeSay: string;
  recoveredBits: number[];
  actualBits: number[];
  seed: string;
  controls: { bits: number; repeats: number; noise: number; probeCount: number; spread: number; ct: boolean };
  outputs: string[];
  softVote: null | {
    bitIndex: number;
    rows: { hitPct: number; readAs: number; reliability: number; llr: number }[];
    majority: Tally;
    softTally: Tally & { sum: number };
    note: string;
  };
}

type RawState = LabStateBase & { bars: RawBar[] };
type LabState = LabStateBase & { bars: Bar[] };

/** Read everything the results panel currently claims, in one round trip. */
async function readLab(page: Page): Promise<RawState> {
  return page.evaluate(() => {
    const q = <T extends Element>(sel: string): T | null => document.querySelector<T>(sel);
    const txt = (sel: string): string => (q<HTMLElement>(sel)?.innerText ?? '').replace(/\s+/g, ' ').trim();
    const num = (s: string): number => parseFloat(s.replace(/,/g, '').replace(/[−–]/g, '-'));

    const pair = (sel: string): [number, number] => {
      const raw = q<HTMLElement>(sel)?.textContent ?? '';
      const m = raw.match(/(\d+)\s*\/\s*(\d+)/);
      return m ? [parseInt(m[1]!, 10), parseInt(m[2]!, 10)] : [NaN, NaN];
    };
    const [soft, k] = pair('.confusion-cell--tp .confusion-val');
    const [hard] = pair('.confusion-cell--fn .confusion-val');
    const probes = num(q<HTMLElement>('.confusion-cell--fp .confusion-val')?.textContent ?? 'NaN');

    const stat = txt('.recovery-stat');
    const statNums = stat.match(/([\d.]+)% Soft-ISD · ([\d.]+)% hard-decision/);

    const bars = [...document.querySelectorAll<HTMLElement>('.bar')].map((el) => ({
      label: el.getAttribute('aria-label') ?? '',
      green: el.classList.contains('bar--hit'),
      red: el.classList.contains('bar--miss'),
      height: parseFloat((el.getAttribute('style') ?? '').replace('--bar-height:', '').replace('%', '')),
    }));

    const bitRows = [...document.querySelectorAll('.bit-details .bit-row')].map((row) =>
      [...row.querySelectorAll('.bit')].map((b) => parseInt(b.textContent ?? '', 10)),
    );
    const actualFromLabels = [...document.querySelectorAll('.bit-details .bit-row')]
      .map((row) => [...row.querySelectorAll('.bit')])
      .at(1)
      ?.map((b) => parseInt((b.getAttribute('aria-label') ?? '').replace(/.*actual /, ''), 10)) ?? [];

    let softVote: unknown = null;
    const sv = q<HTMLElement>('.soft-vote');
    if (sv) {
      const intro = sv.querySelector('.soft-vote-intro')?.textContent ?? '';
      const bitIndex = parseInt(intro.match(/Message bit\s*(\d+)/)?.[1] ?? '-1', 10);
      const rows = [...sv.querySelectorAll('tbody tr')].map((tr) => {
        const cells = [...tr.querySelectorAll('td')];
        const nums = [...tr.querySelectorAll('.sv-num')].map((n) => n.textContent ?? '');
        return {
          hitPct: parseFloat(cells[0]?.textContent ?? 'NaN'),
          readAs: parseInt((cells[1]?.textContent ?? '').replace(/\D+/g, ''), 10),
          reliability: parseFloat(nums[0] ?? 'NaN'),
          llr: parseFloat((nums[1] ?? '').replace(/[−–]/, '-').replace('+', '')),
        };
      });
      const tallies = [...sv.querySelectorAll('.tally-cell')].map((t) => (t as HTMLElement).innerText.replace(/\s+/g, ' '));
      const maj = tallies[0] ?? '';
      const sft = tallies[1] ?? '';
      const majM = maj.match(/(\d+)×\s*1 vs (\d+)×\s*0 → (\d)/);
      const sftM = sft.match(/Σ = ([+\-−–])\s*([\d.]+) → (\d)/);
      softVote = {
        bitIndex,
        rows,
        majority: {
          ones: parseInt(majM?.[1] ?? '-1', 10),
          zeros: parseInt(majM?.[2] ?? '-1', 10),
          bit: parseInt(majM?.[3] ?? '-1', 10),
          ok: maj.includes('matches secret'),
        },
        softTally: {
          ones: -1,
          zeros: -1,
          sum: (sftM?.[1] === '+' ? 1 : -1) * parseFloat(sftM?.[2] ?? 'NaN'),
          bit: parseInt(sftM?.[3] ?? '-1', 10),
          ok: sft.includes('matches secret'),
        },
        note: sv.querySelector('.soft-vote-note')?.textContent?.replace(/\s+/g, ' ').trim() ?? '',
      };
    }

    return {
      chip: txt('.panel-card--wide .panel-header .vs-chip'),
      verdict: txt('.recovery-out .panel-copy'),
      soft,
      hard,
      k,
      probes,
      softPct: parseFloat(statNums?.[1] ?? 'NaN'),
      hardPct: parseFloat(statNums?.[2] ?? 'NaN'),
      bars,
      softVote,
      chartFootnote: txt('.timing-chart .section-footnote'),
      bridgeSay: txt('#bar-bridge-say'),
      recoveredBits: bitRows[0] ?? [],
      actualBits: actualFromLabels.length ? actualFromLabels : (bitRows[1] ?? []),
      seed: q<HTMLElement>('#seed-value')?.textContent ?? '',
      controls: {
        bits: parseInt((q<HTMLInputElement>('#bits')?.value ?? '0'), 10),
        repeats: parseInt((q<HTMLInputElement>('#repeats')?.value ?? '0'), 10),
        noise: parseInt((q<HTMLInputElement>('#noise')?.value ?? '0'), 10),
        probeCount: parseInt((q<HTMLInputElement>('#probes')?.value ?? '0'), 10),
        spread: parseInt((q<HTMLInputElement>('#spread')?.value ?? '0'), 10),
        ct: q<HTMLInputElement>('#ct')?.checked ?? false,
      },
      outputs: ['bits-val', 'repeats-val', 'noise-val', 'probes-val', 'spread-val'].map(
        (id) => document.getElementById(id)?.textContent ?? '',
      ),
    };
  }) as unknown as Promise<RawState>;
}

function parseBars(state: RawState): Bar[] {
  return state.bars.map((b) => {
    const m = b.label.match(BAR_RE);
    expect(m, `bar aria-label should describe the position: "${b.label}"`).not.toBeNull();
    return {
      position: parseInt(m![1]!, 10),
      messageBit: parseInt(m![2]!, 10),
      secretBit: parseInt(m![3]!, 10),
      hitPct: parseInt(m![4]!, 10),
      readAs: parseInt(m![5]!, 10),
      correct: m![6] === 'correct',
      green: b.green,
      heightPct: b.height,
    };
  });
}

async function state(page: Page): Promise<LabState> {
  const raw = await readLab(page);
  return { ...raw, bars: parseBars(raw) };
}

/** The live region is filled 50ms after render, so poll rather than snapshot. */
async function expectLive(page: Page, needle: string): Promise<void> {
  await expect
    .poll(() => page.evaluate(() => document.getElementById('live-status')?.textContent ?? ''), { timeout: 5_000 })
    .toContain(needle);
}

/** Run the lab and wait for the freshly rendered result panel. */
async function runAndWait(page: Page, action?: () => Promise<void>): Promise<void> {
  await page.evaluate(() => document.querySelector('.result-column')?.setAttribute('data-stale', '1'));
  if (action) await action();
  else await page.locator('#run').click();
  await expect(page.locator('.result-column:not([data-stale])')).toHaveCount(1, { timeout: 20_000 });
}

async function setControls(
  page: Page,
  v: { bits?: number; repeats?: number; noise?: number; probes?: number; spread?: number; ct?: boolean },
): Promise<void> {
  for (const [id, val] of Object.entries(v)) {
    if (id === 'ct') {
      const box = page.locator('#ct');
      if ((await box.isChecked()) !== val) await box.click();
      continue;
    }
    const sel = id === 'probes' ? '#probes' : `#${id}`;
    await page.locator(sel).fill(String(val));
    await page.locator(sel).dispatchEvent('input');
  }
}

/** Chance baseline the page itself uses: k/2 + 2 standard deviations. */
function guessBar(k: number): number {
  return k / 2 + 2 * Math.sqrt(k * 0.25);
}

async function openLab(page: Page): Promise<void> {
  await page.goto('.');
  // The first render is kicked off by the "Clean break" preset in a microtask.
  await expect(page.locator('.bar').first()).toBeVisible();
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
  });
}

test.describe('the leak', () => {
  test('a noiseless optimized run recovers every bit, and every bar encodes its own secret bit', async ({ page }) => {
    await openLab(page);
    // Cache noise 0 with no unevenness => flip probability 0 at every position,
    // so the hit-rate is exactly 1 for a secret 1 and exactly 0 for a secret 0.
    // Full recovery is forced by the model, not by luck of the seed.
    await setControls(page, { bits: 12, repeats: 5, noise: 0, probes: 8, spread: 0, ct: false });
    await runAndWait(page);
    await page.evaluate(() => {
      for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    });
    const s = await state(page);

    expect(s.chip).toBe('Full recovery');
    expect(s.verdict).toBe('Full plaintext recovered (12/12 bits (100%)) — a complete decryption oracle.');
    expect(s.soft).toBe(12);
    expect(s.hard).toBe(12);
    expect(s.k).toBe(12);
    expect(s.softPct).toBe(100);
    expect(s.hardPct).toBe(100);
    expect(s.probes).toBe(12 * 5 * 8);
    expect(s.bars).toHaveLength(12 * 5);

    // The chart's stated dual encoding: height = hit-rate = secret bit,
    // color = whether noise flipped the read. With zero noise nothing flips.
    for (const b of s.bars) {
      expect(b.hitPct, `position ${b.position}`).toBe(b.secretBit === 1 ? 100 : 0);
      expect(b.readAs).toBe(b.secretBit);
      expect(b.correct).toBe(true);
      expect(b.green).toBe(true);
      // Bar height mirrors the hit-rate, with a 2% floor so a 0% bar stays visible.
      expect(b.heightPct).toBeCloseTo(Math.max(2, b.hitPct), 5);
    }

    // The recovered bit row matches the actual message row, cell for cell.
    expect(s.recoveredBits).toHaveLength(12);
    expect(s.recoveredBits).toEqual(s.actualBits);
    // ...and the bars agree with the message they claim to have leaked.
    for (const b of s.bars) expect(b.secretBit).toBe(s.actualBits[b.messageBit]);

    await expectLive(page, 'Attack complete. Soft-ISD recovered 12 of 12 message bits, 100%.');
    expect(s.chartFootnote).toContain('Optimized binary');
  });

  test('recovery counters sum: Soft-ISD count equals the bits that actually match, probes equal the budget', async ({
    page,
  }) => {
    await openLab(page);
    for (const preset of ['clean', 'noisy', 'few']) {
      await runAndWait(page, () => page.locator(`.preset-chip[data-preset="${preset}"]`).click());
      await page.evaluate(() => {
        for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
      });
      const s = await state(page);
      const where = `preset ${preset}`;

      // Counter vs the bit-by-bit panel: the headline tally is the number of
      // recovered cells that equal the actual cell. Parts summing to the whole.
      const matching = s.recoveredBits.filter((b, i) => b === s.actualBits[i]).length;
      expect(s.soft, where).toBe(matching);
      expect(s.recoveredBits.length, where).toBe(s.k);
      expect(s.actualBits.length, where).toBe(s.k);

      // Probe budget = positions x probes per position.
      expect(s.probes, where).toBe(s.controls.bits * s.controls.repeats * s.controls.probeCount);
      expect(s.bars.length, where).toBe(s.controls.bits * s.controls.repeats);

      // Percentages are the counters, not independent numbers (rounded to whole %).
      expect(Math.abs(s.softPct - (s.soft / s.k) * 100), where).toBeLessThanOrEqual(0.5);
      expect(Math.abs(s.hardPct - (s.hard / s.k) * 100), where).toBeLessThanOrEqual(0.5);
      expect(s.hard, where).toBeLessThanOrEqual(s.k);

      // Green/red partition the bars, and red means exactly "the read disagrees
      // with the secret bit" — the legend's promise.
      const green = s.bars.filter((b) => b.green).length;
      const red = s.bars.length - green;
      expect(green + red, where).toBe(s.bars.length);
      expect(red, where).toBe(s.bars.filter((b) => !b.correct).length);
      for (const b of s.bars) {
        expect(b.green, `${where} position ${b.position}`).toBe(b.readAs === b.secretBit);
        // Threshold semantics: a bar reads 1 only when it is above the 50% line.
        expect(b.readAs, `${where} position ${b.position}`).toBe(b.hitPct > 50 ? 1 : 0);
      }

      // Every codeword position belongs to exactly one message bit, and each
      // message bit is carried by the configured redundancy.
      for (let i = 0; i < s.k; i++) {
        expect(s.bars.filter((b) => b.messageBit === i).length, `${where} bit ${i}`).toBe(s.controls.repeats);
      }
      await expectLive(page, `recovered ${s.soft} of ${s.k} message bits`);
    }
  });

  test('the verdict and status chip follow the numbers the page printed beside them', async ({ page }) => {
    await openLab(page);
    const configs = [
      { preset: 'clean' },
      { preset: 'noisy' },
      { preset: 'few' },
      { controls: { bits: 12, repeats: 7, noise: 40, probes: 32, spread: 100, ct: false } },
      { controls: { bits: 11, repeats: 3, noise: 30, probes: 2, spread: 80, ct: false } },
      { controls: { bits: 9, repeats: 5, noise: 0, probes: 16, spread: 0, ct: false } },
    ];

    for (const cfg of configs) {
      if (cfg.preset) {
        await runAndWait(page, () => page.locator(`.preset-chip[data-preset="${cfg.preset}"]`).click());
      } else {
        await setControls(page, cfg.controls!);
        await runAndWait(page);
      }
      const s = await state(page);
      const where = JSON.stringify(cfg);

      // Recompute the page's own decision inputs from what it rendered.
      const distinctRates = new Set(s.bars.map((b) => b.hitPct)).size;
      const beatsChance = distinctRates > 1 && s.soft > guessBar(s.k);
      const measured = `${s.soft}/${s.k} bits (${s.softPct}%)`;
      const chance = String(s.k / 2);
      const edge =
        s.soft > s.hard
          ? ` Reliability weighting recovered ${s.soft - s.hard} more bit${s.soft - s.hard === 1 ? '' : 's'} than a plain majority vote here.`
          : '';

      let expectedVerdict: string;
      let expectedChip: string;
      if (s.soft === s.k) {
        expectedVerdict = `Full plaintext recovered (${measured}) — a complete decryption oracle.${edge}`;
        expectedChip = 'Full recovery';
      } else if (s.soft / s.k > 0.8) {
        expectedVerdict = `Most of the message recovered (${measured}); add probes or redundancy to finish.${edge}`;
        expectedChip = beatsChance ? 'Partial' : 'No signal';
      } else if (beatsChance) {
        expectedVerdict = `Weak signal — ${measured}, still above the ~${chance} bits from guessing; raise probes/redundancy or lower cache noise.${edge}`;
        expectedChip = 'Partial';
      } else {
        expectedVerdict = `No usable signal — ${measured}, no better than the ~${chance} bits from guessing at this noise level.${edge}`;
        expectedChip = 'No signal';
      }

      expect(s.verdict, where).toBe(expectedVerdict);
      expect(s.chip, where).toBe(expectedChip);
      // A degraded run must say what to do about it, not just report a number.
      if (s.soft < s.k) {
        expect(s.verdict, where).toMatch(/add probes or redundancy|raise probes\/redundancy|from guessing/);
      }
      expect(s.verdict, where).not.toContain('NaN');
    }
  });
});

test.describe('the defense (constant-time binary)', () => {
  test('flipping the binary to constant-time silences the channel and says why', async ({ page }) => {
    await openLab(page);
    await runAndWait(page, () => page.locator('.preset-chip[data-preset="fixed"]').click());
    const s = await state(page);

    expect(s.controls.ct).toBe(true);
    expect(s.chip).toBe('Defended');
    // Every probe hits regardless of the secret: one hit-rate, no discrimination.
    expect(new Set(s.bars.map((b) => b.hitPct))).toEqual(new Set([100]));
    expect(s.bars.length).toBe(s.controls.bits * s.controls.repeats);
    // A bar is red exactly where the pinned read (1) disagrees with the secret.
    for (const b of s.bars) {
      expect(b.readAs).toBe(1);
      expect(b.green).toBe(b.secretBit === 1);
    }
    expect(s.verdict).toContain('Defense held');
    expect(s.verdict).toContain('carried no information');
    expect(s.verdict).toContain(`${s.soft}/${s.k} bits`);
    expect(s.chartFootnote).toContain('Constant-time binary');
    expect(s.chartFootnote).toContain('no information about the secret');
    expect(s.bridgeSay).toContain('touches both lines');
    await expectLive(page, 'channel silent');
    // The Soft-ISD-vs-majority trace is about reading a leak; there is none here.
    expect(await page.locator('.soft-vote').count()).toBe(0);
  });

  test('the recovery counters on a silent channel are the message weight, and both decoders agree', async ({
    page,
  }) => {
    await openLab(page);
    await setControls(page, { bits: 12, repeats: 5, noise: 30, probes: 8, spread: 90, ct: true });
    await runAndWait(page);
    await page.evaluate(() => {
      for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    });
    const s = await state(page);

    // With no discrimination both decoders emit the same constant vector, so
    // the two counters must be identical and equal the message's Hamming weight.
    expect(s.recoveredBits.every((b) => b === 1)).toBe(true);
    expect(s.soft).toBe(s.hard);
    expect(s.soft).toBe(s.actualBits.filter((b) => b === 1).length);
    expect(s.chip).toBe('Defended');
  });

  test('REGRESSION: a silent channel is never reported as a broken defense, however high the tally', async ({
    page,
  }) => {
    // Before the fix this failed: the constant-time run emits all-ones, so a
    // mostly-ones secret scored 10/12 and the page printed "Defense FAILED ... a
    // working constant-time decoder cannot produce this" over 60 identical bars.
    test.setTimeout(180_000);
    await openLab(page);
    await setControls(page, { bits: 12, repeats: 5, noise: 8, probes: 24, spread: 40, ct: true });
    await runAndWait(page);

    let maxSoft = 0;
    const bar = guessBar(12);
    for (let i = 0; i < 150; i++) {
      await runAndWait(page, () => page.locator('#reroll').click());
      const s = await state(page);
      maxSoft = Math.max(maxSoft, s.soft);
      expect(s.chip, `reroll ${i}`).toBe('Defended');
      expect(s.verdict, `reroll ${i} verdict: ${s.verdict}`).not.toContain('Defense FAILED');
      expect(s.verdict, `reroll ${i}`).toContain('Defense held');
      expect(new Set(s.bars.map((b) => b.hitPct)), `reroll ${i}`).toEqual(new Set([100]));
      if (s.soft > bar) {
        // The exact case that used to misfire: tally above the chance bar on a
        // channel that discriminated nothing.
        expect(s.verdict).toContain('carried no information');
      }
    }
    // Sanity: the sweep really did exercise a range of message weights.
    expect(maxSoft).toBeGreaterThan(6);
  });
});

test.describe('Soft-ISD vs majority vote', () => {
  test('the traced bit tallies are internally consistent with the rows above them', async ({ page }) => {
    await openLab(page);
    for (const preset of ['clean', 'noisy', 'few']) {
      await runAndWait(page, () => page.locator(`.preset-chip[data-preset="${preset}"]`).click());
      await page.evaluate(() => {
        for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
      });
      const s = await state(page);
      const where = `preset ${preset}`;
      expect(s.softVote, where).not.toBeNull();
      const sv = s.softVote!;

      // One row per carrying position, and the head-count splits across them.
      expect(sv.rows.length, where).toBe(s.controls.repeats);
      expect(sv.majority.ones + sv.majority.zeros, where).toBe(sv.rows.length);
      expect(sv.majority.ones, where).toBe(sv.rows.filter((r) => r.readAs === 1).length);
      expect(sv.majority.bit, where).toBe(sv.majority.ones * 2 > sv.rows.length ? 1 : 0);

      // Each row's reliability and LLR are functions of the hit-rate printed in
      // the same row: reliability = |p - 0.5| * 2, vote = ln(p / (1 - p)).
      for (const r of sv.rows) {
        const p = r.hitPct / 100;
        expect(r.reliability, `${where} row ${r.hitPct}%`).toBeCloseTo(Math.min(1, Math.abs(p - 0.5) * 2), 1);
        const clamped = Math.max(1e-3, Math.min(1 - 1e-3, p));
        expect(r.llr, `${where} row ${r.hitPct}%`).toBeCloseTo(Math.log(clamped / (1 - clamped)), 0);
        expect(r.readAs, `${where} row ${r.hitPct}%`).toBe(r.hitPct > 50 ? 1 : 0);
      }

      // The weighted tally is the sum of the votes shown, and decides by sign.
      const rowSum = sv.rows.reduce((a, r) => a + r.llr, 0);
      // Each printed vote is rounded to 2dp, so allow that much drift per row.
      expect(Math.abs(sv.softTally.sum - rowSum), `${where} Σ ${sv.softTally.sum} vs rows ${rowSum}`).toBeLessThan(
        0.006 * (sv.rows.length + 1),
      );
      if (Math.abs(sv.softTally.sum) > 0.005) {
        expect(sv.softTally.bit, where).toBe(sv.softTally.sum > 0 ? 1 : 0);
      }

      // The tick/cross flags are checked against the real secret bit shown in
      // the bit-by-bit panel — the two panels must not disagree.
      const trueBit = s.actualBits[sv.bitIndex];
      expect(trueBit, `${where} traced bit ${sv.bitIndex}`).not.toBeUndefined();
      expect(sv.majority.ok, where).toBe(sv.majority.bit === trueBit);
      expect(sv.softTally.ok, where).toBe(sv.softTally.bit === trueBit);
      // ...and against the bars that carry that bit.
      const carriers = s.bars.filter((b) => b.messageBit === sv.bitIndex);
      expect(carriers.length, where).toBe(sv.rows.length);
      expect(new Set(carriers.map((b) => b.secretBit)), where).toEqual(new Set([trueBit]));
      expect([...carriers].map((b) => b.hitPct).sort(), where).toEqual(sv.rows.map((r) => r.hitPct).sort());

      // The closing note matches which tally won.
      if (sv.softTally.ok && !sv.majority.ok) {
        expect(sv.note, where).toContain('won the head-count');
      } else if (sv.majority.bit === sv.softTally.bit) {
        expect(sv.note, where).toContain('both tallies agree');
      }
    }
  });

  test('the verdict claims a Soft-ISD edge only when the two counters differ', async ({ page }) => {
    await openLab(page);
    for (let i = 0; i < 12; i++) {
      await setControls(page, { bits: 12, repeats: 7, noise: 30, probes: 8, spread: 95, ct: false });
      await runAndWait(page);
      const s = await state(page);
      if (s.soft > s.hard) {
        expect(s.verdict).toContain(
          `Reliability weighting recovered ${s.soft - s.hard} more bit${s.soft - s.hard === 1 ? '' : 's'} than a plain majority vote here.`,
        );
      } else {
        expect(s.verdict).not.toContain('Reliability weighting recovered');
      }
    }
  });
});

test.describe('bar-to-branch bridge', () => {
  test('focusing a bar lights the matching branch line and narrates that position', async ({ page }) => {
    await openLab(page);
    await setControls(page, { bits: 8, repeats: 5, noise: 12, probes: 16, spread: 60, ct: false });
    await runAndWait(page);
    const s = await state(page);
    expect(s.bridgeSay).toContain('Hover or focus a bar');

    const bars = page.locator('.bar');
    const count = await bars.count();
    // Bring the chart into view once, so a later focus() cannot scroll a bar
    // under the pointer and fire a competing mouseenter.
    await bars.first().scrollIntoViewIfNeeded();
    // Sample across the chart, including the first and last position. Odd
    // indices are driven by hover, even ones by keyboard focus — the README
    // promises both gestures light the branch.
    const picks = [0, 1, Math.floor(count / 2), count - 1];
    for (const idx of picks) {
      const bar = s.bars[idx]!;
      if (idx % 2 === 1) {
        await bars.nth(idx).hover();
      } else {
        await page.mouse.move(0, 0); // park the pointer off the chart
        await bars.nth(idx).focus();
      }
      await expect(page.locator('.bar-bridge.is-active')).toHaveCount(1);
      const hot = page.locator('.bb-line--hot');
      await expect(hot).toHaveCount(1);
      // secret bit 1 -> the "if (bit)" line; secret bit 0 -> the else line.
      expect(await hot.getAttribute('data-line')).toBe(String(bar.secretBit));
      const say = (await page.locator('#bar-bridge-say').innerText()).replace(/\s+/g, ' ');
      expect(say).toContain(`Position ${bar.position}`);
      expect(say).toContain(`secret bit = ${bar.secretBit}`);
      expect(say).toContain(`touches line ${bar.secretBit === 1 ? 'a' : 'b'}`);
      expect(say).toContain(bar.secretBit === 1 ? 'HIT' : 'miss');
      expect(say).toContain(`${bar.hitPct}% over ${s.controls.probeCount} reads`);
      expect(say).toContain(bar.correct ? 'read correctly' : 'flipped by noise');
    }

    // Leaving the last-touched bar puts the panel back to its resting prompt.
    const last = picks[picks.length - 1]!;
    await page.mouse.move(0, 0);
    await bars.nth(last).focus();
    await expect(page.locator('.bar-bridge.is-active')).toHaveCount(1);
    await bars.nth(last).blur();
    await expect(page.locator('.bar-bridge.is-active')).toHaveCount(0);
    expect(await page.locator('#bar-bridge-say').innerText()).toContain('Hover or focus a bar');
  });
});

test.describe('reproducibility controls', () => {
  test('a locked seed replays the identical run; unlocking draws a new one', async ({ page }) => {
    await openLab(page);
    await runAndWait(page, () => page.locator('.preset-chip[data-preset="clean"]').click());
    await page.locator('#seed-lock').click();
    await expect(page.locator('#seed-lock')).toHaveAttribute('aria-pressed', 'true');

    const fingerprint = async () => {
      const s = await state(page);
      return {
        seed: s.seed,
        bars: s.bars.map((b) => `${b.position}:${b.secretBit}:${b.hitPct}`).join('|'),
        counts: `${s.soft}/${s.hard}/${s.probes}`,
        verdict: s.verdict,
      };
    };

    const first = await fingerprint();
    expect(first.seed).toMatch(/^0x[0-9a-f]{8}$/);
    await runAndWait(page);
    const second = await fingerprint();
    expect(second).toEqual(first);

    // "New secret" draws a fresh seed but leaves the lock engaged.
    await runAndWait(page, () => page.locator('#reroll').click());
    const rerolled = await fingerprint();
    expect(rerolled.seed).not.toBe(first.seed);
    await expect(page.locator('#seed-lock')).toHaveAttribute('aria-pressed', 'true');

    // ...and re-running still replays that new seed.
    await runAndWait(page);
    expect((await fingerprint()).seed).toBe(rerolled.seed);

    // Unlocking hands the seed back to the RNG.
    await page.locator('#seed-lock').click();
    await expect(page.locator('#seed-lock')).toHaveAttribute('aria-pressed', 'false');
    await runAndWait(page);
    expect((await fingerprint()).seed).not.toBe(rerolled.seed);
  });

  test('presets set the controls they advertise and mark themselves pressed', async ({ page }) => {
    await openLab(page);
    const expected: Record<string, { noise: number; probes: number; spread: number; ct: boolean }> = {
      clean: { noise: 8, probes: 24, spread: 40, ct: false },
      noisy: { noise: 30, probes: 16, spread: 95, ct: false },
      few: { noise: 18, probes: 4, spread: 70, ct: false },
      fixed: { noise: 8, probes: 24, spread: 40, ct: true },
    };
    for (const [id, want] of Object.entries(expected)) {
      await runAndWait(page, () => page.locator(`.preset-chip[data-preset="${id}"]`).click());
      const s = await state(page);
      expect(s.controls.noise, id).toBe(want.noise);
      expect(s.controls.probeCount, id).toBe(want.probes);
      expect(s.controls.spread, id).toBe(want.spread);
      expect(s.controls.ct, id).toBe(want.ct);
      // The slider outputs mirror the sliders, in the units the labels promise.
      expect(s.outputs, id).toEqual([
        String(s.controls.bits),
        String(s.controls.repeats),
        (want.noise / 100).toFixed(2),
        String(want.probes),
        (want.spread / 100).toFixed(2),
      ]);
      for (const other of Object.keys(expected)) {
        await expect(page.locator(`.preset-chip[data-preset="${other}"]`)).toHaveAttribute(
          'aria-pressed',
          other === id ? 'true' : 'false',
        );
      }
      // The probe budget tracks the preset's probe count.
      expect(s.probes, id).toBe(s.controls.bits * s.controls.repeats * want.probes);
    }
  });
});

test.describe('static claims the README makes', () => {
  test('the two-binaries panel shows a branchless source and the branchy compiled form', async ({ page }) => {
    await openLab(page);
    const cards = page.locator('#app .reuse-grid').first().locator('.panel-card');
    await expect(cards).toHaveCount(2);
    const source = cards.nth(0);
    await expect(source.locator('h3')).toContainText('constant-time');
    await expect(source.locator('.vs-chip')).toHaveText('no branch');
    await expect(source.locator('code')).toContainText('mask');
    await expect(source.locator('code')).not.toContainText('if (bit)');

    const compiled = cards.nth(1);
    await expect(compiled.locator('h3')).toContainText('-O3');
    await expect(compiled.locator('.vs-chip')).toHaveText('leaks');
    await expect(compiled.locator('code')).toContainText('if (bit) out = a;');
    await expect(compiled.locator('code')).toContainText('else     out = b;');
  });

  test('the leak timeline runs to the 2026 compiler-induced entry with its citation', async ({ page }) => {
    await openLab(page);
    const steps = page.locator('.attack-step');
    await expect(steps).toHaveCount(4);
    await expect(page.locator('.attack-year')).toHaveText(['2020', '2023', '2024', '2026']);
    const last = steps.nth(3);
    await expect(last.locator('h3')).toContainText('Compiler-induced cache leak');
    await expect(last.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/693');
  });

  test('the four Flush+Reload steps and the do/don’t guide are present', async ({ page }) => {
    await openLab(page);
    await expect(page.locator('.how-step')).toHaveCount(4);
    await expect(page.locator('.how-step h3')).toHaveText(['Flush', 'Decode', 'Reload', 'Soft-ISD']);
    await expect(page.locator('.trait-list--good li')).toHaveCount(3);
    await expect(page.locator('.trait-list--bad li')).toHaveCount(3);
    await expect(page.locator('.cache-primer')).toContainText('flushes');
    await expect(page.locator('.fs-lane--hit')).toContainText('fast');
    await expect(page.locator('.fs-lane--miss')).toContainText('slow');
    await expect(page.locator('.chart-legend li')).toHaveCount(3);
  });
});
