import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing. The whole point of this lab is what the Flush+Reload run
 *     PRODUCES — the per-position bar chart, the recovery tally, the verdict,
 *     the bit-by-bit disclosure and the Soft-ISD trace — and none of it is
 *     markup until a preset has been applied and a run has completed.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#lab-controls')).toBeVisible();
  await expect(page.locator('#run')).toBeVisible();
  // The lab applies its first preset in a microtask after mount, so a run's
  // results are part of first paint — assert they arrived rather than scanning
  // the empty results container.
  await expect(page.locator('#lab-results .timing-chart')).toBeVisible();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it renders `white-space: pre` C source alongside its `-O3`
 * compilation, a four-column LLR table, and one chart bar per codeword position
 * — 84 of them at the sliders' maxima.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab has that rule,
    // so written unchanged this oracle would be permanently green. Detect the
    // clipping directly instead of trusting the scroll geometry.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element, which is
    // exactly what happened here: the 980px comparison table was reported while
    // the real overflow was 15px of something else entirely.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is. With the viewport clipping,
    // falling back to the widest CLIPPED element would report a decoy forever.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}





/**
 * Run the lab and wait for the results it produces, not for a timeout.
 *
 * `run()` defers the simulation into a `setTimeout(0)` and disables the button
 * for the duration, so "the run finished" is exactly "the button is enabled
 * again and a chart is on the page".
 */
async function runAttack(page: Page): Promise<void> {
  await page.locator('#run').click();
  await expect(page.locator('#run')).toBeEnabled();
  await expect(page.locator('#lab-results .timing-chart')).toBeVisible();
  await expect(page.locator('#lab-results .bar').first()).toBeVisible();
}

/** Move a range input and wait for its `<output>` to echo the new value. */
async function setSlider(page: Page, id: string, value: string, shown: string): Promise<void> {
  await page.locator(`#${id}`).fill(value);
  await expect(page.locator(`#${id}-val`)).toHaveText(shown);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Everything below the controls is generated by a run, and the renderings
 * differ structurally — not just numerically — between branches:
 *
 *  - the four presets are four distinct verdicts. `Clean break` reaches full
 *    recovery, `Few probes` a partial or no-signal one, and `Constant-time
 *    binary` takes the OTHER arm of `chipFor`/`recovery` entirely: a
 *    `vs-chip--stark` "Defended" badge, the silent-channel wording, and
 *    `softVote()` returning an empty string so the Soft-ISD disclosure does not
 *    exist at all. A gate that only ever scanned the default preset never saw
 *    the defended branch, which is half of what this lab teaches.
 *  - the bar bridge has a resting and an active state, and the active one is
 *    reachable only by focusing or hovering a bar; it swaps in `.bb-line--hot`,
 *    `.bb-hit`/`.bb-miss` spans and a different narration.
 *  - both `<details>` (bit-by-bit recovery, the per-position LLR table) are
 *    closed until opened, and `.bit--wrong` cells only exist once noise has
 *    actually flipped a read.
 *  - the seed chip has a locked rendering (a different icon, label and
 *    `.is-locked` treatment) reachable only by clicking Lock.
 *
 * The seed is locked before the parameter sweeps so those states differ by the
 * parameter under test rather than by a fresh random secret.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint (clean break preset)`);

  // Both skip links only exist visually while focused.
  await page.locator('a.cl-skip-link').focus();
  await scan(page, `${theme} / header skip link focused`);
  await page.locator('a.skip-link').focus();
  await scan(page, `${theme} / lab skip link focused`);

  // The two source panels are `overflow-x: auto` scrollers holding `pre` text.
  await expect(page.locator('pre.code-block')).toHaveCount(2);

  // ── The bar bridge, resting and active ────────────────────────────────────
  await expect(page.locator('#bar-bridge-say')).toHaveText(
    'Hover or focus a bar to trace it back to the branch.'
  );
  await page.locator('#lab-results .bar').first().focus();
  await expect(page.locator('.bar-bridge.is-active')).toBeVisible();
  await expect(page.locator('.bb-line--hot')).toHaveCount(1);
  await scan(page, `${theme} / bar bridge traced to branch`);
  await page.locator('#lab-results .bar').first().blur();

  // ── Both disclosures under the default (leaking) preset ───────────────────
  await page.locator('details.bit-details > summary').click();
  await expect(page.locator('.bit-row').first()).toBeVisible();
  await scan(page, `${theme} / bit-by-bit recovery open`);

  await page.locator('details.soft-vote > summary').click();
  await expect(page.locator('.soft-vote-table tbody tr').first()).toBeVisible();
  await scan(page, `${theme} / Soft-ISD LLR trace open`);

  // ── The seed chip's locked rendering ──────────────────────────────────────
  await page.locator('#seed-lock').click();
  await expect(page.locator('#seed-lock')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#seed-lock .seed-button-text')).toHaveText('Locked');
  await scan(page, `${theme} / seed locked`);

  // Copy writes to the clipboard and flips the label for 1.2s. The write can be
  // refused by the permissions model, which the lab catches; either way the
  // control is exercised and whatever it renders is scanned.
  await page.locator('#seed-copy').click();
  await scan(page, `${theme} / seed copy pressed`);

  // ── All four presets ──────────────────────────────────────────────────────
  // Each re-runs on click, so a preset is both an input state and a verdict.
  for (const preset of ['clean', 'noisy', 'few', 'fixed'] as const) {
    await page.locator(`.preset-chip[data-preset="${preset}"]`).click();
    await expect(page.locator(`.preset-chip[data-preset="${preset}"]`)).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    await expect(page.locator('#run')).toBeEnabled();
    await expect(page.locator('#lab-results .timing-chart')).toBeVisible();
    await scan(page, `${theme} / preset: ${preset}`);

    // The bit-by-bit disclosure is re-rendered by every run, so re-open it and
    // scan this preset's cells — under `fixed` the recovered row is the one
    // that carries no signal, which is a different set of `.bit--wrong` cells.
    await page.locator('details.bit-details > summary').click();
    await expect(page.locator('.bit-row').first()).toBeVisible();
    await scan(page, `${theme} / preset: ${preset} — bits open`);
  }

  // `fixed` is still selected: assert the defended branch really rendered, and
  // that `softVote()` correctly produced nothing for a non-leaking run.
  await expect(page.locator('#lab-results .vs-chip--stark')).toHaveText('Defended');
  await expect(page.locator('details.soft-vote')).toHaveCount(0);
  await expect(page.locator('#bar-bridge-say')).toContainText('touches both lines');

  // ── The constant-time checkbox, driven directly rather than via a preset ──
  await page.locator('#ct').uncheck();
  await runAttack(page);
  await scan(page, `${theme} / optimized binary via checkbox`);
  await page.locator('#ct').check();
  await runAttack(page);
  await scan(page, `${theme} / constant-time binary via checkbox`);
  await page.locator('#ct').uncheck();

  // ── Slider extremes ───────────────────────────────────────────────────────
  // Lock the seed so these differ by the parameter, not by a new secret.
  await runAttack(page);

  // Widest possible chart: 12 message bits x 7 positions each = 84 bars.
  await setSlider(page, 'bits', '12', '12');
  await setSlider(page, 'repeats', '7', '7');
  await setSlider(page, 'probes', '32', '32');
  await runAttack(page);
  await expect(page.locator('#lab-results .bar')).toHaveCount(84);
  await scan(page, `${theme} / 84 positions, 32 probes`);

  await page.locator('details.bit-details > summary').click();
  await expect(page.locator('.bit-row').first().locator('.bit')).toHaveCount(12);
  await scan(page, `${theme} / 12 recovered bits open`);

  // The opposite corner: one probe per position at maximum noise and maximum
  // unevenness — the run that produces the weak/no-signal verdict wording.
  await setSlider(page, 'probes', '1', '1');
  await setSlider(page, 'noise', '40', '0.40');
  await setSlider(page, 'spread', '100', '1.00');
  await setSlider(page, 'repeats', '1', '1');
  await runAttack(page);
  await scan(page, `${theme} / one probe, maximum noise`);

  await page.locator('details.soft-vote > summary').click();
  await scan(page, `${theme} / Soft-ISD trace at maximum noise`);

  // The minimum message: 4 bits, no noise at all.
  await setSlider(page, 'bits', '4', '4');
  await setSlider(page, 'noise', '0', '0.00');
  await setSlider(page, 'spread', '0', '0.00');
  await runAttack(page);
  await scan(page, `${theme} / 4 bits, zero noise`);

  // ── New secret, with the seed unlocked again ──────────────────────────────
  await page.locator('#seed-lock').click();
  await expect(page.locator('#seed-lock')).toHaveAttribute('aria-pressed', 'false');
  await page.locator('#reroll').click();
  await expect(page.locator('#run')).toBeEnabled();
  await expect(page.locator('#lab-results .timing-chart')).toBeVisible();
  await scan(page, `${theme} / new secret rerolled`);
}
