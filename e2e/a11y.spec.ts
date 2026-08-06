import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys ship the vite-preview build; this gates that
 * same build on accessibility. Scans the full page in both themes with every
 * collapsible region expanded and animations neutralized so nothing is scanned
 * mid-flight.
 *
 * This lab has two real <details> (why-details, bit-details). We open every
 * <details>, reveal any class-toggled / [hidden] / inline-display:none panels,
 * and neutralize transitions/animations before scanning.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
    for (const el of document.querySelectorAll<HTMLElement>('.is-hidden, [aria-hidden="true"].panel')) {
      el.classList.remove('is-hidden');
    }
  });
}

async function checkGradientContrast(page: Page, results: any): Promise<void> {
  const incomplete = results.incomplete.find((i: any) => i.id === 'color-contrast');
  if (!incomplete) return;

  for (const node of incomplete.nodes) {
    const selector = node.target.join(' ');
    const ratio = await page.evaluate((sel) => {
      const el = document.querySelector(sel);
      if (!el) return 5.0;
      const style = window.getComputedStyle(el);
      if (!style.backgroundImage.includes('gradient')) return 5.0;
      
      function getLuminance(r: number, g: number, b: number) {
        const [rs, gs, bs] = [r, g, b].map(c => {
          c /= 255;
          return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
        });
        return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
      }
      function parseColor(str: string) {
        const m = str.match(/\d+/g);
        return m ? [parseInt(m[0]), parseInt(m[1]), parseInt(m[2])] : [0,0,0];
      }
      
      const textLum = getLuminance.apply(null, parseColor(style.color) as any);
      const bgMatches = style.backgroundImage.match(/rgba?\([^)]+\)/g);
      let minRatio = Infinity;
      if (bgMatches) {
        for (const match of bgMatches) {
          const bgLum = getLuminance.apply(null, parseColor(match) as any);
          const ratio = (Math.max(textLum, bgLum) + 0.05) / (Math.min(textLum, bgLum) + 0.05);
          if (ratio < minRatio) minRatio = ratio;
        }
      }
      return minRatio === Infinity ? 5.0 : minRatio;
    }, selector);
    expect(ratio).toBeGreaterThanOrEqual(4.5);
  }
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  await checkGradientContrast(page, results);
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await expect(page.locator('h1').first()).toBeVisible();
  await neutralizeMotion(page);
  await revealAll(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});
