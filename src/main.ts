import './style.css';
import './extra.css';
import { runAttack, makeMessage, createRng } from './engine.ts';
import { mountApp } from './ui.ts';

// Self-test: optimized binary leaks (Soft-ISD recovers); constant-time binary does not.
console.group('crypto-lab-hqc-timing-break: cache-channel self-test');
const msg = makeMessage(8, createRng(0x1234));
const leak = runAttack(msg, { messageBits: 8, repeats: 5, cacheNoise: 0.12, probes: 16, optimized: true, rng: createRng(0x9999) });
const fixed = runAttack(msg, { messageBits: 8, repeats: 5, cacheNoise: 0.12, probes: 16, optimized: false, rng: createRng(0x9999) });
console.log('Optimized binary     -> Soft-ISD:', (leak.accuracySoft * 100).toFixed(0) + '%', 'hard:', (leak.accuracyHard * 100).toFixed(0) + '%');
console.log('Constant-time binary -> Soft-ISD:', (fixed.accuracySoft * 100).toFixed(0) + '%', '(no usable signal)');
console.log('Total Flush+Reload probes:', leak.totalProbes.toLocaleString());
console.groupEnd();

mountApp(document.querySelector<HTMLDivElement>('#app')!);

(function initThemeToggle() {
	const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
	if (!button) return;
	function reflect(theme: string): void {
		document.documentElement.setAttribute('data-theme', theme);
		const isDark = theme === 'dark';
		const icon = button!.querySelector('span');
		const glyph = isDark ? '\u{1F319}' : '☀️';
		if (icon) icon.textContent = glyph;
		else button!.textContent = glyph;
		button!.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
		button!.setAttribute('aria-pressed', isDark ? 'true' : 'false');
	}
	function persist(theme: string): void {
		try {
			localStorage.setItem('theme', theme);
		} catch (e) {
			// localStorage may be blocked; non-fatal.
		}
	}
	function hasExplicitChoice(): boolean {
		try {
			return localStorage.getItem('theme') !== null;
		} catch (e) {
			return false;
		}
	}
	reflect(document.documentElement.getAttribute('data-theme') ?? 'dark');
	button.addEventListener('click', () => {
		const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
		reflect(next);
		persist(next);
	});
	const mql = window.matchMedia?.('(prefers-color-scheme: dark)');
	mql?.addEventListener?.('change', (e) => {
		if (hasExplicitChoice()) return;
		reflect(e.matches ? 'dark' : 'light');
	});
})();
