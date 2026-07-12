import { defineConfig } from 'vitest/config';

// Unit tests live in src/**. The Playwright a11y/E2E suite in e2e/ is run
// separately via `npm run test:a11y` and must NOT be collected by vitest.
export default defineConfig({
	test: {
		include: ['src/**/*.{test,spec}.ts'],
		exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
		environment: 'node',
	},
});
