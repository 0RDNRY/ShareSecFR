// Pairing-based crypto, PBKDF2 (600k iterations) and exhaustive subset tests are slow in pure JS.
import { defineConfig } from 'vitest/config';

const ci = Boolean(process.env.CI);

export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 60_000,
    hookTimeout: 60_000,
    reporters: ci ? ['default', 'junit'] : ['default'],
    outputFile: { junit: './test-results/junit.xml' },
  },
});
