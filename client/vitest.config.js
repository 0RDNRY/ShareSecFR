import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

const ci = Boolean(process.env.CI);

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'node',
    testTimeout: 30_000,
    reporters: ci ? ['default', 'junit'] : ['default'],
    outputFile: { junit: './test-results/junit.xml' },
  },
});
