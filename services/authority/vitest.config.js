// Vitest config for the authority service. hookTimeout is generous because the first run downloads a mongod
// binary for mongodb-memory-server (cached afterwards, see MONGOMS_DOWNLOAD_DIR).
import { defineConfig } from 'vitest/config';

const ci = Boolean(process.env.CI);

export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 180_000,
    reporters: ci ? ['default', 'junit'] : ['default'],
    outputFile: { junit: './test-results/junit.xml' },
  },
});
