import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    hookTimeout: 1_000_000,
    testTimeout: 6_000_000,
    retry: 0,
    pool: 'forks',
    env: { NODE_ENV: 'test' },
    exclude: ['**/node_modules/**', '**/system-tests/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json', 'lcov'],
      reportsDirectory: './coverage',
      exclude: [
        '**/node_modules/**',
        '**/*.config.*',
        '**/test/**',
        '**/generated/**',
      ],
      include: ['src/**/*.ts'],
      thresholds: {
        global: { branches: 50, functions: 50, lines: 50, statements: 50 },
      },
    },
  },
});
