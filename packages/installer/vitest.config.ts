import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    server: {
      // Vite 5's builtin list predates node:sqlite; keep the runtime module external.
      deps: { external: ['node:sqlite'] },
    },
  },
})
