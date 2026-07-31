import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  base: '/install/',
  plugins: [react()],
  server: {
    port: 5002,
    proxy: {
      '/api': 'http://localhost:4002',
    },
  },
  worker: { format: 'es' },
  build: { outDir: 'dist-web' },
})
