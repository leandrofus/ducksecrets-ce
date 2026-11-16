import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `bun run dev` (make dev) proxies the API to the gateway on :5179 (DUCKSECRETS_PORT: make dev
// picks a free one), so the
// session cookie and the CSRF header work as in production. `bun run build`
// writes into the gateway, which embeds the result.
const api = `http://127.0.0.1:${(globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env.DUCKSECRETS_PORT ?? 5179}`

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: api, ws: true },
    },
  },
  build: { outDir: '../gateway/internal/server/ui/dist', emptyOutDir: true },
})
