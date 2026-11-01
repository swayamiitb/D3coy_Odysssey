import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        // The live stream (/api/stream) sends nothing until its first event or 15 s ping, and the dev proxy holds the
        // response headers until the first body bytes, so the console read "Offline" for 15 s. Flush them at once.
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes, _req, res) => {
            if (String(proxyRes.headers['content-type'] ?? '').startsWith('text/event-stream')) setImmediate(() => res.flushHeaders())
          })
        },
      },
    },
  },
})
