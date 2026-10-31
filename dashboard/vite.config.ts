import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// LIVE mode talks to the Odyssey backend (the lead's FastAPI app). Point it elsewhere with ODYSSEY_API,
// e.g. a Live Share forwarded port:  ODYSSEY_API=http://127.0.0.1:8000 npm run dev
const target = process.env.ODYSSEY_API ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: { '/api': { target, changeOrigin: true } },
  },
})
