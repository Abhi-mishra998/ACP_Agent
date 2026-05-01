import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const BACKEND = 'http://localhost:8000'

// All paths served by the gateway — proxied same-origin so cookies and CORS
// are never an issue in dev. In production the nginx container handles routing.
const API_PATHS = [
  '/auth', '/agents', '/dashboard', '/audit', '/billing', '/risk',
  '/decision', '/forensics', '/incidents', '/api-keys', '/auto-response',
  '/insights', '/system', '/execute', '/events', '/health', '/policy',
  '/usage', '/logs', '/stream',
]

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: 'localhost',
    open: true,
    proxy: Object.fromEntries(
      API_PATHS.map((path) => [
        path,
        { target: BACKEND, changeOrigin: true, secure: false },
      ])
    ),
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
