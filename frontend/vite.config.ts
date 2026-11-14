import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Vendor code is grouped into a few stable chunks so the app bundle changes less often.
const vendorChunk = (id: string): string | undefined => {
  if (!id.includes('node_modules')) return undefined
  if (/node_modules\/(react|react-dom|scheduler)\//.test(id)) return 'react'
  if (/node_modules\/@tanstack\//.test(id)) return 'tanstack'
  if (/node_modules\/recharts\//.test(id)) return 'recharts'
  if (/node_modules\/react-force-graph-2d\//.test(id)) return 'forcegraph'
  if (/node_modules\/lucide-react\//.test(id)) return 'ui'
  return undefined
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: vendorChunk,
      },
    },
  },
})
