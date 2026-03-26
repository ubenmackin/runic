import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      }
    }
  },
  // Preview server configuration (for production build testing)
  preview: {
    proxy: {
      '/api': {
        target: 'https://localhost:60443',
        changeOrigin: true,
        secure: false, // Allow self-signed certificates
      }
    }
  },
  build: {
    outDir: '../internal/api/web/dist',
    emptyOutDir: true,
    sourcemap: false,
  }
})
