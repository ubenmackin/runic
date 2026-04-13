import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
plugins: [react()],
test: {
environment: 'jsdom',
globals: true,
setupFiles: ['./src/test/setup.js'],
  coverage: {
    provider: 'v8',
    reporter: ['text', 'json', 'html'],
    exclude: ['**/*.test.{js,jsx}', '**/test/**'],
    thresholds: {
'**/utils/**': {
branches: 70,
functions: 70,
lines: 70,
statements: 70,
},
'**/components/**': {
branches: 50,
functions: 50,
lines: 50,
statements: 50,
},
},
},
},
})
