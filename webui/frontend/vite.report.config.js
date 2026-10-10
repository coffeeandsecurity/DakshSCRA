import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'

export default defineConfig({
  plugins: [react(), {
    name: 'font-licenses',
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'FONT-LICENSES.txt', source: readFileSync(new URL('./public/font-licenses.txt', import.meta.url), 'utf8') })
    },
  }],
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: {
    outDir: fileURLToPath(new URL('../../resources/analysis-ui', import.meta.url)),
    emptyOutDir: true,
    lib: {
      entry: fileURLToPath(new URL('./src/analysis-report.jsx', import.meta.url)),
      name: 'AnalysisReport',
      formats: ['iife'],
      fileName: () => 'analysis-report.js',
      cssFileName: 'analysis-report',
    },
  },
})
