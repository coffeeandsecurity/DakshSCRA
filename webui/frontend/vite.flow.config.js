import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
export default defineConfig({
  plugins:[react()], define:{'process.env.NODE_ENV':JSON.stringify('production')},
  build:{outDir:fileURLToPath(new URL('../../resources/analysis-ui',import.meta.url)),emptyOutDir:false,
    lib:{entry:fileURLToPath(new URL('./src/flow-report.jsx',import.meta.url)),name:'ReportFlowExplorer',formats:['iife'],fileName:()=> 'flow-graph.js'}}
})
