import React, { Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import FlowGraph from './components/FlowGraph'
import { GraphBoundary } from './components/FlowView'
const roots = new WeakMap()
const positions = new WeakMap()
let active = null
document.addEventListener('click', event => {
  const button = event.target.closest('[data-flow-mode]')
  if (!button) return
  const shell = button.closest('.report-flow-shell')
  const graph = shell.querySelector('[data-flow-graph]'), text = shell.querySelector('[data-flow-text]')
  const graphical = button.dataset.flowMode === 'graph'
  if (graphical && active && active !== shell) {
    const previous = active.querySelector('[data-flow-graph]')
    if (roots.has(previous)) { roots.get(previous).unmount(); roots.delete(previous) }
    previous.hidden = true; active.querySelector('[data-flow-text]').hidden = false
    active.querySelectorAll('[data-flow-mode]').forEach(item=>item.setAttribute('aria-pressed',String(item.dataset.flowMode==='text')))
  }
  if (graphical) active = shell
  else if (active === shell) active = null
  shell.querySelectorAll('[data-flow-mode]').forEach(item => item.setAttribute('aria-pressed', String(item === button)))
  text.hidden = graphical; graph.hidden = !graphical
  if (!graphical && roots.has(graph)) { roots.get(graph).unmount(); roots.delete(graph) }
  if (graphical && !roots.has(graph)) {
    try {
      const payload = JSON.parse(shell.querySelector('script[type="application/json"]').textContent)
      const root = createRoot(graph); roots.set(graph, root)
      root.render(<Suspense fallback={<p>Loading graph…</p>}><GraphBoundary><FlowGraph steps={payload.steps} blocks={payload.blocks || []} title={payload.title} initialStep={positions.get(graph) || 0} onSelection={index=>positions.set(graph,index)}/></GraphBoundary></Suspense>)
    } catch {
      graph.textContent = 'Graph could not be displayed. Use Text to inspect the saved evidence.'
    }
  }
})
