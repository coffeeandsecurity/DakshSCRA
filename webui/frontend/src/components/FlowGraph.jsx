import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { GRAPH_WINDOW, graphWindow, visibleNodes, evidenceLines, codeSegments, graphSvg, shortFile } from '../lib/flowGraphModel'
const colors = { source: '#38d9a9', sink: '#ff8796', guard: '#ffd166', review: '#ffd166', step: '#76aaff' }
const clamp = (value, low, high) => Math.max(low, Math.min(high, value))
const preview = (value, count = 34) => String(value || '').slice(0, count * 4).replace(/\s+/g, ' ').slice(0, count)
export default function FlowGraph({ steps = [], blocks = [], title, initialStep = 0, onSelection }) {
  const [selected, setSelected] = useState(initialStep), [jump, setJump] = useState('1'), [zoomLabel, setZoomLabel] = useState(100), [workspaceNotice, setWorkspaceNotice] = useState('')
  const total = Array.isArray(steps) ? steps.length : 0
  const index = clamp(selected, 0, Math.max(0, total - 1))
  const start = Math.floor(index / GRAPH_WINDOW) * GRAPH_WINDOW
  const model = useMemo(() => graphWindow(steps, start, blocks), [steps, start, blocks])
  const node = model.nodes.find(item => item.index === index)
  const evidence = useMemo(() => evidenceLines(node, blocks), [node, blocks])
  const sourceCode = useRef(null)
  useEffect(() => {
    const panel = sourceCode.current
    if (!panel) return
    let active = true
    const focusExpression = () => {
      if (!active) return
      const selectedLine = panel.querySelector('[data-selected="true"]')
      if (!selectedLine) return
      panel.scrollTop += selectedLine.getBoundingClientRect().top - panel.getBoundingClientRect().top - 36
      panel.scrollLeft = 0
      const expression = selectedLine.querySelector('mark')
      if (expression) panel.scrollLeft = Math.max(0, expression.getBoundingClientRect().left - panel.getBoundingClientRect().left - Math.min(80,panel.clientWidth/3))
    }
    focusExpression()
    document.fonts?.ready.then(focusExpression)
    const observer = new ResizeObserver(focusExpression)
    observer.observe(panel)
    return () => { active = false; observer.disconnect() }
  }, [index, evidence])
  const workspace = useRef(null)
  const canvas = useRef(null), mini = useRef(null), surface = useRef(null)
  const view = useRef({ x: 24, y: 24, zoom: 1 }), size = useRef({ width: 700, height: 440 }), raf = useRef(null), pointers = useRef(new Map()), gesture = useRef(null)
  const draw = useCallback(() => {
    raf.current = null
    const el = canvas.current, map = mini.current
    if (!el || !map) return
    const ctx = el.getContext('2d'), mc = map.getContext('2d')
    if (!ctx || !mc) return
    const {width, height} = size.current, v = view.current, ratio = Math.min(window.devicePixelRatio || 1, 2)
    if (el.width !== Math.round(width * ratio) || el.height !== Math.round(height * ratio)) { el.width = Math.round(width * ratio); el.height = Math.round(height * ratio) }
    ctx.setTransform(ratio,0,0,ratio,0,0);ctx.fillStyle='#0b1220';ctx.fillRect(0,0,width,height)
    ctx.fillStyle='#243047'
    const spacing=28;for(let x=((v.x%spacing)+spacing)%spacing;x<width;x+=spacing)for(let y=((v.y%spacing)+spacing)%spacing;y<height;y+=spacing)ctx.fillRect(x,y,1,1)
    ctx.save();ctx.translate(v.x,v.y);ctx.scale(v.zoom,v.zoom)
    model.lanes.forEach((path,i)=>{ctx.fillStyle='rgba(87,115,162,.08)';ctx.fillRect(22+i*304,0,288,model.height);ctx.fillStyle='#8b9fbd';ctx.font='11px monospace';ctx.fillText(preview(shortFile(path),35),36+i*304,38)})
    for(const edge of model.edges){
      const a=edge.from,b=edge.to;const sy=a.y+a.height,ey=b.y
      if(ey*v.zoom+v.y < -30 || sy*v.zoom+v.y > height+30)continue
      const x1=a.x+a.width/2,x2=b.x+b.width/2
      ctx.strokeStyle=edge.crossFile?'#ae9ce9':'#496587';ctx.lineWidth=2
      ctx.beginPath();ctx.moveTo(x1,sy);ctx.bezierCurveTo(x1,sy+22,x2,ey-22,x2,ey);ctx.stroke()
      ctx.beginPath();ctx.moveTo(x2-5,ey-8);ctx.lineTo(x2,ey-2);ctx.lineTo(x2+5,ey-8);ctx.stroke()
      if(edge.crossFile && v.zoom>.45){ctx.fillStyle='#c3b4ff';ctx.font='10px monospace';ctx.fillText('FILE HANDOFF',(x1+x2)/2+8,(sy+ey)/2)}
    }
    for(const n of visibleNodes(model,v,width,height)){
      const chosen=n.index===index
      ctx.fillStyle=chosen?'#1d3150':'#162337';ctx.strokeStyle=chosen?'#e2edff':colors[n.tone];ctx.lineWidth=chosen?2.5:1
      ctx.beginPath();if(ctx.roundRect)ctx.roundRect(n.x,n.y,n.width,n.height,10);else ctx.rect(n.x,n.y,n.width,n.height);ctx.fill();ctx.stroke()
      ctx.fillStyle=colors[n.tone];ctx.fillRect(n.x+1,n.y+12,3,n.height-24)
      if(v.zoom>.28){ctx.font='bold 11px monospace';ctx.fillText(`${n.index+1} · ${n.role.toUpperCase()}${n.inferred?' · INFERRED':''}`,n.x+14,n.y+22)
        ctx.fillStyle='#f0f5ff';ctx.font='bold 12px monospace';ctx.fillText(preview(n.symbol||n.title),n.x+14,n.y+45)
        ctx.fillStyle='#99b0ce';ctx.font='11px monospace';ctx.fillText(preview(shortFile(n.path),30)+(n.line?':'+n.line:''),n.x+14,n.y+68)
        let left=n.x+14
        const syntaxColors={keyword:'#c5a7ff',string:'#b5de9b',number:'#ffcb8b',comment:'#8698b4'}
        const parts=n.codePreview?.length?n.codePreview:[{text:preview(n.transition||'Select to inspect evidence')}]
        for(const part of parts){const width=ctx.measureText(part.text).width
          if(part.tainted){ctx.fillStyle=colors[n.tone]+'33';ctx.fillRect(left-1,n.y+80,width+2,16)}
          ctx.fillStyle=part.tainted?colors[n.tone]:syntaxColors[part.tone]||'#c1d0e7';ctx.fillText(part.text,left,n.y+92);left+=width}}
    }
    ctx.restore()
    mc.clearRect(0,0,160,112);mc.fillStyle='#101c2c';mc.fillRect(0,0,160,112)
    const sx=148/model.width,sy=100/model.height
    for(const n of model.nodes){mc.fillStyle=n.index===index?'#fff':colors[n.tone];mc.fillRect(6+n.x*sx,6+n.y*sy,Math.max(2,n.width*sx),Math.max(1.5,n.height*sy))}
    mc.strokeStyle='#d7e6ff';mc.lineWidth=1;mc.strokeRect(6+(-v.x/v.zoom)*sx,6+(-v.y/v.zoom)*sy,(width/v.zoom)*sx,(height/v.zoom)*sy)
  },[model,index])
  const schedule = useCallback(() => { if (raf.current === null) raf.current=requestAnimationFrame(draw) },[draw])
  useEffect(() => {
    if (!surface.current) return
    const observer=new ResizeObserver(entries=>{const rect=entries[0].contentRect;size.current={width:Math.max(1,rect.width),height:Math.max(1,rect.height)};schedule()})
    observer.observe(surface.current);schedule()
    return ()=>{observer.disconnect();if(raf.current!==null)cancelAnimationFrame(raf.current);raf.current=null}
  },[schedule])
  const previousSteps = useRef(steps)
  useEffect(()=>{if(previousSteps.current !== steps){setSelected(0);setJump('1');previousSteps.current=steps}},[steps])
  useEffect(()=>{onSelection?.(index)},[index,onSelection])
  useEffect(()=>{
    const n=model.nodes.find(item=>item.index===index)
    if(!n)return
    const s=size.current,v=view.current
    if(n.x*v.zoom+v.x<0 || (n.x+n.width)*v.zoom+v.x>s.width || n.y*v.zoom+v.y<0 || (n.y+n.height)*v.zoom+v.y>s.height){v.x=s.width/2-(n.x+n.width/2)*v.zoom;v.y=s.height/2-(n.y+n.height/2)*v.zoom}
    setJump(String(index+1));schedule()
  },[model,index,schedule])
  function focus(){if(!node)return;const s=size.current,v=view.current;v.zoom=1;v.x=s.width/2-(node.x+node.width/2)*v.zoom;v.y=s.height/2-(node.y+node.height/2)*v.zoom;setZoomLabel(100);schedule()}
  function fit(){const s=size.current,v=view.current;v.zoom=clamp(Math.min((s.width-40)/model.width,(s.height-40)/model.height),.02,1);v.x=(s.width-model.width*v.zoom)/2;v.y=(s.height-model.height*v.zoom)/2;setZoomLabel(Math.round(v.zoom*100));schedule()}
  function zoom(factor,point){const v=view.current,s=size.current,p=point||{x:s.width/2,y:s.height/2};const next=clamp(v.zoom*factor,.02,2.5);v.x=p.x-(p.x-v.x)*next/v.zoom;v.y=p.y-(p.y-v.y)*next/v.zoom;v.zoom=next;setZoomLabel(Math.round(next*100));schedule()}
  useEffect(()=>{
    const el=canvas.current
    if (!el) return
    const wheel=e=>{if(!e.ctrlKey && !e.metaKey)return;e.preventDefault();const rect=el.getBoundingClientRect();zoom(Math.exp(-clamp(e.deltaY,-80,80)*.01),{x:e.clientX-rect.left,y:e.clientY-rect.top})}
    el.addEventListener('wheel',wheel,{passive:false})
    return ()=>el.removeEventListener('wheel',wheel)
  },[schedule])
  function down(e){e.currentTarget.setPointerCapture(e.pointerId);pointers.current.set(e.pointerId,{x:e.clientX,y:e.clientY});gesture.current={x:e.clientX,y:e.clientY,originX:e.clientX,originY:e.clientY,dragged:false, distance:pointers.current.size===2?distance():null}}
  function distance(){const points=[...pointers.current.values()];return points.length===2?Math.hypot(points[0].x-points[1].x,points[0].y-points[1].y):0}
  function move(e){if(!pointers.current.has(e.pointerId)||!gesture.current)return;const g=gesture.current;pointers.current.set(e.pointerId,{x:e.clientX,y:e.clientY})
    if(pointers.current.size===2){const next=distance();if(g.distance)zoom(next/Math.max(1,g.distance));g.distance=next;g.dragged=true}
    else{view.current.x+=e.clientX-g.x;view.current.y+=e.clientY-g.y;g.dragged=g.dragged||Math.hypot(e.clientX-g.originX,e.clientY-g.originY)>4;schedule()}
    g.x=e.clientX;g.y=e.clientY
  }
  function up(e){const g=gesture.current;pointers.current.delete(e.pointerId)
    if(g&&!g.dragged&&e.type!=='pointercancel'){const rect=canvas.current.getBoundingClientRect(),v=view.current,x=(e.clientX-rect.left-v.x)/v.zoom,y=(e.clientY-rect.top-v.y)/v.zoom;const clicked=model.nodes.find(n=>x>=n.x&&x<=n.x+n.width&&y>=n.y&&y<=n.y+n.height);if(clicked)setSelected(clicked.index)}
    gesture.current=null;pointers.current.clear()
  }
  function key(e){if(['ArrowDown','ArrowUp','Home','End','+','-','f'].includes(e.key)){e.preventDefault();if(e.key==='ArrowDown')setSelected(clamp(index+1,0,total-1));else if(e.key==='ArrowUp')setSelected(clamp(index-1,0,total-1));else if(e.key==='Home')setSelected(0);else if(e.key==='End')setSelected(total-1);else if(e.key==='f')fit();else zoom(e.key==='+'?1.2:1/1.2)}}
  function download(){const blob=new Blob([graphSvg(model)],{type:'image/svg+xml'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=`flow-steps-${model.start+1}-${model.end}.svg`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
  if(!total)return <p className="flow-empty">No ordered trace steps were recorded. No graph connections can be established from this evidence.</p>
  return <div className="flow-graph" ref={workspace}>
    <div className="flow-graph-toolbar"><div className="flow-graph-tools"><button onClick={()=>zoom(1.2)} aria-label="Zoom in">＋</button><button onClick={()=>zoom(1/1.2)} aria-label="Zoom out">−</button><span>{zoomLabel}%</span><button onClick={fit}>Overview</button><button onClick={focus}>Focus step</button><button onClick={download}>{total>GRAPH_WINDOW ? 'Export segment SVG' : 'Export SVG'}</button><button onClick={()=>{if(document.fullscreenElement)document.exitFullscreen?.();else workspace.current?.requestFullscreen?.().catch(()=>setWorkspaceNotice('Fullscreen is unavailable in this browser. You can continue using the inline workspace.'))}}>Expand workspace</button></div><span className="flow-window-summary">Steps {model.start+1}–{model.end} of {total.toLocaleString()}</span></div>
    {workspaceNotice && <p className="flow-scope-note" role="status">{workspaceNotice}</p>}
    <div className="flow-graph-workspace"><div ref={surface} className="flow-canvas-surface">
      <canvas ref={canvas} tabIndex={0} role="img" aria-label={`${title}. Interactive recorded flow. Use Up/Down to select steps, Home/End for endpoints, plus/minus to zoom, f for overview.`} onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={up} onKeyDown={key}/>
      <div className="flow-canvas-hint">Drag to pan · Ctrl + scroll to zoom · select a block</div>
      <canvas className="flow-minimap" ref={mini} width="160" height="112" role="img" aria-label="Flow overview minimap" onClick={e=>{const rect=e.currentTarget.getBoundingClientRect(),v=view.current,s=size.current;v.x=s.width/2-(((e.clientX-rect.left)*160/rect.width-6)/148)*model.width*v.zoom;v.y=s.height/2-(((e.clientY-rect.top)*112/rect.height-6)/100)*model.height*v.zoom;schedule()}}/>
    </div><aside className="flow-inspector" aria-label="Selected step evidence">
      <div className="flow-inspector-top"><span className={`flow-role ${node?.tone}`}>{node?.role}</span><strong>Step {index+1}</strong></div>
      {node?.number !== index+1 && <p className="flow-scope-note">Recorded trace step: {node?.number}</p>}
      <h4>{(node?.symbol || node?.title || '').slice(0,1200)}</h4><p>{node?.title.slice(0,2400)}</p>
      <code className="flow-location">{node?.path || 'Location not recorded'}{node?.line ? ':'+node.line : ''}</code>
      {node?.original.matched === false && <p className="flow-scope-note">Recorded condition outcome: not satisfied.</p>}
      {node?.inferred && <p className="flow-scope-note">This step is marked inferred in the recorded analysis.</p>}
      {node?.transition && <p><strong>Transfer: </strong>{node.transition}</p>}
      {node?.original.source_symbol && <p><strong>Source symbol: </strong>{node.original.source_symbol}</p>}{node?.original.target_symbol && <p><strong>Target symbol: </strong>{node.original.target_symbol}</p>}
      <h5>Recorded source evidence</h5>{evidence.lines.length ? <>
        <p className="flow-code-legend">Highlighted row: selected step. {evidence.precise ? 'Marked text: recorded expression.' : evidence.symbolMatched ? 'Marked text: recorded symbol in this line.' : 'The exact expression span is unavailable in this excerpt.'}</p>
        <pre className={`flow-selected-code ${node?.tone}`} ref={sourceCode} tabIndex={0} aria-label="Source code with recorded expression highlights">{evidence.lines.map((line,i) => <span key={`${line.line}-${i}`} className={`flow-code-line${line.selected?' selected':line.highlighted?' recorded':''}`} data-selected={line.selected}>
          <span className="flow-code-number">{line.line || '?'}</span><code>{line.offset>0 && <span className="flow-code-omitted">…</span>}{codeSegments(line.text,line.spans).map((part,j) => part.tainted ? <mark className={`flow-taint flow-syntax-${part.tone}`} title="Recorded expression at this step" key={j}>{part.text}</mark> : <span className={`flow-syntax-${part.tone}`} key={j}>{part.text}</span>)}{line.clipped && <span className="flow-code-omitted">…</span>}</code>
        </span>)}</pre>
      </> : <p>No code excerpt was recorded for this step.</p>}
      {evidence.truncated && <p className="flow-scope-note">This panel shows a bounded excerpt around the selected location. Text mode retains the saved context.</p>}
      <div className="flow-step-navigation"><button disabled={index===0} onClick={()=>setSelected(index-1)}>Previous step</button><button disabled={index+1===total} onClick={()=>setSelected(index+1)}>Next step</button></div>
      <form className="flow-jump" onSubmit={e=>{e.preventDefault();const value=Number(jump);if(Number.isInteger(value)&&value>=1&&value<=total)setSelected(value-1)}}><label>Go to step<input aria-label="Go to step" type="number" min="1" max={total} value={jump} onChange={e=>setJump(e.target.value)}/></label><button>Go</button></form>
    </aside></div>
    <div className="flow-graph-footer"><span><i className="source"/>Source <i className="step"/>Evidence <i className="sink"/>Sink <i className="guard"/>Recorded guard/review</span><div><button disabled={model.start===0} onClick={()=>setSelected(Math.max(0,model.start-GRAPH_WINDOW))}>Previous segment</button><button disabled={model.end>=total} onClick={()=>setSelected(model.end)}>Next segment</button></div></div>
    <p className="flow-scope-note">Arrows show the recorded step order and file handoffs. Branches, execution reachability and protection are shown only when established in the underlying evidence. Every step remains reachable through the step controls; large traces are drawn in {GRAPH_WINDOW}-step segments.</p>
  </div>
}
