import test from 'node:test'
import assert from 'node:assert/strict'
import { graphWindow, graphStep, visibleNodes, evidenceText, graphSvg, GRAPH_WINDOW } from './flowGraphModel.js'
test('models preserve step order, repeated lines, inferred status and true file handoffs', () => {
 const steps=[{predicate:'SOURCE',location:{path:'a.php',line:2},symbol:'$q'},{predicate:'PROPAGATION',location:{path:'a.php',line:2},transition:'argument',inferred:true},{predicate:'SINK',location:{path:'b.php',line:9}}]
 const before=JSON.stringify(steps),m=graphWindow(steps)
 assert.equal(m.nodes.length,3);assert.equal(m.edges.length,2);assert.equal(m.edges[0].crossFile,false);assert.equal(m.edges[1].crossFile,true)
 assert.equal(m.nodes[1].inferred,true);assert.equal(m.nodes[2].tone,'sink');assert.equal(JSON.stringify(steps),before)
})
test('100,000-step trace visits bounded segments without evaluating unrelated records', () => {
 const steps=new Array(100000).fill({role:'propagation',file:'same.php',code:'step'})
 const middle=graphWindow(steps,50000),last=graphWindow(steps,99999)
 assert.equal(middle.nodes.length,GRAPH_WINDOW);assert.equal(last.end,100000);assert.equal(last.nodes.at(-1).index,99999)
 assert.equal(last.nodes[0].index,last.start);assert.equal(graphWindow(steps,-200).start,0)
 const sparse=new Array(100000);sparse[99999]={role:'sink',file:'last.php'}
 Object.defineProperty(sparse,0,{get(){throw new Error('Unrelated record evaluated')}})
 assert.equal(graphWindow(sparse,99999).nodes.at(-1).tone,'sink')
})
test('empty, malformed and unmet conditions do not fabricate source or sink',()=>{
 assert.equal(graphWindow(null).nodes.length,0);assert.equal(graphWindow([]).edges.length,0)
 assert.equal(graphStep(null,0).role,'evidence');assert.equal(graphStep({predicate:'SOURCE',matched:false},0).tone,'review')
 const m=graphWindow([{role:'call'},{role:'return'}]);assert.ok(m.nodes.every(n=>n.tone==='step'))
})
test('source excerpt identity and bounded inspection, with XML-safe SVG export',()=>{
 const m=graphWindow([{predicate:'SOURCE',symbol:'<script>&"',location:{path:'a.php',line:9},code:'<img onerror="evil()">',code_block:'code1'}])
 assert.equal(evidenceText(m.nodes[0],[{id:'wrong',path:'a.php',start:1,end:20,lines:[{line:9,text:'wrong snapshot'}]},{id:'code1',lines:[{line:9,text:'recorded'}]}]),'9  recorded\n')
 assert.equal(evidenceText(graphStep({code:'x'.repeat(1000000)},0)).length,16000)
 const svg=graphSvg(m);assert.ok(svg.includes('&lt;script&gt;'));assert.ok(!svg.includes('<img'));assert.ok(!svg.includes('<script>'))
 const visible=visibleNodes(m,{x:0,y:0,zoom:1},700,440);assert.equal(visible.length,1)
 assert.equal(visibleNodes(m,{x:0,y:-1000,zoom:1},700,440).length,0)
})
test('many source files stay within eight lanes without losing file identity',()=>{
 const m=graphWindow(Array.from({length:120},(_,i)=>({file:`file${i}.php`,role:'propagation'})))
 assert.equal(m.lanes.length,8);assert.equal(m.nodes.at(-1).path,'file119.php');assert.ok(m.width<2600)
})
