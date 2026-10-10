import assert from 'node:assert/strict'
import test from 'node:test'
import { flowEvidence, graphableFlow, collectPaths, collectReferences, handoffLabel } from './rdlReviewModels.js'
import { collectVectors } from './rdlVectors.js'

const step = (predicate, path, line, transition = '') => ({ predicate, matched: true, symbol: predicate === 'SOURCE' ? 'request.body' : 'value', location: { path, line }, transition })
const item = (id, steps) => ({ id, finding: { title: id, evidence: steps } })
const flow = [step('SOURCE', 'route.js', 1), step('PROPAGATION', 'service.js', 8, 'argument-parameter'), step('SINK', 'route.js', 3, 'return-call')]

test('each view projects a distinct unit while shared paths retain linked findings', () => {
  const items = [item('command', flow), item('other rule', flow), item('text', [step('TEXT_MATCHES', 'config.js', 1)]), item('local', [flow[0], step('SINK', 'route.js', 4)])]
  const original = structuredClone(items)
  const paths = collectPaths(items), refs = collectReferences(items), vectors = collectVectors(items)
  assert.equal(paths.length, 2)
  assert.equal(refs.length, 2)
  assert.equal(vectors.length, 1)
  assert.equal(paths[0].items.length, 2)
  assert.equal(refs[0].items.length, 2)
  assert.equal(vectors[0].items.length, 3)
  assert.deepEqual(items, original)
  assert.equal(handoffLabel(refs[0]), 'Argument → parameter')
  assert.equal(handoffLabel(refs[1]), 'Return → caller')
})

test('same-file calls are cross-references; ordinary propagation is not', () => {
  const call = item('call', [flow[0], step('PROPAGATION', 'route.js', 30, 'argument-parameter'), step('SINK', 'route.js', 32)])
  const local = item('local', [flow[0], step('PROPAGATION', 'route.js', 2, 'assignment'), step('SINK', 'route.js', 3)])
  const refs = collectReferences([call, local])
  assert.equal(refs.length, 1)
  assert.equal(refs[0].crossFile, false)
})

test('partial traces, failed sinks and missing locations are not invented as transfers', () => {
  const partial = item('partial', [flow[0], { ...flow[2], matched: false }])
  const paths = collectPaths([partial])
  assert.equal(paths.length, 1)
  assert.equal(paths[0].sink, undefined)
  assert.equal(collectReferences([partial]).length, 0)
  assert.equal(collectReferences([item('unknown', [flow[0], { predicate: 'SINK' }])]).length, 0)
})

test('empty evidence falls back to old trace records without merging distinct origins', () => {
  const old = { id: 'old', finding: { evidence: [], trace: { steps: flow } } }
  assert.equal(flowEvidence(old.finding).length, 3)
  assert.equal(collectReferences([old]).length, 2)
  assert.equal(collectVectors([old, item('other', [{ ...flow[0], location: { path: 'another.js', line: 1 } }])]).length, 2)
})

test('recorded trace wins over mixed conditions and text-only checks never become a flow', () => {
  const mixed = { evidence: [step('TEXT_MATCHES', 'route.js', 1), flow[0]], trace: { steps: [{ ...flow[0], number: 2 }, { ...flow[1], number: 4 }, { ...flow[2], number: 5 }, step('TEXT_MISSING', 'config.js', 1)] } }
  assert.deepEqual(flowEvidence(mixed).map(item => item.number), [2, 4, 5])
  assert.equal(flowEvidence({ evidence: [step('TEXT_MATCHES', 'route.js', 1)] }).length, 0)
  assert.equal(flowEvidence({ evidence: flow, trace: { steps: [step('TEXT_MATCHES', 'route.js', 1)] } }).length, 3)
})

test('graphs require a recorded source and continuation, retaining partial propagation', () => {
  assert.deepEqual(graphableFlow({ evidence: [step('TEXT_MATCHES', 'file.java', 2)] }), [])
  assert.deepEqual(graphableFlow({ evidence: [flow[0]] }), [])
  assert.deepEqual(graphableFlow({ evidence: [flow[2]] }), [])
  assert.deepEqual(graphableFlow({ evidence: [flow[0], { ...flow[2], matched: false }] }), [])
  assert.deepEqual(graphableFlow({ evidence: flow.slice(0, 2) }), flow.slice(0, 2))
  assert.deepEqual(graphableFlow({ evidence: [step('TEXT_MATCHES', 'route.js', 1), ...flow] }), flow)
})
