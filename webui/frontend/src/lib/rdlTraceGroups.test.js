import assert from 'node:assert/strict'
import test from 'node:test'
import { groupTraceSteps, traceActionLabels } from './rdlTraceGroups.js'

const step = (number, transition, path = 'functions/database_functions.php', line = 112, extra = {}) => ({ number, predicate: 'PROPAGATION', transition, symbol: `value${number}`, description: `Description ${number}.`, location: { path, line, column: number }, code_block: 'code-5', ...extra })
const block = { id: 'code-5', path: 'functions/database_functions.php', lines: [{ line: 112, text: '$row = mysqli_fetch_assoc($result);', highlight: true, steps: [18, 19, 20] }] }

test('read/call/assign merge into one highlighted excerpt without changing recorded actions', () => {
  const steps = [step(18, 'reference'), step(19, 'argument'), step(20, 'assignment')]
  const before = JSON.stringify({ steps, block })
  const groups = groupTraceSteps(steps, [block])
  assert.equal(groups.length, 1)
  assert.deepEqual(groups[0].steps, steps)
  assert.equal(groups[0].lines.length, 1)
  assert.equal(groups[0].lines[0].text, '$row = mysqli_fetch_assoc($result);')
  assert.equal(groups[0].lines[0].highlight, true)
  assert.deepEqual(groups[0].links, [{ block: 'code-5', line: 112 }])
  assert.deepEqual(traceActionLabels(groups[0].steps), ['Read', 'Call', 'Assign'])
  assert.equal(JSON.stringify({ steps, block }), before)
})

test('file identity, later line visits and missing locations prevent unsafe grouping', () => {
  const steps = [step(1, 'reference'), step(2, 'argument', 'other/database_functions.php'), step(3, 'assignment'), step(4, 'reference', undefined, 113), step(5, 'return'), step(6, 'return', undefined, 0), step(7, 'return', undefined, 0), step(8, 'return', undefined, 112, { location: null }), step(9, 'return', undefined, 112, { location: null })]
  assert.equal(groupTraceSteps(steps, [block]).length, steps.length)
})

test('source, call, return and sink remain ordered in a merged card', () => {
  const steps = [step(1, '', undefined, 112, { predicate: 'SOURCE' }), step(2, 'argument-parameter'), step(3, 'return'), step(4, 'return-call'), step(5, '', undefined, 112, { predicate: 'SINK' })]
  const groups = groupTraceSteps(steps, [block])
  assert.equal(groups.length, 1)
  assert.deepEqual(traceActionLabels(groups[0].steps), ['Input', 'Receive parameter', 'Return', 'Receive return', 'Sink'])
  assert.deepEqual(groups[0].steps.map(item => item.number), [1, 2, 3, 4, 5])
})

test('multiline ranges and different shared-block references retain all code and links', () => {
  const longer = { ...block, id: 'code-6', lines: [...block.lines, { line: 113, text: 'next line', highlight: true, steps: [2] }] }
  const steps = [step(1, 'reference'), step(2, 'assignment', undefined, 112, { location: { path: block.path, line: 112, end_line: 113 }, code_block: 'code-6' })]
  const [group] = groupTraceSteps(steps, [block, longer])
  assert.deepEqual(group.lines.map(line => line.line), [112, 113])
  assert.equal(group.links.length, 2)
})

test('conflicting recorded source text is not merged', () => {
  const changed = { ...block, id: 'code-6', lines: [{ line: 112, text: 'different source snapshot', highlight: true }] }
  assert.equal(groupTraceSteps([step(1, 'reference'), step(2, 'assignment', undefined, 112, { code_block: 'code-6' })], [block, changed]).length, 2)
})

test('legacy excerpts merge their context and highlight flags without dropping lines', () => {
  const snippet = [{ line: 111, text: 'before', highlight: false }, { line: 112, text: 'same line', highlight: false }]
  const steps = [step(1, 'reference', undefined, 112, { snippet }), step(2, 'assignment', undefined, 112, { snippet: [{ line: 112, text: 'same line', highlight: true }, { line: 113, text: 'after', highlight: false }] })]
  const [group] = groupTraceSteps(steps)
  assert.deepEqual(group.lines.map(line => [line.line, line.highlight]), [[111, false], [112, true], [113, false]])
  assert.equal(snippet[1].highlight, false)
})

test('repeated action labels are compacted with counts, without deleting actions', () => {
  const steps = [step(1, 'reference'), step(2, 'reference'), step(3, 'argument'), step(4, 'reference')]
  assert.deepEqual(traceActionLabels(steps), ['Read ×2', 'Call', 'Read'])
  assert.equal(groupTraceSteps(steps)[0].steps.length, 4)
})


test('detailed story keeps every same-line action and its exact metadata and code visible separately', () => {
  const steps = [step(1, '', undefined, 112, { predicate: 'SOURCE' }), step(2, 'assignment'), step(3, 'argument'), step(4, '', undefined, 112, { predicate: 'SINK' })]
  const before = JSON.stringify({ steps, block })
  const cards = groupTraceSteps(steps, [block], { mergeSameLine: false })
  assert.equal(cards.length, steps.length)
  cards.forEach((card, index) => {
    assert.deepEqual(card.steps, [steps[index]])
    assert.equal(card.lines[0].text, block.lines[0].text)
    assert.equal(card.lines[0].highlight, true)
    assert.deepEqual(card.links, [{ block: 'code-5', line: 112 }])
  })
  assert.equal(JSON.stringify({ steps, block }), before)
})
