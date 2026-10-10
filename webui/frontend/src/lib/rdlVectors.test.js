import assert from 'node:assert/strict'
import test from 'node:test'
import { classifyVector, collectVectors } from './rdlVectors.js'

test('recorded request, upload, state and unresolved symbols have distinct categories', () => {
  for (const [symbol, category, label] of [
    ['$this->input->post', 'request', 'Form / POST'], ['$_POST[video_url]', 'request', 'Form / POST'],
    ['$_GET[query]', 'request', 'Query / GET'], ['request.args.get', 'request', 'Query / GET'],
    ['request.body', 'request', 'Request body'], ['req.params', 'request', 'Route parameter'],
    ['$_FILES[logo]', 'uploads', 'Upload'], ['request.files', 'uploads', 'Upload'],
    ['$_COOKIE[reg_data]', 'state', 'Cookie'], ['$_SESSION[token]', 'state', 'Session'],
    ['request.headers', 'headers', 'Header'], ['$_SERVER[HTTP_HOST]', 'headers', 'Header'],
    ['process.argv', 'process', 'Process input'], ['file_get_contents', 'data', 'File read'],
    ['request', 'other', 'Origin unresolved'], ['$request', 'other', 'Origin unresolved'],
    ['$quiz_id', 'other', 'Origin unresolved'], ['$filename', 'other', 'Origin unresolved'],
    ['$store->get', 'other', 'Origin unresolved'], ['$_POST[filename]', 'request', 'Form / POST'],
  ]) assert.deepEqual(classifyVector({ symbol }), { category, label }, symbol)
})

test('unknown input origins do not inherit API names from neighbouring snippets', () => {
  assert.equal(classifyVector({ symbol: '$value', snippet: [{ text: '$_POST["value"]' }] }).category, 'other')
  assert.equal(classifyVector({}).category, 'other')
})

test('same location keeps distinct inputs, and repeated inputs retain every linked path once', () => {
  const source = (symbol, line = 7, path = 'a.php') => ({ predicate: 'SOURCE', matched: true, symbol, location: { path, line } })
  const first = { id: '1', finding: { evidence: [source('$quiz_id'), source('$question_id'), source('$quiz_id')] } }
  const second = { id: '2', finding: { evidence: [source('$quiz_id'), source('$_POST[x]', 9), { ...source('ignored'), matched: false }, { predicate: 'SINK' }] } }
  const vectors = collectVectors([first, first, second])
  assert.equal(vectors.length, 3)
  assert.deepEqual(vectors.find(item => item.source.symbol === '$quiz_id').items.map(item => item.id), ['1', '2'])
  assert.equal(vectors.find(item => item.source.symbol === '$question_id').items.length, 1)
  assert.deepEqual(collectVectors([first, second]), collectVectors([first, first, second]))
})

test('path identity and line order remain stable and legacy trace evidence is supported', () => {
  const item = (id, path, line) => ({ id, finding: { trace: { steps: [{ predicate: 'SOURCE', symbol: 'request.body', location: { path, line } }] } } })
  const vectors = collectVectors([item('a', 'two.php', 10), item('b', 'one.php', 20), item('c', 'one.php', 2)])
  assert.deepEqual(vectors.map(v => [v.source.location.path, v.source.location.line]), [['one.php', 2], ['one.php', 20], ['two.php', 10]])
})
