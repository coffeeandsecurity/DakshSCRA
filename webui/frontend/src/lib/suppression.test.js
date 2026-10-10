import test from 'node:test'
import assert from 'node:assert/strict'
import { suppressionDetails } from './suppression.js'

test('suppression version comes from recorded logic, never scan-wide selection', () => {
  assert.equal(suppressionDetails({ logic_engine: 'rdl', logic_source: 'logic/rdl/v1/php/test.rdl', rdl_engine: 'both' }).engine, 'RDL v1')
  assert.equal(suppressionDetails({ logic_engine: 'rdl_v2' }).engine, 'RDL v2')
  assert.equal(suppressionDetails({ rdl_text: 'VERSION 2\nWHEN PRESENT example' }).engine, 'RDL v2')
  assert.equal(suppressionDetails({ rdl_condition: 'RDL:logic\\rdl\\v1\\php\\test.rdl' }).engine, 'RDL v1')
  assert.equal(suppressionDetails({ logic_engine: 'rdl', rdl_engine: 'both' }).engine, 'RDL · version not recorded')
  assert.equal(suppressionDetails({ rdl_engine: 'v2' }).engine, 'Engine not recorded')
})

test('rule intent is not misrepresented as the suppression reason', () => {
  const item = { logic_reason: 'Detect untrusted input', suppression_reason: 'Required sink was missing' }
  assert.equal(suppressionDetails(item).reason, item.suppression_reason)
  assert.equal(suppressionDetails({ logic_reason: item.logic_reason }).reason, 'Suppression reason was not recorded for this finding.')
})
