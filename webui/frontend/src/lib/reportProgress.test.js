import test from 'node:test'
import assert from 'node:assert/strict'
import { reportProgress } from './reportProgress.js'
test('legacy running reports use indeterminate progress', () => {
  const result = reportProgress({ status: 'running', format: 'pdf' })
  assert.equal(result.counted, false)
  assert.equal(result.message, 'Generating PDF report')
})
test('stage counts clamp and stale completed progress is ignored', () => {
  const progress = { phase: 'building', message: 'Rendering sections', completed: 12, total: 10, unit: 'sections' }
  assert.equal(reportProgress({ status: 'running', progress }).completed, 10)
  assert.equal(reportProgress({ status: 'failed', progress }).counted, false)
  assert.equal(reportProgress({ status: 'complete', progress }).message, 'Ready to download')
})
