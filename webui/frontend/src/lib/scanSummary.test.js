import test from 'node:test'
import assert from 'node:assert/strict'
import { buildScanSummary, recordedNumber, recordedDuration } from './scanSummary.js'

test('missing or invalid numbers stay unknown while recorded zero remains zero', () => {
  for (const value of [undefined, null, '', '  ', true, false, [], {}, -1, Infinity, 'bad']) assert.equal(recordedNumber(value), null)
  assert.equal(recordedNumber('0'), 0)
  assert.equal(recordedNumber('813'), 813)
})
test('recorded stage duration is parsed without treating absent duration as zero', () => {
  assert.equal(recordedDuration('00Hr:40Min:32s:478ms'), 2432.478)
  assert.equal(recordedDuration(undefined), null)
  assert.equal(recordedDuration('not recorded'), null)
})
test('groups, evidence locations, unique files and suppressed records are separate metrics', () => {
  const m = buildScanSummary({ duration_sec: 60 }, { findings: [{ evidence: [{ file: 'a.php', line: 1 }, { file: 'a.php', matches: [{ line: 2 }, { line: 3 }] }] }], filepaths: [{ filepath: ['a.php', 'b.php'] }], scan_meta: { detection_summary: { total_files_scanned: '2', total_project_files_identified: '5', suppressed_findings: '7' } } }, 0)
  assert.equal(m.code, 1); assert.equal(m.paths, 1); assert.equal(m.areas, 2)
  assert.equal(m.locations, 3); assert.equal(m.evidenceFiles, 1)
  assert.equal(m.suppressed, 0); assert.equal(m.otherFiles, 3)
})
test('identified files never become files scanned and inconsistent scope is not graphed', () => {
  const m = buildScanSummary({}, { summary: { detection_summary: { total_files_identified: '8', total_project_files_identified: '5' } } })
  assert.equal(m.files, null); assert.equal(m.identified, 8); assert.equal(m.otherFiles, null)
  assert.equal(m.parserErrors, null); assert.equal(m.completed, null)
})
test('removed results retain configuration without displaying empty inventories as clean results', () => {
  const m = buildScanSummary({ rdl_engine: 'v2' }, { data_removed: true, findings: [], filepaths: [], loc_breakdown: [] }, 0)
  assert.equal(m.code, null); assert.equal(m.paths, null); assert.equal(m.suppressed, null)
  assert.equal(m.locations, null); assert.equal(m.evidenceFiles, null); assert.equal(m.mode, 'v2')
})
test('composition sums file counts and LOC separately and loaded rules keep their breakdown', () => {
  const m = buildScanSummary({}, { loc_breakdown: [{ path: 'a.php', loc: 7 }, { path: 'b.php', loc: 8 }, { path: 'c.js', loc: 3 }], scan_meta: { inputs_received: { total_rules_loaded: '82', platform_specific_rules: 'javascript[22], php[31]', common_rules: '24', framework_rules_count: '5' }, analyzer_summary: { targets_total: 3, targets_analyzed: 3, targets_failed: 0 } } })
  assert.deepEqual(m.languages, [{ label: 'PHP', files: 2, loc: 15 }, { label: 'JavaScript', files: 1, loc: 3 }])
  assert.equal(m.platformRules.reduce((sum, row) => sum + row.value, 0), 82)
  assert.equal(m.failed, 0); assert.equal(m.completed, 3)
})

test('partial runtime metadata retains metrics recorded in the saved report summary', () => {
  const m = buildScanSummary({}, { summary: { detection_summary: { total_files_scanned: '813', total_loc: '115363' } }, scan_meta: { detection_summary: { total_files_scanned: '812' } } })
  assert.equal(m.files, 812); assert.equal(m.loc, 115363)
})
