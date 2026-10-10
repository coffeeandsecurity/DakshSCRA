"""Read-only saved-scan planning, report export and request validation."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from pydantic import ValidationError
from . import main
from .schemas import EffortPlanRequest, ScanCreate


class EffortPlanApiTests(unittest.TestCase):
    def row(self, **kwargs):
        return SimpleNamespace(**dict({'status': 'success', 'project_key': 'p', 'target_dir': '/src',
                                      'data_removed_at': None}, **kwargs))

    def database(self, row):
        db = MagicMock(); db.query.return_value.filter.return_value.first.return_value = row
        return db

    def test_new_estimate_scans_default_recon_loc_but_respect_opt_out(self):
        scan = ScanCreate(target_dir='/src', estimate=True, recon=False, loc=False)
        self.assertFalse(scan.recon); self.assertFalse(scan.loc)
        defaults = ScanCreate(target_dir='/src', estimate=True)
        self.assertTrue(defaults.recon); self.assertTrue(defaults.loc)
        from webui.api.scan_runtime import build_cmd
        command = build_cmd(scan.model_dump())
        self.assertIn('--no-recon', command); self.assertIn('--no-loc', command)
        self.assertNotIn('--recon', command); self.assertNotIn('--loc', command)

    def test_invalid_domains_and_rates_rejected(self):
        for fields in ({'domains': ['unknown']}, {'assumptions': {'hours_per_day': 0}}, {'mode': 'instant'}):
            with self.assertRaises(ValidationError):
                EffortPlanRequest(**fields)

    def test_missing_active_and_deleted_scan_guards(self):
        for row, code in ((None, 404), (self.row(status='running'), 409),
                          (self.row(data_removed_at='removed'), 410)):
            with self.assertRaises(HTTPException) as caught:
                main.get_effort_plan('r', self.database(row))
            self.assertEqual(code, caught.exception.status_code)

    def test_select_export_and_ai_keep_saved_artifacts_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); runtime = root / 'runtime'; data = root / 'results/data'
            runtime.mkdir(); data.mkdir(parents=True)
            (runtime/'filepaths.json').write_text('[{"path":"auth.py","loc":200}]')
            (data/'areas_of_interest.json').write_text(json.dumps([{'rule_title': 'Authentication',
                'evidence': [{'file': '/src/auth.py', 'line': 3}]}]))
            before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with patch.object(main, '_scan_data_dir', return_value=data), patch.object(main, 'run_dir', return_value=root):
                db = self.database(self.row())
                report = main.create_effort_plan('r', EffortPlanRequest(mode='targeted', domains=['authentication']), db)
                self.assertEqual(1, report['selected_workload']['active'])
                self.assertGreater(report['total_hours'][0], 0)
                response = main.download_effort_report('r', EffortPlanRequest(mode='manual'), db)
                self.assertIn('Review effort plan', response.body.decode())
                self.assertIn('attachment;', response.headers['content-disposition'])
                self.assertIsNone(main.create_effort_plan('r', EffortPlanRequest(mode='ai'), db)['total_hours'])
                self.assertEqual([0, 0], main.create_effort_plan('r', EffortPlanRequest(mode='targeted', domains=[]), db)['total_hours'])
            self.assertEqual(before, {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_failed_scan_keeps_uncertainty_visible(self):
        from core.effort import build_workload
        workload = build_workload([{'path': 'a', 'loc': 10}], complete=False)
        with patch.object(main, '_effort_workload', return_value=workload):
            report = main.get_effort_plan('r', self.database(self.row(status='failed')))
        self.assertEqual('evidence_limited', report['status'])
        self.assertTrue(any('incomplete' in text for text in report['warnings']))


if __name__ == '__main__':
    unittest.main()
