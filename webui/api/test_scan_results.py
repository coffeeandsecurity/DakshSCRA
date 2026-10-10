"""Release result contracts must remain independent of experimental telemetry."""
import json
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from . import main
from .models import ScanRun


class ScanResultsTests(TestCase):
    def test_original_results_include_analysis_in_every_engine_mode(self):
        analysis = {
            'summary': {'confirmed_vulnerabilities': 2},
            'results': [{'engine': 'dataflow_controlflow', 'platform': 'php',
                         'security_inventory': {'finding_reviews': [
                             {'rule_id': 'php1', 'status': 'confirmed_vulnerability'}]},
                         'findings': [{'analysis_kind': 'taint_flow', 'trace': ['source', 'sink']}]}],
        }
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'analysis.json').write_text(json.dumps(analysis))
            (directory / 'areas_of_interest.json').write_text(json.dumps([{'rule_id': 'php1'}]))
            # Invalid experimental telemetry must not prevent the original views loading.
            (directory / 'runtime').mkdir()
            (directory / 'runtime' / 'rdl_shadow_comparisons.jsonl').write_text('{invalid')
            db = Mock()
            with patch.object(main, '_scan_data_dir', return_value=directory), \
                    patch.object(main, 'run_dir', return_value=directory), \
                    patch.object(main, '_scan_progress_payload', return_value={}):
                for mode in [None, 'v1', 'both', 'v2']:
                    with self.subTest(mode=mode):
                        db.query.return_value.filter.return_value.first.return_value = ScanRun(
                            run_uuid='saved', status='success', project_key='old', rdl_engine=mode)
                        payload = main.get_scan_findings('saved', db)
                        self.assertEqual(payload['analysis'], analysis)
                        self.assertEqual(payload['findings'], [{'rule_id': 'php1'}])
                        self.assertNotIn('rdl_shadow', payload)
                (directory / 'analysis.json').unlink()
                self.assertIsNone(main.get_scan_findings('saved', db)['analysis'])
                self.assertEqual(main.get_scan_findings('saved', db)['findings'], [{'rule_id': 'php1'}])

    def test_removed_scan_never_loads_old_analysis(self):
        db = Mock()
        db.query.return_value.filter.return_value.first.return_value = ScanRun(
            run_uuid='removed', status='success', data_removed_at=datetime.now())
        with patch.object(main, '_load_json_safe') as load:
            payload = main.get_scan_findings('removed', db)
        load.assert_not_called()
        self.assertTrue(payload['data_removed'])
        self.assertEqual(payload['findings'], [])
        self.assertIsNone(payload['analysis'])
