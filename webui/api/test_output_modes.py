import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from . import main, scan_runtime
from .models import ScanRun


class WebOutputTests(TestCase):
    def test_web_launch_uses_private_mode_and_no_report_argument(self):
        cmd=scan_runtime.build_cmd({'rules':'auto','target_dir':'/source','report_format':'html,pdf'})
        self.assertNotIn('-rpt',cmd)
        with TemporaryDirectory() as d, patch.object(scan_runtime,'WEB_RUNS_DIR',Path(d)), \
                patch.object(scan_runtime.subprocess,'Popen') as popen, \
                patch.object(scan_runtime,'register_proc'), patch.object(scan_runtime,'unregister_proc'):
            popen.return_value.wait.return_value=0
            self.assertEqual(scan_runtime.execute_scan_sync(cmd,Path(d)/'scan.log','run','project'),0)
            self.assertEqual(popen.call_args.kwargs['env']['DAKSH_OUTPUT_MODE'],'web')

    def test_web_data_lookup_and_regeneration_do_not_create_reports(self):
        with TemporaryDirectory() as d, patch.object(scan_runtime,'WEB_RUNS_DIR',Path(d)), \
                patch.object(main,'run_dir',side_effect=scan_runtime.run_dir):
            results=Path(d)/'run'/'results';(results/'data').mkdir(parents=True)
            (results/'data'/'analysis.json').write_text(json.dumps({'results':[{'findings':[1]}]}))
            self.assertEqual(main._scan_data_dir('project','run'),results/'data')
            db=Mock();db.query.return_value.filter.return_value.first.return_value=ScanRun(run_uuid='run',project_key='project',status='success')
            with patch.object(main.core_reports,'gen_report') as generate:
                self.assertEqual(main.regenerate_reports('run',db)['status'],'not_required')
                generate.assert_not_called()
            self.assertFalse(list(results.rglob('*.html')))
