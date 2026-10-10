import json
import time
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch
from fastapi import HTTPException
from . import main, report_exports as exports
from .models import ScanRun

class ReportExportsTests(TestCase):
    def test_missing_selected_scope_is_not_replaced_with_summary(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); data = root / 'results/data'; data.mkdir(parents=True)
            (data / 'summary.json').write_text('{"detection_summary": {}}')
            for scope in ('findings', 'analysis', 'suppressed'):
                with self.assertRaisesRegex(ValueError, 'No saved data'):
                    exports.collect(data, root, scope, {'run_uuid': 'test'})
            self.assertIn('summary', exports.collect(data, root, 'full', {})['sections'])

    def test_all_formats_and_preserved_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            text = 'evidence <script>alert(1)</script> & final-marker'
            doc = {'report': 'Areas of interest', 'sections': {'evidence': text}}
            for fmt in ('html', 'pdf', 'docx', 'json'):
                path = root / ('report.' + fmt)
                exports.render(doc, path, fmt)
                self.assertGreater(path.stat().st_size, 100)
                if fmt == 'pdf': self.assertTrue(path.read_bytes().startswith(b'%PDF'))
                if fmt == 'docx':
                    with zipfile.ZipFile(path) as archive:
                        self.assertIn('final-marker', archive.read('word/document.xml').decode())
                if fmt == 'html':
                    self.assertNotIn('<script>alert', path.read_text())
                    self.assertIn('final-marker', path.read_text())
                if fmt == 'json': self.assertEqual(json.loads(path.read_text()), doc)

    def test_read_only_until_requested_and_background_job(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); data = root / 'results/data'; data.mkdir(parents=True)
            source = data / 'areas_of_interest.json'; source.write_text('[{"evidence":"keep"}]')
            before = source.read_bytes()
            self.assertEqual(exports.jobs(root), [])
            self.assertFalse((root / 'exports').exists())
            job = exports.start(root, data, exports.ReportRequest(format='json', scope='findings'), {'run_uuid':'test'})
            for _ in range(100):
                items = exports.jobs(root)
                if items[0]['status'] in ('complete', 'failed'): break
                time.sleep(.02)
            self.assertEqual(items[0]['status'], 'complete', items)
            self.assertEqual(source.read_bytes(), before)
            payload = json.loads((root / 'exports' / job['id'] / job['filename']).read_text())
            self.assertEqual(payload['sections']['areas_of_interest'][0]['evidence'], 'keep')

    def test_active_scan_and_invalid_download_rejected(self):
        db = Mock(); row = ScanRun(run_uuid='test', status='running', project_key='p')
        db.query.return_value.filter.return_value.first.return_value = row
        with self.assertRaises(HTTPException) as error:
            main.create_report('test', exports.ReportRequest(), db)
        self.assertEqual(error.exception.status_code, 409)
        row.status = 'success'
        with self.assertRaises(HTTPException) as error:
            main.download_report('test', '../secret', db)
        self.assertEqual(error.exception.status_code, 404)

    def test_analysis_html_uses_release_template_and_safe_evidence(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / 'analysis.html'
            exports.render({'report': 'Advanced analysis', 'sections': {'analysis': {'results': [{'target':'php','findings':[{'title':'Escaping proof','description':'</script><script>alert(1)</script>'}]}]}}}, path, 'html')
            html = path.read_text()
            self.assertIn('id="taint-flows"', html)
            self.assertIn('Escaping proof', html)
            self.assertIn('&lt;script&gt;alert(1)', html)
            self.assertIn('class="sidebar"', html)
            self.assertNotIn('</script><script>alert(1)', html)

    def test_orphan_job_is_reported_as_interrupted(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); folder = root / 'exports/old'; folder.mkdir(parents=True)
            (folder / 'job.json').write_text(json.dumps({'id':'old','status':'running','created_at':'now'}))
            self.assertEqual(exports.jobs(root)[0]['status'], 'failed')

    def test_progress_stages_are_persisted_and_finish_only_after_download_exists(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); folder = root / 'exports/test'; folder.mkdir(parents=True)
            item = dict(id='test', status='queued', scope='full', format='json', filename='report.json', created_at='now')
            exports._write(folder / 'job.json', item)
            phases = []
            original = exports._write
            def record(path, value):
                phases.append(value.get('progress', {}).get('phase'))
                if value['status'] == 'complete':
                    self.assertTrue((folder / 'report.json').is_file())
                original(path, value)
            with patch.object(exports, 'collect', return_value={'sections': {}}), patch.object(exports, '_write', side_effect=record):
                exports._generate(folder, root, root, item, {})
            self.assertEqual(phases, ['collecting', 'building', 'packaging', 'finalizing', 'complete'])
            self.assertIn('finished_at', item)
            self.assertEqual(item['progress']['message'], 'Ready to download')

    def test_report_scratch_is_scan_owned_and_released_on_failure(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); folder = root / 'exports/test'; folder.mkdir(parents=True)
            item = dict(id='test', status='queued', scope='full', format='json', filename='report.json', created_at='now')
            exports._write(folder / 'job.json', item)
            def fail(document, destination, fmt, progress=None):
                self.assertEqual(destination.parent.parent, folder)
                self.assertTrue(destination.parent.name.startswith('scratch-'))
                destination.write_text('partial')
                raise ValueError('Fixture rendering failed')
            with patch.object(exports, 'collect', return_value={'sections': {}}), patch.object(exports, 'render', side_effect=fail), patch('logging.Logger.exception'):
                exports._generate(folder, root, root, item, {})
            self.assertEqual(item['status'], 'failed')
            self.assertEqual(list(folder.glob('scratch-*')), [])
            self.assertEqual(item['progress']['phase'], 'failed')
