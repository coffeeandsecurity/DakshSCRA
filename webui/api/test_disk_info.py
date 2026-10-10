import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from fastapi import HTTPException
from . import disk_info, main, report_exports
from .models import ScanRun

class DiskInfoTests(TestCase):
    def fixture(self, root):
        scan = ScanRun(run_uuid='scan1', project_key='project1', project_name='Example', status='success', log_path=str(root / 'runtime/web_runs_v2/scan1.log'), artifacts_json='[]', command='')
        work = root / 'runtime/web_runs_v2/scan1'
        for relative, content in [('results/data/summary.json', 'saved'), ('runtime/diagnostics/trace.txt', 'scratch'), ('runtime/scan_state.json', 'state'), ('exports/report1/report.pdf', 'download'), ('exports/report1/job.json', json.dumps({'id':'report1','status':'complete','format':'pdf'}))]:
            path = work / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content)
        Path(scan.log_path).write_text('log')
        return scan, work

    def test_inventory_counts_once_groups_categories_and_lists_files(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            result = disk_info.inventory([scan], [SimpleNamespace(project_key='project1',project_name='Example')], root, work.parent, root / 'reports', set())
            group = result['projects'][0]; items = group['scans'][0]['units']
            self.assertEqual({i['kind'] for i in items}, {'reports','runtime','data','logs','temporary'})
            self.assertEqual(group['bytes'], sum(p.stat().st_size for p in disk_info.files(work)) + 3)
            self.assertEqual(result['unassigned'], [])
            self.assertFalse(next(i for i in items if i['kind']=='data')['removable'])
            self.assertNotIn('_path', json.dumps(result))

    def test_report_cleanup_preserves_results_source_and_accounts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            (root / 'source.php').write_text('source'); (root / 'runtime/account.db').write_text('accounts')
            item = next(i for i in disk_info.units(scan, root, work.parent, root / 'reports') if i['kind']=='reports')
            self.assertGreater(disk_info.remove_unit(item, root), 0)
            self.assertFalse((work / 'exports/report1').exists())
            self.assertEqual((work / 'results/data/summary.json').read_text(), 'saved')
            self.assertEqual((root / 'source.php').read_text(), 'source')
            self.assertEqual((root / 'runtime/account.db').read_text(), 'accounts')

    def test_symlink_and_traversal_are_excluded_and_not_deleted(self):
        with TemporaryDirectory() as tmp, TemporaryDirectory() as outside:
            root = Path(tmp); scan, work = self.fixture(root)
            external = Path(outside) / 'secret'; external.write_text('keep')
            (work / 'exports/linked').symlink_to(Path(outside), target_is_directory=True)
            items = disk_info.units(scan, root, work.parent, root / 'reports')
            self.assertFalse(any(i['_path'].name == 'linked' for i in items))
            self.assertFalse(disk_info.owned(root / 'runtime/../source.php', root))
            fake = dict(removable=True, _path=work / 'exports/linked')
            with self.assertRaises(ValueError): disk_info.remove_unit(fake, root)
            self.assertEqual(external.read_text(), 'keep')

    def test_active_report_or_scan_blocks_cleanup_and_existing_delete(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            db = Mock(); db.query.return_value.filter.return_value.first.return_value = scan
            with patch.object(main, 'ROOT_DIR', root), patch.object(main, 'WEB_RUNS_DIR', work.parent), patch.object(main, 'run_dir', return_value=work), patch.object(report_exports, '_ACTIVE', {'report1'}):
                for cleanup in (lambda: main.system_disk_delete_scan('scan1', db), lambda: main.delete_scan_data('scan1', db)):
                    with self.assertRaises(HTTPException) as error: cleanup()
                    self.assertEqual(error.exception.status_code, 409)
                self.assertTrue((work / 'exports/report1/report.pdf').is_file())
            scan.status = 'stopping'
            with self.assertRaises(HTTPException) as error: main._ensure_storage_idle(scan)
            self.assertEqual(error.exception.status_code, 409)

    def test_paginated_file_listing_and_immutable_saved_data_unit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            db = Mock(); db.query.return_value.filter.return_value.first.return_value = scan
            unit = next(i for i in disk_info.units(scan, root, work.parent, root / 'reports') if i['kind']=='data')
            with patch.object(main, 'ROOT_DIR', root), patch.object(main, 'WEB_RUNS_DIR', work.parent):
                result = main.system_disk_files('scan1', unit['id'], 0, 1, db)
                self.assertEqual(result['total'], 1)
                self.assertEqual(result['files'][0]['bytes'], 5)
                with self.assertRaises(HTTPException) as error: main.system_disk_delete_unit('scan1', unit['id'], db)
                self.assertEqual(error.exception.status_code, 409)
                with self.assertRaises(HTTPException) as error: main.system_disk_delete_unit('scan1', '../data', db)
                self.assertEqual(error.exception.status_code, 404)

    def test_full_cleanup_retains_history_and_rejects_foreign_artifact_before_deleting(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            db = Mock(); db.query.return_value.filter.return_value.first.return_value = scan
            source = root / 'source.php'; source.write_text('source')
            scan.artifacts_json = json.dumps([str(source)])
            with patch.object(main, 'ROOT_DIR', root), patch.object(main, 'WEB_RUNS_DIR', work.parent), patch.object(main, 'run_dir', return_value=work):
                with self.assertRaises(HTTPException): main.system_disk_delete_scan('scan1', db)
                self.assertTrue((work / 'results/data/summary.json').exists())
                scan.artifacts_json = '[]'
                result = main.system_disk_delete_scan('scan1', db)
                self.assertGreater(result['removed_bytes'], 0)
                self.assertFalse(work.exists()); self.assertFalse(Path(root / 'runtime/web_runs_v2/scan1.log').exists())
                self.assertIsNotNone(scan.data_removed_at)
                db.delete.assert_not_called(); db.commit.assert_called_once()
                self.assertEqual(source.read_text(), 'source')

    def test_unassigned_storage_is_visible_and_active_units_disabled(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            orphan = work.parent / 'orphan'; orphan.mkdir(); (orphan / 'old.zip').write_text('old')
            result = disk_info.inventory([scan], [], root, work.parent, root / 'reports', {'scan1'})
            self.assertTrue(result['projects'][0]['scans'][0]['active'])
            self.assertFalse(any(i['removable'] for i in result['projects'][0]['scans'][0]['units']))
            self.assertEqual(result['unassigned'][0]['bytes'], 3)

    def test_protected_http_routes_and_pagination_validation(self):
        import asyncio
        from urllib.parse import urlsplit
        async def request(method, url):
            parsed = urlsplit(url); messages = []
            scope = dict(type='http', asgi={'version':'3.0'}, http_version='1.1', method=method,
                         scheme='http', path=parsed.path, raw_path=parsed.path.encode(), root_path='',
                         query_string=parsed.query.encode(), headers=[], server=('test',80), client=('test',123))
            async def receive(): return dict(type='http.request', body=b'', more_body=False)
            async def send(message): messages.append(message)
            await main.app(scope, receive, send)
            status = next(m['status'] for m in messages if m['type']=='http.response.start')
            body = b''.join(m.get('body',b'') for m in messages if m['type']=='http.response.body')
            return status, json.loads(body) if body else None
        def call(method, url): return asyncio.run(request(method, url))
        self.assertEqual(call('GET', '/api/v1/system/disk')[0], 401)
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            db = Mock(); db.query.return_value.filter.return_value.first.return_value = scan
            original = dict(main.app.dependency_overrides)
            main.app.dependency_overrides[main.require_password_ok] = lambda: SimpleNamespace(username='review')
            main.app.dependency_overrides[main.db_session] = lambda: db
            try:
                with patch.object(main, 'ROOT_DIR', root), patch.object(main, 'WEB_RUNS_DIR', work.parent):
                    unit = next(i for i in disk_info.units(scan, root, work.parent, root / 'reports') if i['kind']=='reports')
                    url = f'/api/v1/system/disk/scans/scan1/units/{unit["id"]}'
                    self.assertEqual(call('GET', url + '/files?limit=501')[0], 422)
                    self.assertEqual(call('GET', url + '/files?offset=-1')[0], 422)
                    self.assertEqual(call('GET', url + '/files?limit=1')[1]['total'], 2)
                    self.assertGreater(call('DELETE', url)[1]['removed_bytes'], 0)
            finally:
                main.app.dependency_overrides.clear(); main.app.dependency_overrides.update(original)

    def test_interrupted_report_scratch_is_measured_and_removed_with_report(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp); scan, work = self.fixture(root)
            scratch = work / 'exports/report1/scratch-interrupted'
            scratch.mkdir(); (scratch / 'partial.pdf').write_text('temporary')
            item = next(i for i in disk_info.units(scan, root, work.parent, root / 'reports') if i['kind']=='reports')
            self.assertEqual(item['metadata']['temporary_bytes'], 9)
            disk_info.remove_unit(item, root)
            self.assertFalse(scratch.exists())
            self.assertTrue((work / 'results/data/summary.json').exists())
