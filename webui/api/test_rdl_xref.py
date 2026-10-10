"""Reference endpoints preserve scan isolation, source roots and deleted data."""
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch
from fastapi import HTTPException
from . import main
from .models import ScanRun
from core.rdl.xref import build_index, write_index, INDEX_NAME


class XrefApiTests(TestCase):
    def db(self, **values):
        db=Mock();row=ScanRun(run_uuid='test',rdl_engine='both',status='success',**values)
        db.query.return_value.filter.return_value.first.return_value=row
        return db

    def get(self, db, **options):
        query=dict(search='',kind='all',offset=0,symbol_id='',direction='callees',reference_offset=0)
        query.update(options)
        return main.get_rdl_xref('test',db=db,**query)

    def test_saved_index_is_read_without_accessing_target_source(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'a.py').write_text('def f():\n pass\nf()\n')
            index=build_index(root);write_index(root/'runtime'/INDEX_NAME,index);(root/'a.py').unlink()
            with patch.object(main,'run_dir',return_value=root),patch.object(main,'_resolve_target_path') as resolve:
                response=self.get(self.db(target_dir='/unavailable'))
            self.assertTrue(response['available']);self.assertEqual(1,response['summary']['resolved']);resolve.assert_not_called()

    def test_old_scan_has_explicit_missing_index(self):
        with TemporaryDirectory() as tmp,patch.object(main,'run_dir',return_value=Path(tmp)):
            self.assertFalse(self.get(self.db())['available'])

    def test_deleted_scan_is_not_read_or_rebuilt(self):
        db=self.db(data_removed_at=datetime.now())
        with patch.object(main,'run_dir') as paths:
            for action in (lambda:self.get(db),lambda:main.build_rdl_xref('test',db=db)):
                with self.assertRaises(HTTPException) as error:action()
                self.assertEqual(410,error.exception.status_code)
            paths.assert_not_called()

    def test_build_validates_roots_and_labels_current_source(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'a.py').write_text('print(42)')
            db=self.db(target_dir=str(root))
            with patch.object(main,'run_dir',return_value=root/'saved'),patch.object(main,'get_browse_roots',return_value=[str(root)]):
                result=main.build_rdl_xref('test',db=db)
            self.assertEqual('current-source',result['provenance'])
            self.assertTrue((root/'saved/runtime'/INDEX_NAME).exists())
            with patch.object(main,'get_browse_roots',return_value=[str(root/'other')]):
                with self.assertRaises(HTTPException) as error:main.build_rdl_xref('test',db=db)
            self.assertEqual(403,error.exception.status_code)

    def test_concurrent_build_is_rejected_and_lock_released_on_failure(self):
        db=self.db(target_dir='/tmp')
        with patch.object(main,'_resolve_target_path',return_value=Path('/tmp')),patch.object(main,'get_browse_roots',return_value=['/tmp']):
            main._xref_build_lock.acquire()
            try:
                with self.assertRaises(HTTPException) as error:main.build_rdl_xref('test',db=db)
                self.assertEqual(409,error.exception.status_code)
            finally:main._xref_build_lock.release()
            with patch('core.rdl.xref.build_index',side_effect=ValueError('test')):
                with self.assertRaises(HTTPException):main.build_rdl_xref('test',db=db)
            self.assertFalse(main._xref_build_lock.locked())

    def test_http_contract_validation_and_authentication(self):
        from fastapi.testclient import TestClient
        client=TestClient(main.app)
        db=self.db()
        with TemporaryDirectory() as tmp,patch.object(main,'run_dir',return_value=Path(tmp)),patch.dict(main.app.dependency_overrides,{main.db_session:lambda:db}):
            self.assertEqual(401,client.get('/api/v1/scans/test/rdl-xref').status_code)
            self.assertEqual(401,client.post('/api/v1/scans/test/rdl-xref').status_code)
            with patch.dict(main.app.dependency_overrides,{main.require_password_ok:lambda:object()}):
                result=client.get('/api/v1/scans/test/rdl-xref')
                self.assertEqual(200,result.status_code)
                self.assertFalse(result.json()['available'])
                self.assertEqual(422,client.get('/api/v1/scans/test/rdl-xref?offset=-1').status_code)
                self.assertEqual(422,client.get('/api/v1/scans/test/rdl-xref?direction=invalid').status_code)

    def test_active_v1_and_unknown_scans_cannot_be_built(self):
        for mode,status in [('v1','success'),('both','running'),('both','queued')]:
            db=self.db();row=db.query.return_value.filter.return_value.first.return_value
            row.rdl_engine=mode;row.status=status
            with self.assertRaises(HTTPException) as error:main.build_rdl_xref('test',db=db)
            self.assertEqual(409,error.exception.status_code)
        db=Mock();db.query.return_value.filter.return_value.first.return_value=None
        with self.assertRaises(HTTPException) as error:self.get(db)
        self.assertEqual(404,error.exception.status_code)
