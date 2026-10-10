"""Per-scan custom rule persistence and command reconstruction without live data."""
import json
import tempfile
import unittest
import re
from pathlib import Path
from unittest.mock import patch
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from fastapi import HTTPException

from . import main
from .database import Base
from .models import ScanRun
from .schemas import ScanCreate
from .scan_runtime import build_cmd

ROOT=Path(__file__).resolve().parents[2]


class CustomRdlApiTests(unittest.TestCase):
    def test_selection_persists_reconstructs_and_does_not_affect_other_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine=create_engine('sqlite:///'+tmp+'/test.db')
            Base.metadata.create_all(engine)
            sessions=sessionmaker(bind=engine)
            pack=str(ROOT/'examples/custom-rdl/schoolhub/pack.json')
            with sessions() as db, patch.object(main,'_wake_scan_dispatcher'), patch.object(main,'get_browse_roots',return_value=[str(ROOT),tmp]):
                selected=main.create_scan(ScanCreate(target_dir=tmp,rules='android',custom_rdl=[pack]),db)
                row=db.query(ScanRun).filter_by(run_uuid=selected.run_uuid).one()
                cmd=main._scan_cmd_from_row(row)
                self.assertEqual(pack,cmd[cmd.index('--custom-rdl')+1])
                self.assertEqual([pack],main._serialize_scan(row).custom_rdl)
                plain=main.create_scan(ScanCreate(target_dir=tmp,rules='android'),db)
                self.assertEqual([],plain.custom_rdl)
                row=db.query(ScanRun).filter_by(run_uuid=plain.run_uuid).one()
                self.assertNotIn('--custom-rdl',main._scan_cmd_from_row(row))
                for payload in [ScanCreate(target_dir=tmp,rdl_engine='v1',custom_rdl=[pack]),
                                ScanCreate(target_dir=tmp,custom_rdl=[str(Path(tmp)/'missing.json')])]:
                    with self.assertRaises(HTTPException) as error:
                        main.create_scan(payload,db)
                    self.assertEqual(422,error.exception.status_code)
            engine.dispose()

    def test_migration_is_idempotent_and_preserves_existing_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine=create_engine('sqlite:///'+tmp+'/old.db')
            with engine.begin() as db:
                db.execute(text('CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, project_key TEXT, project_name TEXT, data_removed_at DATETIME, rdl_engine TEXT)'))
                db.execute(text("INSERT INTO scan_runs(id,project_key,project_name,rdl_engine) VALUES(1,'old','Old','both')"))
            with patch.object(main,'engine',engine):
                main._ensure_schema_compatibility(); main._ensure_schema_compatibility()
            with engine.connect() as db:
                row=db.execute(text('SELECT custom_rdl_json,rdl_engine FROM scan_runs')).one()
                self.assertEqual(('[]','both'),tuple(row))
            engine.dispose()

    def test_paths_are_command_arguments_and_v1_rejects_packs(self):
        path='/allowed/path with spaces/pack.json'
        cmd=build_cmd(dict(rules='auto',target_dir='/app',custom_rdl=[path]))
        self.assertEqual(path,cmd[cmd.index('--custom-rdl')+1])
        with self.assertRaises(ValueError):
            build_cmd(dict(rules='auto',target_dir='/app',rdl_engine='v1',custom_rdl=[path]))

    def test_custom_analysis_filter_is_accepted_by_http_contract(self):
        schema=main.app.openapi()
        route=schema['paths']['/api/v1/scans/{run_uuid}/rdl-shadow']['get']
        kind=next(p for p in route['parameters'] if p['name']=='kind')
        self.assertTrue(re.fullmatch(kind['schema']['pattern'],'custom'))
        self.assertFalse(re.fullmatch(kind['schema']['pattern'],'invalid'))
