"""Per-scan API validation, persistence, queue execution and legacy migration."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker

from . import main
from .database import Base
from .models import ScanRun
from .schemas import ScanCreate
from .scan_runtime import build_cmd


class EngineSelectionApiTests(TestCase):
    def test_api_validates_persists_and_dispatches_each_mode(self):
        with TemporaryDirectory() as tmp:
            engine = create_engine(f'sqlite:///{tmp}/test.db', connect_args={'check_same_thread': False})
            Base.metadata.create_all(engine)
            sessions = sessionmaker(bind=engine)
            def db():
                with sessions() as session:
                    yield session
            overrides = dict(main.app.dependency_overrides)
            main.app.dependency_overrides[main.db_session] = db
            main.app.dependency_overrides[main.require_password_ok] = lambda: object()
            try:
                client = TestClient(main.app)
                with patch.object(main, '_wake_scan_dispatcher'), patch.object(main, '_resolve_target_path', return_value=Path(tmp)):
                    for mode in ['v1', 'v2', 'both', None]:
                        payload = {'target_dir': tmp, 'rules': 'python'}
                        if mode:
                            payload['rdl_engine'] = mode
                        response = client.post('/api/v1/scans', json=payload)
                        self.assertEqual(response.status_code, 200, response.text)
                        scan = response.json()
                        selected = mode or 'both'
                        self.assertEqual(scan['rdl_engine'], selected)
                        with sessions() as session:
                            row = session.query(ScanRun).filter_by(run_uuid=scan['run_uuid']).one()
                            self.assertEqual(row.rdl_engine, selected)
                            cmd = main._scan_cmd_from_row(row)
                            self.assertEqual(cmd[cmd.index('--rdl-engine') + 1], selected)
                        detail = client.get('/api/v1/scans/' + scan['run_uuid']).json()
                        self.assertEqual(detail['rdl_engine'], selected)
                    invalid = client.post('/api/v1/scans', json={'target_dir': tmp, 'rdl_engine': 'none'})
                    self.assertEqual(invalid.status_code, 422)
            finally:
                main.app.dependency_overrides.clear()
                main.app.dependency_overrides.update(overrides)
                engine.dispose()

    def test_existing_schema_migrates_without_relabeling_old_runs(self):
        with TemporaryDirectory() as tmp:
            engine = create_engine(f'sqlite:///{tmp}/old.db')
            with engine.begin() as conn:
                conn.execute(text('CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, project_key VARCHAR(96), project_name VARCHAR(255), data_removed_at DATETIME)'))
                conn.execute(text("INSERT INTO scan_runs (id, project_key, project_name) VALUES (1, 'old', 'Old')"))
            with patch.object(main, 'engine', engine):
                main._ensure_schema_compatibility()
                main._ensure_schema_compatibility()
            self.assertIn('rdl_engine', {c['name'] for c in inspect(engine).get_columns('scan_runs')})
            with engine.connect() as conn:
                self.assertEqual(conn.execute(text('SELECT project_key, rdl_engine FROM scan_runs')).one(), ('old', None))
            engine.dispose()

    def test_historical_selection_comes_from_saved_scan_not_new_default(self):
        with TemporaryDirectory() as tmp, patch.object(main, 'run_dir', return_value=Path(tmp)):
            row = ScanRun(run_uuid='historical')
            self.assertEqual(main._scan_rdl_engine(row), 'v1')
            runtime = Path(tmp) / 'runtime'
            runtime.mkdir()
            (runtime / 'scan_summary.json').write_text(json.dumps({'inputs_received': {'rdl_v2_shadow_enabled': True}}))
            self.assertEqual(main._scan_rdl_engine(row), 'both')
            row.rdl_engine = 'v2'
            self.assertEqual(main._scan_rdl_engine(row), 'v2')

    def test_command_defaults_and_rejects_invalid_selection(self):
        self.assertEqual(ScanCreate(target_dir='/tmp').rdl_engine, 'both')
        cmd = build_cmd({'rules': 'auto', 'target_dir': '/tmp'})
        self.assertEqual(cmd[cmd.index('--rdl-engine') + 1], 'both')
        with self.assertRaises(ValueError):
            build_cmd({'rules': 'auto', 'target_dir': '/tmp', 'rdl_engine': 'none'})
