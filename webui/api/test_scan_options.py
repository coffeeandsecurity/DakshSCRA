"""Isolated Web UI scan options contracts, persistence and safe command arguments."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from . import main
from .database import Base
from .models import ScanRun
from .schemas import ScanCreate
from .scan_runtime import build_cmd


class ScanOptionsApiTests(unittest.TestCase):
    def test_checkpoint_file_is_isolated_for_each_web_run(self):
        from . import scan_runtime
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(scan_runtime, 'WEB_RUNS_DIR', root / 'runs'), patch.object(scan_runtime.subprocess, 'Popen') as spawn:
                spawn.return_value.wait.return_value = 0
                for identity in ('one', 'two'):
                    cmd = build_cmd(dict(rules='auto', target_dir='/source', state_mode='enabled'))
                    scan_runtime.execute_scan_sync(cmd, root / (identity + '.log'), identity, 'fixture')
                    effective = spawn.call_args.args[0]
                    self.assertEqual(str(root / 'runs' / identity / 'runtime' / 'scan_state.json'), effective[effective.index('--state-file') + 1])
                    self.assertNotIn('--state-file', cmd)

    def test_settings_persist_reconstruct_and_stay_per_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / 'baseline with spaces.json'; baseline.write_text('{"suppressions": []}')
            review = root / 'review.json'; review.write_text('{"rules": {"source": [], "path": [], "analyzer": []}}')
            engine = create_engine('sqlite:///' + tmp + '/test.db')
            Base.metadata.create_all(engine); sessions = sessionmaker(bind=engine)
            options = dict(exclude_checks=['sql', 'xss'], exclude_paths=['vendor/**', '**/test/**'], exclude_types=['.map'],
                           exclude_keywords=['--literal;$(never execute)', 'generated file'], recon=True, recon_strict=True,
                           baseline_mode='custom', baseline_file=str(baseline), review_config=str(review), state_mode='enabled')
            with sessions() as db, patch.object(main, '_wake_scan_dispatcher'), patch.object(main, 'get_browse_roots', return_value=[tmp]):
                result = main.create_scan(ScanCreate(target_dir=tmp, rules='auto', **options), db)
                row = db.query(ScanRun).filter_by(run_uuid=result.run_uuid).one()
                command = main._scan_cmd_from_row(row)
                self.assertEqual(build_cmd(dict(rules='auto', target_dir=tmp, **options)), command)
                self.assertIn('--exclude-keyword=--literal;$(never execute)', command)
                self.assertIn('--exclude-check=sql', command)
                self.assertIn('--state', command); self.assertIn('--recon-strict', command)
                self.assertEqual(str(baseline), command[command.index('--baseline-file') + 1])
                for key, value in options.items():
                    self.assertEqual(value, getattr(main._serialize_scan(row), key))
                plain = main.create_scan(ScanCreate(target_dir=tmp, rules='auto'), db)
                self.assertEqual([], plain.exclude_checks); self.assertEqual('default', plain.baseline_mode)
                plain_cmd = main._scan_cmd_from_row(db.query(ScanRun).filter_by(run_uuid=plain.run_uuid).one())
                self.assertFalse(any(arg.startswith('--exclude-') for arg in plain_cmd))
                disabled = build_cmd(dict(rules='auto', target_dir=tmp, baseline_mode='disabled', state_mode='disabled'))
                self.assertIn('--no-baseline', disabled); self.assertIn('--no-state', disabled)
            engine.dispose()

    def test_invalid_options_fail_before_queueing(self):
        for options in [dict(exclude_checks=['imaginary']), dict(exclude_keywords=['a\nb']),
                        dict(exclude_paths=['x' * 513]), dict(recon_strict=True), dict(baseline_mode='custom'),
                        dict(state_mode='resume'), dict(exclude_keywords=['\x00'])]:
            with self.subTest(options=options), self.assertRaises(ValidationError):
                ScanCreate(target_dir='/allowed', **options)
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            invalid = root / 'invalid.json'; invalid.write_text('broken json')
            wrong = root / 'wrong.json'; wrong.write_text('{"rules": []}')
            external = Path(outside) / 'review.json'; external.write_text('{"rules": {}}')
            for name in [str(invalid), str(wrong), str(external)]:
                with patch.object(main, 'get_browse_roots', return_value=[tmp]), self.assertRaises(HTTPException) as error:
                    main.create_scan(ScanCreate(target_dir=tmp, review_config=name), None)
                self.assertEqual(422, error.exception.status_code)

    def test_migration_retains_existing_scan_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = create_engine('sqlite:///' + tmp + '/old.db')
            with engine.begin() as db:
                db.execute(text('CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, project_key TEXT, project_name TEXT, data_removed_at DATETIME, rdl_engine TEXT, custom_rdl_json TEXT)'))
                db.execute(text("INSERT INTO scan_runs VALUES(1,'old','Original',NULL,'both','[]')"))
            with patch.object(main, 'engine', engine):
                main._ensure_schema_compatibility(); main._ensure_schema_compatibility()
            with engine.connect() as db:
                self.assertEqual(('Original', 'both', '{}'), tuple(db.execute(text('SELECT project_name,rdl_engine,scan_options_json FROM scan_runs')).one()))
            engine.dispose()

    def test_catalog_is_authenticated_and_lists_actual_registered_checks(self):
        schema = main.app.openapi()
        self.assertIn('/api/v1/check-catalog', schema['paths'])
        route = next(route for route in main.protected.routes if getattr(route, 'path', '') == '/api/v1/check-catalog')
        self.assertTrue(route.dependant.dependencies)
        catalog = main.get_check_catalog()
        self.assertEqual('all', catalog['default'])
        injection = next(group for group in catalog['groups'] if group['id'] == 'injection')
        self.assertTrue(any(check['id'] == 'sql' and check['count'] > 0 for check in injection['checks']))
