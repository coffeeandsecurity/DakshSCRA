"""Project history remains complete and isolated across pages and filters."""
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from fastapi import HTTPException
from . import main
from .models import Project
from .test_scan_queue import _scan, _session_factory

class ProjectHistoryTests(TestCase):
    def test_history_past_two_hundred_is_paginated_without_cross_project_rows(self):
        with TemporaryDirectory() as tmp:
            engine, sessions = _session_factory(Path(tmp))
            with sessions() as db:
                now = datetime(2026, 10, 10)
                db.add_all([_scan(f'alpha-{i:03}', 'alpha', 'success', now) for i in range(205)])
                db.add(_scan('other', 'beta', 'running', now + timedelta(days=1)))
                db.commit()
                first = main.list_scans(limit=200, project_key='alpha', db=db)
                last = main.list_scans(limit=200, project_key='alpha', offset=200, db=db)
                self.assertEqual((len(first), len(last)), (200, 5))
                self.assertEqual(len({r.run_uuid for r in first + last}), 205)
                self.assertTrue(all(r.project_key == 'alpha' for r in first + last))
                self.assertEqual(first[0].run_uuid, 'alpha-204')
            engine.dispose()

    def test_search_status_and_removed_history_are_combined_and_literal(self):
        with TemporaryDirectory() as tmp:
            engine, sessions = _session_factory(Path(tmp))
            with sessions() as db:
                now = datetime(2026, 10, 10)
                a = _scan('100%_done', 'alpha', 'success', now); a.data_removed_at = now
                db.add_all([a, _scan('100xxdone', 'alpha', 'failed', now), _scan('100%_foreign', 'beta', 'success', now)])
                db.commit()
                found = main.list_scans(limit=20, project_key='alpha', search='%_', status='success', db=db)
                self.assertEqual([r.run_uuid for r in found], ['100%_done'])
                self.assertTrue(found[0].data_removed)
                found = main.list_scans(limit=20, project_key='alpha', status='data-removed', db=db)
                self.assertEqual([r.run_uuid for r in found], ['100%_done'])
                with self.assertRaises(HTTPException):main.list_scans(limit=20, offset=-1, db=db)
                with self.assertRaises(HTTPException):main.list_scans(limit=20, status='unknown', db=db)
            engine.dispose()

    def test_project_metrics_include_all_statuses_and_retained_records(self):
        with TemporaryDirectory() as tmp:
            engine, sessions = _session_factory(Path(tmp))
            with sessions() as db:
                now = datetime(2026, 10, 10)
                db.add(Project(project_key='alpha', project_name='Alpha', target_dir='/targets/alpha', rules='auto'))
                for status in ['success', 'running', 'queued', 'stopping', 'failed', 'stopped']:
                    db.add(_scan(status, 'alpha', status, now))
                removed = _scan('removed', 'alpha', 'success', now);removed.data_removed_at = now;db.add(removed)
                db.commit()
                p = main.list_projects(db=db)[0]
                self.assertEqual(p.total_scans, 7)
                self.assertEqual(p.success_scans, 2)
                self.assertEqual((p.running_scans, p.queued_scans, p.stopping_scans, p.failed_scans, p.stopped_scans, p.data_removed_scans), (1, 1, 1, 1, 1, 1))
            engine.dispose()
