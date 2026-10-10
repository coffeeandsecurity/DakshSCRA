from datetime import datetime, timedelta
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from . import main
from .database import Base
from .models import Project, ScanRun


def _scan(run_uuid: str, project_key: str, status: str, created_at: datetime) -> ScanRun:
    return ScanRun(
        run_uuid=run_uuid,
        project_key=project_key,
        project_name=project_key.title(),
        status=status,
        rules="auto",
        target_dir=f"/targets/{project_key}",
        file_types="auto",
        report_format="html",
        verbosity=1,
        recon="false",
        estimate="false",
        analysis="true",
        loc="false",
        command="python dakshscra.py -r auto -t /targets/example",
        log_path=f"runtime/web_runs_v2/{run_uuid}.log",
        artifacts_json="[]",
        created_at=created_at,
    )


def _session_factory(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'queue.db'}")
    Base.metadata.create_all(bind=engine)
    return engine, sessionmaker(bind=engine, autocommit=False, autoflush=False)


class ScanQueueTests(TestCase):
    def test_queued_elapsed_is_zero_and_running_uses_its_own_start_time(self):
        with TemporaryDirectory() as tmp:
            started = datetime.now() - timedelta(seconds=12)
            with patch.object(main, "run_dir", lambda run_uuid: Path(tmp) / run_uuid):
                queued = main._scan_progress_payload("waiting", fallback_status="queued", started_at=started)
                running = main._scan_progress_payload("active", fallback_status="running", started_at=started)

            self.assertEqual(queued["elapsed_seconds"], 0)
            self.assertGreaterEqual(running["elapsed_seconds"], 11)
            self.assertLess(running["elapsed_seconds"], 20)

    def test_running_elapsed_advances_when_scanner_snapshot_is_stale(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root/'active'/'runtime'
            runtime.mkdir(parents=True)
            (runtime/'scan_summary.json').write_text(json.dumps({'live_progress': {'elapsed_seconds': 3}}))
            started = datetime.now() - timedelta(seconds=60)
            with patch.object(main, 'run_dir', lambda run_uuid: root/run_uuid):
                running = main._scan_progress_payload('active', fallback_status='running', started_at=started)
                queued = main._scan_progress_payload('active', fallback_status='queued', started_at=started)
                completed = main._scan_progress_payload('active', fallback_status='success', started_at=started)
            self.assertGreaterEqual(running['elapsed_seconds'], 59)
            self.assertEqual(0, queued['elapsed_seconds'])
            self.assertEqual(3, completed['elapsed_seconds'])

    def test_semantic_operation_timing_is_exposed_without_resetting_it(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / 'active' / 'runtime'
            runtime.mkdir(parents=True)
            live = dict(stage='pattern_matching', current_phase='semantic_review',
                        message='Reviewing semantic rule 7 of 34',
                        updated_at=1234.5, operation_started_at=1200.25)
            (runtime / 'scan_summary.json').write_text(json.dumps({'live_progress': live}))
            with patch.object(main, 'run_dir', lambda run_uuid: root / run_uuid):
                payload = main._scan_progress_payload('active', fallback_status='running')
            self.assertEqual(payload['updated_at'], 1234.5)
            self.assertEqual(payload['operation_started_at'], 1200.25)
            self.assertEqual(payload['current_phase'], 'semantic_review')
            self.assertEqual(payload['message'], live['message'])

    def test_result_payload_preserves_analysis_and_defers_suppressed_records(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, sessions = _session_factory(root)
            data_dir = root / "reports" / "alpha" / "finished" / "data"
            runtime_dir = root / "runtime" / "finished"
            data_dir.mkdir(parents=True)
            runtime_dir.mkdir(parents=True)
            (data_dir / "areas_of_interest.json").write_text(json.dumps([{"rule_id": "A1"}]), encoding="utf-8")
            (data_dir / "analysis.json").write_text(json.dumps({"results": [{"engine": "flow"}]}), encoding="utf-8")
            (data_dir / "suppressed_findings.json").write_text(json.dumps([{"id": "S1", "rdl_condition": "safe"}]), encoding="utf-8")

            db = sessions()
            db.add(_scan("finished", "alpha", "success", datetime(2026, 8, 24, 6, 30, 0)))
            db.commit()

            with (
                patch.object(main, "_scan_data_dir", lambda project_key, run_uuid: data_dir),
                patch.object(main, "run_dir", lambda run_uuid: runtime_dir),
            ):
                findings = main.get_scan_findings("finished", db=db)
                analysis = main.get_scan_analysis("finished", db=db)
                suppressed = main.get_suppressed_findings("finished", summary_only=True, db=db)

            self.assertEqual(findings["analysis"], analysis["analysis"])
            self.assertEqual(analysis["analysis"]["results"][0]["engine"], "flow")
            self.assertEqual(suppressed["summary"]["total_suppressed"], 1)
            self.assertNotIn("suppressed", suppressed)
            db.close()
            engine.dispose()

    def test_dispatcher_claims_fifo_and_never_claims_while_running(self):
        with TemporaryDirectory() as tmp:
            engine, sessions = _session_factory(Path(tmp))
            now = datetime(2026, 8, 24, 6, 30, 0)
            db = sessions()
            db.add_all([
                _scan("first", "alpha", "queued", now),
                _scan("second", "beta", "queued", now + timedelta(seconds=1)),
                _scan("third", "gamma", "queued", now + timedelta(seconds=2)),
            ])
            db.commit()
            db.close()

            with patch.object(main, "SessionLocal", sessions):
                self.assertEqual(main._claim_next_queued_scan(), "first")
                self.assertIsNone(main._claim_next_queued_scan())

                db = sessions()
                first = db.query(ScanRun).filter(ScanRun.run_uuid == "first").one()
                first.status = "success"
                db.commit()
                db.close()

                self.assertEqual(main._claim_next_queued_scan(), "second")

            db = sessions()
            statuses = {row.run_uuid: row.status for row in db.query(ScanRun).all()}
            db.close()
            engine.dispose()
            self.assertEqual(statuses, {"first": "success", "second": "running", "third": "queued"})

    def test_project_summary_separates_running_and_queued_counts(self):
        with TemporaryDirectory() as tmp:
            engine, sessions = _session_factory(Path(tmp))
            now = datetime(2026, 8, 24, 6, 30, 0)
            db = sessions()
            db.add(Project(
                project_key="alpha",
                project_name="Alpha",
                target_dir="/targets/alpha",
                rules="auto",
            ))
            db.add_all([
                _scan("active", "alpha", "running", now),
                _scan("waiting", "alpha", "queued", now + timedelta(seconds=1)),
            ])
            db.commit()

            summaries = main.list_projects(db=db)
            db.close()
            engine.dispose()

            self.assertEqual(len(summaries), 1)
            self.assertEqual(summaries[0].running_scans, 1)
            self.assertEqual(summaries[0].queued_scans, 1)

    def test_scan_data_deletion_keeps_tombstone_until_record_is_cleared(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, sessions = _session_factory(root)
            report_dir = root / "reports" / "alpha" / "finished"
            runtime_dir = root / "runtime" / "web_runs_v2" / "finished"
            log_path = root / "runtime" / "web_runs_v2" / "finished.log"
            report_dir.mkdir(parents=True)
            runtime_dir.mkdir(parents=True)
            artifact = report_dir / "report.html"
            artifact.write_text("report", encoding="utf-8")
            (runtime_dir / "scan_summary.json").write_text("{}", encoding="utf-8")
            log_path.write_text("log", encoding="utf-8")

            db = sessions()
            scan = _scan("finished", "alpha", "success", datetime(2026, 8, 24, 6, 30, 0))
            scan.log_path = str(log_path)
            scan.artifacts_json = f'["{artifact}"]'
            db.add(scan)
            db.commit()

            with (
                patch.object(main, "ROOT_DIR", root),
                patch.object(main, "WEB_RUNS_DIR", root / "runtime" / "web_runs_v2"),
                patch.object(main, "project_reports_dir", lambda project_key, run_uuid="": root / "reports" / project_key / run_uuid),
                patch.object(main, "run_dir", lambda run_uuid: root / "runtime" / "web_runs_v2" / run_uuid),
            ):
                deleted = main.delete_scan_data("finished", db=db)

            self.assertTrue(deleted.data_removed)
            self.assertFalse(report_dir.exists())
            self.assertFalse(runtime_dir.exists())
            self.assertFalse(log_path.exists())
            tombstone = db.query(ScanRun).filter(ScanRun.run_uuid == "finished").one()
            self.assertIsNotNone(tombstone.data_removed_at)
            self.assertEqual(tombstone.artifacts_json, "[]")
            self.assertEqual(tombstone.command, "")

            main.delete_scan_record("finished", db=db)
            self.assertIsNone(db.query(ScanRun).filter(ScanRun.run_uuid == "finished").first())
            db.close()
            engine.dispose()

    def test_project_delete_retains_recent_scan_tombstones(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, sessions = _session_factory(root)
            db = sessions()
            db.add(Project(project_key="alpha", project_name="Alpha", target_dir="/targets/alpha", rules="auto"))
            db.add(_scan("finished", "alpha", "success", datetime(2026, 8, 24, 6, 30, 0)))
            db.commit()

            with (
                patch.object(main, "ROOT_DIR", root),
                patch.object(main, "WEB_RUNS_DIR", root / "runtime" / "web_runs_v2"),
                patch.object(main, "project_reports_dir", lambda project_key, run_uuid="": root / "reports" / project_key / run_uuid),
                patch.object(main, "run_dir", lambda run_uuid: root / "runtime" / "web_runs_v2" / run_uuid),
            ):
                main.delete_project("alpha", db=db)

            self.assertIsNone(db.query(Project).filter(Project.project_key == "alpha").first())
            tombstone = db.query(ScanRun).filter(ScanRun.run_uuid == "finished").one()
            self.assertIsNotNone(tombstone.data_removed_at)
            self.assertEqual(main.list_projects(db=db), [])
            db.close()
            engine.dispose()
