import json
import time
from datetime import datetime, timezone
from typing import Optional

from celery import Celery
from sqlalchemy.orm import Session

from api.config import REDIS_URL
from api.database import SessionLocal
from api.models import ScanRun
from api.scan_runtime import WEB_RUNS_DIR, build_cmd, execute_scan_sync, safe_rel_path, scan_artifacts

celery_app = Celery("daksh_worker", broker=REDIS_URL, backend=REDIS_URL)


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _load_scan(db: Session, run_uuid: str) -> Optional[ScanRun]:
    return db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()


@celery_app.task(name="worker.tasks.run_scan")
def run_scan(run_uuid: str, payload: dict):
    db = SessionLocal()
    start_ts = time.time()
    cmd = build_cmd(payload)
    log_path = WEB_RUNS_DIR / f"{run_uuid}.log"

    try:
        scan = _load_scan(db, run_uuid)
        if not scan:
            return {"error": "run_not_found", "run_uuid": run_uuid}

        scan.status = "running"
        scan.started_at = _utc_now_naive()
        scan.command = " ".join(cmd)
        db.commit()

        rc = execute_scan_sync(cmd, log_path)

        artifacts = scan_artifacts(start_ts)
        scan = _load_scan(db, run_uuid)
        if scan:
            scan.status = "success" if rc == 0 else "failed"
            scan.return_code = rc
            scan.duration_sec = round(time.time() - start_ts, 2)
            scan.ended_at = _utc_now_naive()
            scan.log_path = safe_rel_path(str(log_path))
            scan.artifacts_json = json.dumps(artifacts)
            db.commit()

        return {
            "run_uuid": run_uuid,
            "return_code": rc,
            "artifacts": artifacts,
        }
    except Exception as exc:
        scan = _load_scan(db, run_uuid)
        if scan:
            scan.status = "failed"
            scan.return_code = 1
            scan.duration_sec = round(time.time() - start_ts, 2)
            scan.ended_at = _utc_now_naive()
            scan.log_path = safe_rel_path(str(log_path))
            db.commit()

        WEB_RUNS_DIR.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write("\n[worker-error] ")
            f.write(str(exc))
            f.write("\n")

        return {"run_uuid": run_uuid, "error": str(exc)}
    finally:
        db.close()
