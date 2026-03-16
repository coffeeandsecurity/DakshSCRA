import json
import os
import re
import signal
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .config import ROOT_DIR, get_browse_roots
from .database import Base, SessionLocal, engine
from .models import Project, ScanRun
from .scan_runtime import (
    WEB_RUNS_DIR,
    build_cmd,
    cmd_as_shell_string,
    execute_scan_sync,
    get_proc,
    read_log_tail,
    run_dir,
    safe_rel_path,
    scan_artifacts,
)
from .schemas import (
    ArtifactIndex,
    DashboardMetrics,
    FsEntry,
    FsListResponse,
    ProjectSummary,
    ScanCreate,
    ScanDetails,
    ScanSummary,
    SettingsData,
)

app = FastAPI(title="DakshSCRA API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    (ROOT_DIR / "runtime").mkdir(parents=True, exist_ok=True)
    WEB_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    _ensure_schema_compatibility()
    port = os.environ.get("DAKSH_PORT", "8080")
    print(f"\n  DakshSCRA Web UI  →  http://localhost:{port}\n", flush=True)


def _ensure_schema_compatibility() -> None:
    insp = inspect(engine)
    tables = insp.get_table_names()

    if "projects" not in tables:
        Project.__table__.create(bind=engine, checkfirst=True)

    if "scan_runs" not in tables:
        return

    cols = {c["name"] for c in insp.get_columns("scan_runs")}
    statements = []
    if "project_key" not in cols:
        statements.append("ALTER TABLE scan_runs ADD COLUMN project_key VARCHAR(96)")
    if "project_name" not in cols:
        statements.append("ALTER TABLE scan_runs ADD COLUMN project_name VARCHAR(255)")

    if statements:
        with engine.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))

    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE scan_runs SET project_key = COALESCE(project_key, 'legacy') "
                "WHERE project_key IS NULL OR project_key = ''"
            )
        )
        conn.execute(
            text(
                "UPDATE scan_runs SET project_name = COALESCE(project_name, 'Legacy') "
                "WHERE project_name IS NULL OR project_name = ''"
            )
        )


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _to_bool(v: str) -> bool:
    return str(v).lower() == "true"


def _normalize_raw_path(raw_path: str) -> str:
    v = (raw_path or "").strip().strip('"').strip("'")
    if not v:
        return ""
    v = v.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", v)
    if m:
        drive = m.group(1).lower()
        rest = m.group(2)
        return f"/host/{drive}/{rest}"
    return v


def _slugify(name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return clean[:80] if clean else "project"


def _default_project_name(target_dir: str, rules: str) -> str:
    base = Path(target_dir).name or "project"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{base}-{rules.replace(',', '-')}-{stamp}"


def _project_key_from_name(name: str) -> str:
    return f"{_slugify(name)}-{uuid4().hex[:6]}"


def _remap_path_aliases(p: Path) -> Path:
    text_v = str(p)
    alias_pairs = [
        ("/mnt/c", "/host/c"),
        ("/mnt/d", "/host/d"),
        ("/run/desktop/mnt/host/c", "/host/c"),
        ("/run/desktop/mnt/host/d", "/host/d"),
    ]
    for src, dst in alias_pairs:
        if text_v == src or text_v.startswith(src + "/"):
            mapped = Path(text_v.replace(src, dst, 1))
            if mapped.exists():
                return mapped
    return p


def _resolve_target_path(raw_path: str, roots: List[Path]) -> Path:
    p = Path(_normalize_raw_path(raw_path)).expanduser()
    if not p.is_absolute():
        p = (roots[0] / p).resolve()
    else:
        p = p.resolve()
    p = _remap_path_aliases(p)

    for r in roots:
        try:
            p.relative_to(r)
            if not p.exists() or not p.is_dir():
                raise HTTPException(status_code=400, detail="target_not_directory")
            return p
        except ValueError:
            continue
    raise HTTPException(status_code=403, detail="target_outside_allowed_roots")


def _get_or_create_project(db: Session, payload: ScanCreate) -> Project:
    name = (payload.project_name or "").strip()
    if not name:
        name = _default_project_name(payload.target_dir, payload.rules)

    existing = db.query(Project).filter(Project.project_name == name).first()
    if existing:
        existing.target_dir = payload.target_dir
        existing.rules = payload.rules
        existing.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
        db.refresh(existing)
        return existing

    project = Project(
        project_key=_project_key_from_name(name),
        project_name=name,
        target_dir=payload.target_dir,
        rules=payload.rules,
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def _serialize_scan(s: ScanRun) -> ScanDetails:
    artifacts: List[str] = []
    try:
        artifacts = json.loads(s.artifacts_json or "[]")
    except Exception:
        pass
    return ScanDetails(
        run_uuid=s.run_uuid,
        project_key=s.project_key,
        project_name=s.project_name,
        status=s.status,
        rules=s.rules,
        target_dir=s.target_dir,
        created_at=s.created_at.isoformat() if s.created_at else None,
        duration_sec=s.duration_sec,
        file_types=s.file_types,
        report_format=s.report_format,
        verbosity=s.verbosity,
        recon=_to_bool(s.recon),
        estimate=_to_bool(s.estimate),
        analysis=_to_bool(s.analysis),
        loc=_to_bool(s.loc),
        command=s.command,
        return_code=s.return_code,
        task_id=s.task_id,
        artifacts=artifacts,
    )


def _artifact_index(artifacts: List[str]) -> ArtifactIndex:
    report_html = None
    xref_html = None
    other_html: List[str] = []
    json_files: List[str] = []
    logs: List[str] = []
    pdf_files: List[str] = []

    for a in artifacts:
        low = a.lower()
        if low.endswith("analysis_xref.html"):
            xref_html = a
            continue
        if low.endswith("report.html"):
            report_html = a
            continue
        if low.endswith("report_modern.html") and not report_html:
            report_html = a
            continue
        if low.endswith(".html"):
            other_html.append(a)
        elif low.endswith(".json"):
            json_files.append(a)
        elif low.endswith(".log"):
            logs.append(a)
        elif low.endswith(".pdf"):
            pdf_files.append(a)

    return ArtifactIndex(
        report_html=report_html,
        xref_html=xref_html,
        other_html=sorted(other_html),
        json_files=sorted(json_files),
        logs=sorted(logs),
        pdf_files=sorted(pdf_files),
        all_artifacts=sorted(artifacts),
    )


# ── Background scan runner ────────────────────────────────────────────────────

def _run_scan_thread(run_uuid: str, cmd: list, cmd_payload: dict, log_path: Path, start_ts: float) -> None:
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()

        rc = execute_scan_sync(cmd, log_path, run_uuid=run_uuid)

        scan = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
        if scan:
            ended = datetime.now(timezone.utc).replace(tzinfo=None)
            scan.ended_at = ended
            scan.return_code = rc
            scan.duration_sec = round(time.time() - start_ts, 2)

            # If status was already set to "stopped" by the stop endpoint, keep it
            if scan.status == "stopped":
                pass
            elif rc == 0:
                scan.status = "success"
            elif rc in (-2, -15, 2):  # SIGINT / SIGTERM / KeyboardInterrupt
                scan.status = "stopped"
            else:
                scan.status = "failed"

            artifacts = scan_artifacts(run_uuid)
            scan.artifacts_json = json.dumps(artifacts)
            db.commit()
    except Exception:
        db.rollback()
        db2 = SessionLocal()
        try:
            s = db2.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
            if s:
                s.status = "failed"
                db2.commit()
        finally:
            db2.close()
    finally:
        db.close()


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "dakshscra-api"}


@app.get("/api/v1/version")
def get_version():
    try:
        import sys as _sys
        _sys.path.insert(0, str(ROOT_DIR))
        import yaml as _yaml
        with open(ROOT_DIR / "config" / "tool.yaml", "r") as _f:
            _cfg = _yaml.safe_load(_f)
        ver = str(_cfg.get("release", "unknown"))
        release_date = str(_cfg.get("release_date", "")) or None
    except Exception:
        ver = "unknown"
        release_date = None
    return {
        "version": ver,
        "release_date": release_date,
        "github_repo": "coffeeandsecurity/DakshSCRA",
    }


@app.post("/api/v1/scans", response_model=ScanDetails)
def create_scan(payload: ScanCreate, db: Session = Depends(db_session)):
    run_uuid = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid4().hex[:8]
    roots = [Path(p).resolve() for p in get_browse_roots()]
    target_dir = str(_resolve_target_path(payload.target_dir, roots))
    payload.target_dir = target_dir

    project = _get_or_create_project(db, payload)

    cmd_payload = payload.model_dump()
    cmd = build_cmd(cmd_payload)
    log_path = WEB_RUNS_DIR / f"{run_uuid}.log"

    scan = ScanRun(
        run_uuid=run_uuid,
        project_key=project.project_key,
        project_name=project.project_name,
        status="queued",
        rules=payload.rules,
        target_dir=payload.target_dir,
        file_types=payload.file_types,
        report_format=payload.report_format,
        verbosity=payload.verbosity,
        recon=str(payload.recon).lower(),
        estimate=str(payload.estimate).lower(),
        analysis=str(payload.analysis).lower(),
        loc=str(payload.loc).lower(),
        command=cmd_as_shell_string(cmd),
        log_path=safe_rel_path(str(log_path)),
        artifacts_json="[]",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    start_ts = time.time()
    t = threading.Thread(
        target=_run_scan_thread,
        args=(run_uuid, cmd, cmd_payload, log_path, start_ts),
        daemon=True,
    )
    t.start()

    return _serialize_scan(scan)


@app.post("/api/v1/scans/{run_uuid}/stop")
def stop_scan(run_uuid: str, db: Session = Depends(db_session)):
    scan = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="run_not_found")
    if scan.status not in ("running", "queued"):
        raise HTTPException(status_code=409, detail="scan_not_active")

    proc = get_proc(run_uuid)
    if proc and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            proc.terminate()

    scan.status = "stopped"
    db.commit()
    return {"run_uuid": run_uuid, "status": "stopped"}


@app.get("/api/v1/scans/{run_uuid}/stream")
def stream_scan_log(run_uuid: str):
    # Validate run exists before opening the stream
    _db = SessionLocal()
    try:
        scan = _db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
        if not scan:
            raise HTTPException(status_code=404, detail="run_not_found")
        log_rel = scan.log_path
    finally:
        _db.close()

    log_path = Path(os.path.join(ROOT_DIR, log_rel)) if log_rel else None

    def _generate():
        offset = 0
        idle_ticks = 0
        while True:
            inner_db = SessionLocal()
            try:
                s = inner_db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
                current_status = s.status if s else "unknown"
            except Exception:
                current_status = "unknown"
            finally:
                inner_db.close()

            new_chunk = ""
            if log_path and log_path.exists():
                try:
                    text_content = log_path.read_text(encoding="utf-8", errors="replace")
                    new_chunk = text_content[offset:]
                    if new_chunk:
                        offset = len(text_content)
                        idle_ticks = 0
                except Exception:
                    pass

            if new_chunk:
                # Strip ANSI escape codes and lone backspace/carriage-return chars
                new_chunk = re.sub(r"\[[0-9;]*[mABCDEFGHJKSTfhilmnprsu]", "", new_chunk)
                new_chunk = re.sub(r"[\x08\r]+", "", new_chunk)
            if new_chunk or current_status not in ("running", "queued"):
                data = json.dumps({"log": new_chunk, "status": current_status})
                yield f"data: {data}\n\n"
            else:
                # SSE keep-alive comment every ~15 s of silence
                idle_ticks += 1
                if idle_ticks % 19 == 0:
                    yield ": keep-alive\n\n"

            if current_status not in ("running", "queued"):
                yield f"data: {json.dumps({'log': '', 'status': current_status, 'done': True})}\n\n"
                break

            time.sleep(0.8)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/v1/scans", response_model=List[ScanSummary])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    project_key: Optional[str] = Query(default=None),
    db: Session = Depends(db_session),
):
    q = db.query(ScanRun)
    if project_key:
        q = q.filter(ScanRun.project_key == project_key)
    rows = q.order_by(ScanRun.created_at.desc()).limit(limit).all()
    out = []
    for s in rows:
        out.append(
            ScanSummary(
                run_uuid=s.run_uuid,
                project_key=s.project_key,
                project_name=s.project_name,
                status=s.status,
                rules=s.rules,
                target_dir=s.target_dir,
                created_at=s.created_at.isoformat() if s.created_at else None,
                duration_sec=s.duration_sec,
            )
        )
    return out


@app.get("/api/v1/scans/{run_uuid}", response_model=ScanDetails)
def get_scan(run_uuid: str, db: Session = Depends(db_session)):
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")
    return _serialize_scan(row)


@app.get("/api/v1/scans/{run_uuid}/artifacts", response_model=ArtifactIndex)
def get_scan_artifacts(run_uuid: str, db: Session = Depends(db_session)):
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")
    try:
        artifacts = json.loads(row.artifacts_json or "[]")
    except Exception:
        artifacts = []
    # Fall back to a live disk scan if DB cache is empty (e.g. scan predates
    # the artifacts_json column, or an error prevented it from being saved).
    if not artifacts and row.status in ("success", "failed", "stopped"):
        artifacts = scan_artifacts(run_uuid)
        if artifacts:
            try:
                row.artifacts_json = json.dumps(artifacts)
                db.commit()
            except Exception:
                db.rollback()
    return _artifact_index(artifacts)


@app.get("/api/v1/scans/{run_uuid}/log")
def get_scan_log(run_uuid: str, db: Session = Depends(db_session)):
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")
    log_text = read_log_tail(Path(os.path.join(ROOT_DIR, row.log_path)))
    return {"run_uuid": run_uuid, "status": row.status, "log_tail": log_text}


def _load_json_safe(path: Path):
    """Load JSON from path, returning None if missing or invalid."""
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        pass
    return None


@app.get("/api/v1/scans/{run_uuid}/findings")
def get_scan_findings(run_uuid: str, db: Session = Depends(db_session)):
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")

    rdir = run_dir(run_uuid)
    json_dir = rdir / "reports" / "data"
    runtime_dir = rdir / "runtime"

    findings = _load_json_safe(json_dir / "areas_of_interest.json") or []
    summary = _load_json_safe(json_dir / "summary.json")
    filepaths = _load_json_safe(json_dir / "filepaths_aoi.json") or []
    analysis = _load_json_safe(json_dir / "analysis.json")
    recon = _load_json_safe(json_dir / "recon.json")
    scan_meta = _load_json_safe(runtime_dir / "scan_summary.json")
    loc_breakdown = _load_json_safe(runtime_dir / "filepaths.json") or []

    return {
        "run_uuid": run_uuid,
        "status": row.status,
        "findings": findings,
        "summary": summary,
        "filepaths": filepaths,
        "analysis": analysis,
        "recon": recon,
        "scan_meta": scan_meta,
        "loc_breakdown": loc_breakdown,
    }


@app.get("/api/v1/projects", response_model=List[ProjectSummary])
def list_projects(db: Session = Depends(db_session)):
    projects = db.query(Project).order_by(Project.updated_at.desc()).all()
    known_keys = {p.project_key for p in projects}
    scan_only_keys = (
        db.query(ScanRun.project_key)
        .filter(ScanRun.project_key.isnot(None))
        .distinct()
        .all()
    )
    out: List[ProjectSummary] = []
    for p in projects:
        scans = db.query(ScanRun).filter(ScanRun.project_key == p.project_key).all()
        running = sum(1 for s in scans if s.status in ("running", "queued"))
        failed = sum(1 for s in scans if s.status == "failed")
        latest = max([s.created_at for s in scans if s.created_at], default=None)
        out.append(
            ProjectSummary(
                project_key=p.project_key,
                project_name=p.project_name,
                target_dir=p.target_dir,
                rules=p.rules,
                total_scans=len(scans),
                running_scans=running,
                failed_scans=failed,
                latest_scan_at=latest.isoformat() if latest else None,
            )
        )

    for (scan_key,) in scan_only_keys:
        if not scan_key or scan_key in known_keys:
            continue
        scans = db.query(ScanRun).filter(ScanRun.project_key == scan_key).all()
        if not scans:
            continue
        latest_scan = sorted(scans, key=lambda x: x.created_at or datetime.min, reverse=True)[0]
        running = sum(1 for s in scans if s.status in ("running", "queued"))
        failed = sum(1 for s in scans if s.status == "failed")
        latest = max([s.created_at for s in scans if s.created_at], default=None)
        out.append(
            ProjectSummary(
                project_key=scan_key,
                project_name=latest_scan.project_name or "Legacy",
                target_dir=latest_scan.target_dir,
                rules=latest_scan.rules,
                total_scans=len(scans),
                running_scans=running,
                failed_scans=failed,
                latest_scan_at=latest.isoformat() if latest else None,
            )
        )

    out.sort(key=lambda x: x.latest_scan_at or "", reverse=True)
    return out


@app.delete("/api/v1/projects/{project_key}", status_code=204)
def delete_project(project_key: str, db: Session = Depends(db_session)):
    project = db.query(Project).filter(Project.project_key == project_key).first()
    if not project:
        raise HTTPException(status_code=404, detail="project_not_found")
    running = (
        db.query(ScanRun)
        .filter(ScanRun.project_key == project_key, ScanRun.status.in_(["running", "queued"]))
        .first()
    )
    if running:
        raise HTTPException(status_code=409, detail="project_has_active_scans")
    db.query(ScanRun).filter(ScanRun.project_key == project_key).delete()
    db.delete(project)
    db.commit()


@app.get("/api/v1/dashboard/metrics", response_model=DashboardMetrics)
def dashboard_metrics(db: Session = Depends(db_session)):
    scans = db.query(ScanRun).all()
    total = len(scans)
    running = sum(1 for s in scans if s.status == "running")
    queued = sum(1 for s in scans if s.status == "queued")
    failed = sum(1 for s in scans if s.status == "failed")
    success = sum(1 for s in scans if s.status == "success")

    durations = [s.duration_sec for s in scans if s.duration_sec is not None and s.duration_sec > 0]
    avg_duration = round(sum(durations) / len(durations), 2) if durations else 0.0
    success_rate = round((success / total) * 100, 2) if total else 0.0

    now = datetime.now(timezone.utc)
    series: List[Dict] = []
    for i in range(6, -1, -1):
        d = (now - timedelta(days=i)).date()
        count = 0
        for s in scans:
            if s.created_at and s.created_at.date() == d:
                count += 1
        series.append({"date": d.isoformat(), "count": count})

    project_count = len({s.project_key for s in scans if s.project_key}) or db.query(Project).count()

    return DashboardMetrics(
        total_projects=project_count,
        total_scans=total,
        running_scans=running,
        queued_scans=queued,
        failed_scans=failed,
        success_scans=success,
        success_rate=success_rate,
        avg_duration_sec=avg_duration,
        recent_daily=series,
    )


@app.get("/api/v1/fs/list", response_model=FsListResponse)
def fs_list(path: str = Query(default="")):
    roots = [Path(p).resolve() for p in get_browse_roots()]

    def under_roots(p: Path) -> bool:
        rp = p.resolve()
        for r in roots:
            try:
                rp.relative_to(r)
                return True
            except Exception:
                continue
        return False

    if path.strip():
        p = Path(_normalize_raw_path(path)).expanduser()
        if not p.is_absolute():
            p = (roots[0] / p).resolve()
        else:
            p = p.resolve()
        p = _remap_path_aliases(p)
    else:
        p = roots[0]

    if not under_roots(p):
        raise HTTPException(status_code=403, detail="forbidden_path")
    if not p.exists() or not p.is_dir():
        raise HTTPException(status_code=404, detail="not_a_directory")

    dirs = []
    try:
        iterable = list(p.iterdir())
    except (PermissionError, OSError):
        iterable = []
    for child in sorted(iterable, key=lambda x: x.name.lower()):
        try:
            if not child.is_dir():
                continue
            cp = child.resolve()
            if under_roots(cp):
                dirs.append(FsEntry(name=child.name, path=str(cp)))
        except (PermissionError, OSError):
            continue

    parent = None
    for r in roots:
        try:
            p.relative_to(r)
            if p != r:
                parent = str(p.parent)
            break
        except Exception:
            continue

    return FsListResponse(current=str(p), parent=parent, roots=[str(r) for r in roots], directories=dirs)


@app.get("/api/v1/settings", response_model=SettingsData)
def get_settings():
    """Read current settings from all config YAML files."""
    import sys
    sys.path.insert(0, str(ROOT_DIR))
    try:
        from ruamel.yaml import YAML
        _yaml = YAML()

        def _load(path):
            p = ROOT_DIR / path
            if not p.exists():
                return {}
            with open(p, "r") as f:
                return _yaml.load(f) or {}

        tool = _load("config/tool.yaml")
        project = _load("config/project.yaml")
        estimate = _load("config/estimate.yaml")

        tool_sm = tool.get("state_management", {}) or {}
        tool_an = tool.get("analysis", {}) or {}
        tool_disp = tool.get("display", {}) or {}

        return SettingsData(
            tool_info={"tool_name": str(tool.get("tool_name", "")), "release": str(tool.get("release", ""))},
            project={"title": str(project.get("title", "")), "subtitle": str(project.get("subtitle", ""))},
            display={"timezone": str(tool_disp.get("timezone", "") or "")},
            analysis={
                "run_by_default": bool(tool_an.get("run_by_default", True)),
                "include_frameworks": bool(tool_an.get("include_frameworks", True)),
                "report_theme": str(tool_an.get("report_theme", "hacker_mode")),
                "max_files_per_platform": int(tool_an.get("max_files_per_platform", 300)),
                "max_functions_per_platform": int(tool_an.get("max_functions_per_platform", 1500)),
            },
            state_management={
                "enabled": bool(tool_sm.get("enabled", False)),
                "resume_mode": str(tool_sm.get("resume_mode", "manual")),
                "persist_after_seconds": int(tool_sm.get("persist_after_seconds", 300)),
                "persist_interval_seconds": int(tool_sm.get("persist_interval_seconds", 30)),
                "cleanup_on_success": bool(tool_sm.get("cleanup_on_success", False)),
            },
            estimation={
                "efficiency_factor": int(estimate.get("efficiency_factor", 10)),
                "buffer": int(estimate.get("buffer", 2)),
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"settings_read_error: {exc}")


@app.put("/api/v1/settings", response_model=SettingsData)
def save_settings(payload: SettingsData):
    """Write settings back to config YAML files."""
    import sys
    sys.path.insert(0, str(ROOT_DIR))
    try:
        from ruamel.yaml import YAML
        _yaml = YAML()
        _yaml.preserve_quotes = True

        def _load(path):
            p = ROOT_DIR / path
            if not p.exists():
                return {}
            with open(p, "r") as f:
                return _yaml.load(f) or {}

        def _save(path, data):
            p = ROOT_DIR / path
            with open(p, "w") as f:
                _yaml.dump(data, f)

        # tool.yaml
        tool = _load("config/tool.yaml")
        disp = tool.setdefault("display", {})
        disp["timezone"] = payload.display.timezone

        an = tool.setdefault("analysis", {})
        an["run_by_default"] = payload.analysis.run_by_default
        an["include_frameworks"] = payload.analysis.include_frameworks
        an["report_theme"] = payload.analysis.report_theme
        an["max_files_per_platform"] = payload.analysis.max_files_per_platform
        an["max_functions_per_platform"] = payload.analysis.max_functions_per_platform

        sm = tool.setdefault("state_management", {})
        sm["enabled"] = payload.state_management.enabled
        sm["resume_mode"] = payload.state_management.resume_mode
        sm["persist_after_seconds"] = payload.state_management.persist_after_seconds
        sm["persist_interval_seconds"] = payload.state_management.persist_interval_seconds
        sm["cleanup_on_success"] = payload.state_management.cleanup_on_success

        _save("config/tool.yaml", tool)

        # project.yaml
        project = _load("config/project.yaml")
        project["title"] = payload.project.title
        project["subtitle"] = payload.project.subtitle
        _save("config/project.yaml", project)

        # estimate.yaml
        estimate = _load("config/estimate.yaml")
        estimate["efficiency_factor"] = payload.estimation.efficiency_factor
        estimate["buffer"] = payload.estimation.buffer
        _save("config/estimate.yaml", estimate)

        return get_settings()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"settings_write_error: {exc}")


@app.get("/api/v1/artifacts")
def get_artifact(path: str = Query(...)):
    p = Path(path)
    base = ROOT_DIR
    abs_path = (base / p).resolve() if not p.is_absolute() else p.resolve()

    try:
        abs_path.relative_to(base.resolve())
    except Exception:
        raise HTTPException(status_code=403, detail="forbidden_artifact")

    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="artifact_not_found")
    return FileResponse(abs_path)
