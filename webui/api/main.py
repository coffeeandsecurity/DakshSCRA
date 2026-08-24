import html
import json
import os
import re
import signal
import shutil
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Cookie, Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
import core.reports as core_reports
import state.runtime_state as runtime_state
from core.parser import FILEPATH_RULE_GUIDANCE

from .auth import (
    bootstrap_admin_user,
    clear_session_cookie,
    create_session,
    delete_session,
    get_current_user,
    hash_password,
    require_admin,
    require_password_ok,
    set_session_cookie,
    verify_password,
)
from .config import ADMIN_PASSWORD, ADMIN_USERNAME, ROOT_DIR, SESSION_COOKIE_NAME, get_browse_roots, get_cors_origins
from .database import Base, SessionLocal, engine
from .models import Project, ScanRun, User, UserSession
from .scan_runtime import (
    WEB_RUNS_DIR,
    build_cmd,
    cleanup_run_runtime,
    cmd_as_shell_string,
    execute_scan_sync,
    get_proc,
    project_reports_dir,
    read_log_tail,
    run_dir,
    safe_rel_path,
    scan_artifacts,
)
from .schemas import (
    ArtifactIndex,
    BootstrapInfo,
    ChangePasswordRequest,
    DashboardMetrics,
    FsEntry,
    FsListResponse,
    LoginRequest,
    ProjectSummary,
    ScanCreate,
    ScanDetails,
    ScanSummary,
    SelfChangePasswordRequest,
    SettingsData,
    UserCreate,
    UserOut,
)

@asynccontextmanager
async def _lifespan(app: FastAPI):
    (ROOT_DIR / "runtime").mkdir(parents=True, exist_ok=True)
    WEB_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    _ensure_schema_compatibility()
    _db = SessionLocal()
    try:
        bootstrap_admin_user(_db)
    finally:
        _db.close()
    port = os.environ.get("DAKSH_PORT", "8080")
    print(f"\n  DakshSCRA Web UI  →  http://localhost:{port}\n", flush=True)
    yield


app = FastAPI(title="DakshSCRA API", version="2.0.0", lifespan=_lifespan)

# core.reports/state.runtime_state are written for a single CLI process and
# hold their output paths in module-level globals. regenerate_reports()
# below is the only place this API process touches them, so a lock keeps
# two concurrent regenerate calls from racing on that shared global state.
_report_regen_lock = threading.Lock()


def _enrich_file_path_findings(items):
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            out.append(item)
            continue
        title = str(item.get("rule_title", "")).strip()
        guidance = FILEPATH_RULE_GUIDANCE.get(title, {})
        out.append({
            **item,
            "brief_desc": str(item.get("brief_desc", "")).strip() or guidance.get("brief_desc", "") or str(item.get("rule_desc", "")).strip(),
            "attack_desc": str(item.get("attack_desc", "")).strip() or guidance.get("attack_desc", "") or str(item.get("vuln_desc", "")).strip(),
            "developer_note": str(item.get("developer_note", "")).strip() or guidance.get("developer_note", ""),
            "reviewer_note": str(item.get("reviewer_note", "")).strip() or guidance.get("reviewer_note", ""),
        })
    return out

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every route except health/version/login/logout/me/change-password
# requires a valid session AND a password that isn't still pending a
# forced change. Kept as a separate router (rather than a global app-level
# dependency) so those endpoints can stay reachable pre-login and while a
# password change is still outstanding.
protected = APIRouter(dependencies=[Depends(require_password_ok)])


def _ensure_schema_compatibility() -> None:
    insp = inspect(engine)
    tables = insp.get_table_names()

    if "projects" not in tables:
        Project.__table__.create(bind=engine, checkfirst=True)

    if "users" in tables:
        user_cols = {c["name"] for c in insp.get_columns("users")}
        if "must_change_password" not in user_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0"))
                conn.execute(text("UPDATE users SET must_change_password = 0 WHERE must_change_password IS NULL"))

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
                "UPDATE scan_runs SET project_key = 'default' "
                "WHERE project_key IS NULL OR project_key = '' OR project_key = 'legacy'"
            )
        )
        conn.execute(
            text(
                "UPDATE scan_runs SET project_name = 'Default' "
                "WHERE project_name IS NULL OR project_name = '' OR project_name = 'Legacy'"
            )
        )


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


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


_PROJECT_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")


def _validate_project_key(project_key: str) -> str:
    """Defense-in-depth: project_key drives filesystem paths (reports/<key>,
    _safe_remove_path). Reject anything that isn't a plain generated slug
    before it ever reaches a path operation, even though the existing
    resolve()/relative_to() containment check in _safe_remove_path already
    blocks traversal outside ROOT_DIR."""
    if not project_key or not _PROJECT_KEY_RE.match(project_key):
        raise HTTPException(status_code=400, detail="invalid_project_key")
    return project_key


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

def _run_scan_thread(run_uuid: str, cmd: list, log_path: Path, start_ts: float) -> None:
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
        if not scan:
            return
        if scan.status == "stopped":
            # /stop was called while this scan was still "queued" - honor
            # it instead of clobbering it back to "running" and spawning
            # the subprocess anyway.
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()

        rc = execute_scan_sync(cmd, log_path, run_uuid=run_uuid, project_key=scan.project_key)

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

            artifacts = scan_artifacts(run_uuid, project_key=scan.project_key)
            scan.artifacts_json = json.dumps(artifacts)
            db.commit()
            cleanup_run_runtime(run_uuid)
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


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        is_admin=user.is_admin,
        must_change_password=user.must_change_password,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
    )


@app.get("/api/v1/auth/bootstrap-info", response_model=BootstrapInfo)
def get_bootstrap_info(db: Session = Depends(db_session)):
    # Public, and only reveals anything while the bootstrapped admin
    # account is still on its assigned password. default_password only
    # ever surfaces the *configured* DAKSH_ADMIN_PASSWORD - if that env
    # var was left unset at bootstrap, a one-time random password was
    # generated and printed to the startup log instead, and there is no
    # way to recover it here, so this deliberately stays null in that case
    # rather than guessing.
    admin = db.query(User).filter(User.username == ADMIN_USERNAME).first()
    pending = bool(admin and admin.must_change_password)
    return BootstrapInfo(
        default_username=ADMIN_USERNAME,
        default_credentials_pending=pending,
        default_password=(ADMIN_PASSWORD or None) if pending else None,
    )


@app.post("/api/v1/auth/login", response_model=UserOut)
def login(payload: LoginRequest, response: Response, db: Session = Depends(db_session)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    token = create_session(db, user)
    set_session_cookie(response, token)
    return _user_out(user)


@app.post("/api/v1/auth/logout")
def logout(
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(db_session),
):
    # Intentionally public (no get_current_user dependency): a session that
    # is already invalid/expired must still be able to clear its cookie
    # and get a clean 200 rather than a 401 on its way out.
    delete_session(db, session_token or "")
    clear_session_cookie(response)
    return {"status": "logged_out"}


@app.get("/api/v1/auth/me", response_model=UserOut)
def get_me(user: User = Depends(get_current_user)):
    # Deliberately on the plain `app` (not `protected`/require_password_ok):
    # the frontend needs this to succeed precisely when must_change_password
    # is true, so it can detect the flag and show the change-password gate.
    return _user_out(user)


@app.post("/api/v1/auth/change-password", response_model=UserOut)
def change_own_password(
    payload: SelfChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    # Also deliberately on `app`: this is the one action a user with
    # must_change_password=True must still be able to take.
    # The login request has already verified the assigned credential for a
    # user in the mandatory first-time/reset flow. Requiring it again risks
    # locking out someone who did not retain the temporary password. Normal
    # voluntary password changes still require current-password verification.
    if not user.must_change_password and (
        not payload.current_password
        or not verify_password(payload.current_password, user.password_hash)
    ):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    # get_current_user resolves `user` through its own DB session
    # (auth.py's _get_db), separate from this route's `db` (db_session) -
    # mutating `user` and committing via `db` would silently do nothing,
    # since `db` never loaded that row. Re-fetch it in `db`'s own session.
    db_user = db.query(User).filter(User.id == user.id).first()

    new_username = (payload.new_username or "").strip()
    if new_username and new_username != db_user.username:
        # Username changes are only permitted while completing the mandatory
        # first-time/reset flow (must_change_password was true coming into
        # this request) - never on a later voluntary password change. Once
        # that flow is done, the username is fixed until an admin resets it
        # again via exclude/scripts/reset_first_time_setup.py.
        if not user.must_change_password:
            raise HTTPException(status_code=403, detail="username_change_not_allowed")
        taken = db.query(User).filter(User.username == new_username, User.id != db_user.id).first()
        if taken:
            raise HTTPException(status_code=409, detail="username_taken")
        db_user.username = new_username

    db_user.password_hash = hash_password(payload.new_password)
    db_user.must_change_password = False
    db.commit()
    db.refresh(db_user)
    return _user_out(db_user)


@protected.get("/api/v1/auth/users", response_model=List[UserOut], dependencies=[Depends(require_admin)])
def list_users(db: Session = Depends(db_session)):
    return [_user_out(u) for u in db.query(User).order_by(User.username).all()]


@protected.post("/api/v1/auth/users", response_model=UserOut, dependencies=[Depends(require_admin)])
def create_user(payload: UserCreate, db: Session = Depends(db_session)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=409, detail="username_taken")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        is_admin=payload.is_admin,
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_out(user)


@protected.delete("/api/v1/auth/users/{user_id}", status_code=204, dependencies=[Depends(require_admin)])
def delete_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="cannot_delete_self")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="user_not_found")
    if target.is_admin and db.query(User).filter(User.is_admin.is_(True)).count() <= 1:
        raise HTTPException(status_code=400, detail="cannot_delete_last_admin")
    db.query(UserSession).filter(UserSession.user_id == user_id).delete()
    db.delete(target)
    db.commit()


@protected.post("/api/v1/auth/users/{user_id}/reset-password", dependencies=[Depends(require_admin)])
def reset_user_password(user_id: int, payload: ChangePasswordRequest, db: Session = Depends(db_session)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="user_not_found")
    target.password_hash = hash_password(payload.new_password)
    target.must_change_password = True
    db.query(UserSession).filter(UserSession.user_id == user_id).delete()
    db.commit()
    return {"status": "password_reset", "user_id": user_id}


@protected.post("/api/v1/scans", response_model=ScanDetails)
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
        args=(run_uuid, cmd, log_path, start_ts),
        daemon=True,
    )
    t.start()

    return _serialize_scan(scan)


@protected.post("/api/v1/scans/{run_uuid}/stop")
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


@protected.get("/api/v1/scans/{run_uuid}/stream")
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
        last_progress_marker = ""
        while True:
            inner_db = SessionLocal()
            try:
                s = inner_db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
                current_status = s.status if s else "unknown"
                scan_started_at = (s.started_at or s.created_at) if s else None
            except Exception:
                current_status = "unknown"
                scan_started_at = None
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
            progress_payload = _scan_progress_payload(
                run_uuid,
                fallback_status=current_status,
                started_at=scan_started_at,
            )
            progress_marker = json.dumps(progress_payload, sort_keys=True)
            if new_chunk or current_status not in ("running", "queued") or progress_marker != last_progress_marker:
                data = json.dumps({"log": new_chunk, "status": current_status, "progress": progress_payload})
                yield f"data: {data}\n\n"
                last_progress_marker = progress_marker
            else:
                # SSE keep-alive comment every ~15 s of silence
                idle_ticks += 1
                if idle_ticks % 19 == 0:
                    yield ": keep-alive\n\n"

            if current_status not in ("running", "queued"):
                yield f"data: {json.dumps({'log': '', 'status': current_status, 'done': True, 'progress': progress_payload})}\n\n"
                break

            time.sleep(0.8)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@protected.get("/api/v1/scans", response_model=List[ScanSummary])
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


@protected.get("/api/v1/scans/{run_uuid}", response_model=ScanDetails)
def get_scan(run_uuid: str, db: Session = Depends(db_session)):
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")
    return _serialize_scan(row)


@protected.get("/api/v1/scans/{run_uuid}/artifacts", response_model=ArtifactIndex)
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
        artifacts = scan_artifacts(run_uuid, project_key=row.project_key)
        if artifacts:
            try:
                row.artifacts_json = json.dumps(artifacts)
                db.commit()
            except Exception:
                db.rollback()
    return _artifact_index(artifacts)


@protected.get("/api/v1/scans/{run_uuid}/log")
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


def _scan_reports_root(project_key: str, run_uuid: str) -> Path:
    # Deliberately does NOT fall back to the bare top-level `reports/` root -
    # that directory is the parent of every project's reports, and using it
    # as a fallback here would leak one project's/run's data into another's
    # findings/artifacts response whenever a specific run's own dir is
    # missing, instead of correctly reporting "nothing found".
    candidates = [
        project_reports_dir(project_key, run_uuid),
        ROOT_DIR / "reports" / run_uuid,
        run_dir(run_uuid) / "reports",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _scan_data_dir(project_key: str, run_uuid: str) -> Path:
    return _scan_reports_root(project_key, run_uuid) / "data"


def _safe_progress_int(value, default=0):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _scan_progress_payload(run_uuid: str, fallback_status: str = "", started_at=None):
    rdir = run_dir(run_uuid)
    runtime_dir = rdir / "runtime"
    scan_state = _load_json_safe(runtime_dir / "scan_state.json") or {}
    scan_summary = _load_json_safe(runtime_dir / "scan_summary.json") or {}

    progress = (scan_state.get("progress") or {}) if isinstance(scan_state, dict) else {}
    cursor = progress.get("cursor") or {}
    heartbeat = progress.get("heartbeat") or {}
    stages = progress.get("stages") or {}
    live = (scan_summary.get("live_progress") or {}) if isinstance(scan_summary, dict) else {}
    analyzer = (scan_summary.get("analyzer_summary") or {}) if isinstance(scan_summary, dict) else {}
    detection = (scan_summary.get("detection_summary") or {}) if isinstance(scan_summary, dict) else {}

    fallback_stage = "queued" if fallback_status == "queued" else "initialization" if fallback_status == "running" else ""
    fallback_message = (
        "Scan queued - preparing isolated workspace"
        if fallback_status == "queued"
        else "Scan engine started - preparing repository"
        if fallback_status == "running"
        else ""
    )
    fallback_elapsed = 0
    if started_at:
        try:
            fallback_elapsed = max(0, int((datetime.now(timezone.utc).replace(tzinfo=None) - started_at).total_seconds()))
        except (TypeError, ValueError):
            fallback_elapsed = 0

    current_stage = str(live.get("stage") or progress.get("current_stage") or fallback_stage).strip()
    stage_status = str((stages.get(current_stage) or {}).get("status") or live.get("status") or "").strip()
    return {
        "current_stage": current_stage,
        "stage_status": stage_status,
        "message": str(live.get("message") or heartbeat.get("message") or analyzer.get("heartbeat_message") or fallback_message).strip(),
        "platform": str(live.get("platform") or analyzer.get("current_target") or cursor.get("platform") or "").strip(),
        "category": str(live.get("category") or cursor.get("category") or "").strip(),
        "rule_title": str(live.get("rule_title") or cursor.get("rule_title") or "").strip(),
        "current_file": str(live.get("current_file") or cursor.get("current_file") or cursor.get("filepath") or "").strip(),
        "current_function": str(live.get("current_function") or cursor.get("current_function") or "").strip(),
        "current_phase": str(live.get("current_phase") or cursor.get("current_phase") or heartbeat.get("phase") or "").strip(),
        "current_index": _safe_progress_int(live.get("current_index") or cursor.get("current_index") or cursor.get("file_index")),
        "total_items": _safe_progress_int(live.get("total_items") or cursor.get("total_items")),
        "elapsed_seconds": _safe_progress_int(live.get("elapsed_seconds") or heartbeat.get("elapsed_seconds"), fallback_elapsed),
        "directories_scanned": _safe_progress_int(live.get("directories_scanned")),
        "files_discovered": _safe_progress_int(live.get("files_discovered") or detection.get("total_project_files_identified")),
        "files_selected": _safe_progress_int(live.get("files_selected") or detection.get("total_files_identified")),
        "rules_match_count": _safe_progress_int(live.get("rules_match_count") or detection.get("areas_of_interest_identified")),
        "suppressed_count": _safe_progress_int(live.get("suppressed_count") or detection.get("suppressed_findings")),
        "paths_match_count": _safe_progress_int(live.get("paths_match_count") or detection.get("file_paths_areas_of_interest_identified")),
        "parse_error_count": _safe_progress_int(live.get("parse_error_count")),
    }


@protected.get("/api/v1/scans/{run_uuid}/findings")
def get_scan_findings(run_uuid: str, db: Session = Depends(db_session)):
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")

    rdir = run_dir(run_uuid)
    json_dir = _scan_data_dir(row.project_key, run_uuid)
    runtime_dir = rdir / "runtime"

    findings = _load_json_safe(json_dir / "areas_of_interest.json") or []
    summary = _load_json_safe(json_dir / "summary.json")
    filepaths = _enrich_file_path_findings(_load_json_safe(json_dir / "filepaths_aoi.json") or [])
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
        "progress": _scan_progress_payload(
            run_uuid,
            fallback_status=row.status,
            started_at=row.started_at or row.created_at,
        ),
        "loc_breakdown": loc_breakdown,
    }


@protected.get("/api/v1/projects", response_model=List[ProjectSummary])
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
        latest_scan = max(scans, key=lambda s: s.created_at or datetime.min, default=None)
        latest = latest_scan.created_at if latest_scan and latest_scan.created_at else None
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
                latest_run_uuid=latest_scan.run_uuid if latest_scan else None,
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
        latest = latest_scan.created_at if latest_scan.created_at else None
        out.append(
            ProjectSummary(
                project_key=scan_key,
                project_name=latest_scan.project_name or "Default",
                target_dir=latest_scan.target_dir,
                rules=latest_scan.rules,
                total_scans=len(scans),
                running_scans=running,
                failed_scans=failed,
                latest_scan_at=latest.isoformat() if latest else None,
                latest_run_uuid=latest_scan.run_uuid,
            )
        )

    out.sort(key=lambda x: x.latest_scan_at or "", reverse=True)
    return out


def _safe_remove_path(path_value: str, *, is_dir: bool) -> None:
    if not path_value:
        return
    p = Path(path_value)
    if not p.is_absolute():
        p = (ROOT_DIR / p).resolve()
    else:
        p = p.resolve()
    try:
        p.relative_to(ROOT_DIR.resolve())
    except ValueError:
        return
    try:
        if is_dir:
            shutil.rmtree(p, ignore_errors=True)
        elif p.exists():
            p.unlink()
    except Exception:
        pass


@protected.delete("/api/v1/projects/{project_key}", status_code=204)
def delete_project(project_key: str, db: Session = Depends(db_session)):
    project_key = _validate_project_key(project_key)
    project = db.query(Project).filter(Project.project_key == project_key).first()
    scans = db.query(ScanRun).filter(ScanRun.project_key == project_key).all()
    if not project and not scans:
        raise HTTPException(status_code=404, detail="project_not_found")
    running = next((scan for scan in scans if scan.status in ("running", "queued")), None)
    if running:
        raise HTTPException(status_code=409, detail="project_has_active_scans")
    run_ids = [scan.run_uuid for scan in scans if scan.run_uuid]
    log_paths = [scan.log_path for scan in scans if scan.log_path]
    db.query(ScanRun).filter(ScanRun.project_key == project_key).delete(synchronize_session=False)
    if project:
        db.delete(project)
    db.commit()
    _safe_remove_path(str(project_reports_dir(project_key)), is_dir=True)
    for run_id in run_ids:
        _safe_remove_path(str(run_dir(run_id)), is_dir=True)
    for log_path in log_paths:
        _safe_remove_path(log_path, is_dir=False)


@protected.get("/api/v1/dashboard/metrics", response_model=DashboardMetrics)
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


@protected.get("/api/v1/fs/list", response_model=FsListResponse)
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


@protected.get("/api/v1/settings", response_model=SettingsData)
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


@protected.put("/api/v1/settings", response_model=SettingsData)
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


@protected.get("/api/v1/scans/{run_uuid}/suppressed")
def get_suppressed_findings(run_uuid: str, db: Session = Depends(db_session)):
    """Return suppressed findings (RDL-filtered FPs) for a scan."""
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")

    sup_path = _scan_data_dir(row.project_key, run_uuid) / "suppressed_findings.json"
    suppressed = _load_json_safe(sup_path) or []

    # Build summary metrics
    total_suppressed = len(suppressed)
    rdl_conditions_hit = len({s["rdl_condition"] for s in suppressed if s.get("rdl_condition")})
    promoted = sum(1 for s in suppressed if s.get("status") == "confirmed_finding")

    return {
        "run_uuid": run_uuid,
        "summary": {
            "total_suppressed": total_suppressed,
            "rdl_conditions_triggered": rdl_conditions_hit,
            "promoted_to_findings": promoted,
        },
        "suppressed": suppressed,
    }


@protected.put("/api/v1/scans/{run_uuid}/suppressed/{item_id}")
def update_suppressed_item(
    run_uuid: str,
    item_id: str,
    payload: dict,
    db: Session = Depends(db_session),
):
    """Update metadata on a suppressed finding (notes, status, etc.)."""
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")

    sup_path = _scan_data_dir(row.project_key, run_uuid) / "suppressed_findings.json"
    suppressed = _load_json_safe(sup_path) or []

    item = next((s for s in suppressed if s.get("id") == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="item_not_found")

    allowed_fields = {"notes", "status", "confidence", "confidence_level", "severity", "rating"}
    for k, v in payload.items():
        if k in allowed_fields:
            item[k] = v

    try:
        sup_path.write_text(json.dumps(suppressed, indent=2), encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"write_error: {exc}")

    return item


@protected.post("/api/v1/scans/{run_uuid}/suppressed/{item_id}/promote")
def promote_suppressed_to_finding(
    run_uuid: str,
    item_id: str,
    payload: dict,
    db: Session = Depends(db_session),
):
    """
    Promote a suppressed FP back to active findings.
    Payload: { confidence, confidence_level, severity, rating, notes }
    """
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")

    data_dir = _scan_data_dir(row.project_key, run_uuid)
    sup_path = data_dir / "suppressed_findings.json"
    findings_path = data_dir / "areas_of_interest.json"

    suppressed = _load_json_safe(sup_path) or []
    findings = _load_json_safe(findings_path) or []

    item = next((s for s in suppressed if s.get("id") == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="item_not_found")

    # Update suppressed item status
    item["status"] = "confirmed_finding"
    item["promoted_at"] = datetime.now(timezone.utc).isoformat()
    for k in ("confidence", "confidence_level", "severity", "rating", "notes"):
        if k in payload:
            item[k] = payload[k]

    # Merge into findings: look for existing finding with same platform + rule_title
    platform = item.get("platform", "")
    rule_title = item.get("rule_title", "")
    existing = next(
        (f for f in findings if f.get("platform") == platform and f.get("rule_title") == rule_title),
        None,
    )

    ev_entry = {
        "file": item.get("file", ""),
        "line": item.get("line", 0),
        "code": item.get("code", ""),
        "promoted_from_suppressed": True,
    }
    if item.get("context_before"):
        ev_entry["context_before"] = item["context_before"]
    if item.get("context_after"):
        ev_entry["context_after"] = item["context_after"]

    if existing is None:
        new_finding = {
            "platform": platform,
            "rule_id": f"{platform}-promoted",
            "rule_title": rule_title,
            "category": item.get("category", ""),
            "issue_scope": "",
            "rule_desc": "",
            "issue_desc": "",
            "developer_note": "",
            "reviewer_note": item.get("notes", ""),
            "confidence_score": payload.get("confidence", 50),
            "confidence_level": payload.get("confidence_level", "medium"),
            "scan_config": {},
            "evidence": [ev_entry],
        }
        for k in ("severity", "rating"):
            if k in payload:
                new_finding[k] = payload[k]
        findings.append(new_finding)
    else:
        if not any(e.get("file") == ev_entry["file"] and e.get("line") == ev_entry["line"]
                   for e in existing.get("evidence", [])):
            existing.setdefault("evidence", []).append(ev_entry)
        for k in ("confidence_score", "confidence_level", "severity", "rating"):
            if k in payload:
                existing[k] = payload[k]
        if payload.get("notes"):
            existing["reviewer_note"] = payload["notes"]

    try:
        sup_path.write_text(json.dumps(suppressed, indent=2), encoding="utf-8")
        findings_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"write_error: {exc}")

    return {"status": "promoted", "item_id": item_id}


@protected.get("/api/v1/scans/{run_uuid}/suppressed-report")
def get_suppressed_report(
    run_uuid: str,
    format: str = Query(default="json"),
    db: Session = Depends(db_session),
):
    """Download suppressed findings report in json or html format."""
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")

    sup_path = _scan_data_dir(row.project_key, run_uuid) / "suppressed_findings.json"
    suppressed = _load_json_safe(sup_path) or []

    if format == "json":
        total_suppressed = len(suppressed)
        rdl_conditions_hit = len({s["rdl_condition"] for s in suppressed if s.get("rdl_condition")})
        report = {
            "run_uuid": run_uuid,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_suppressed": total_suppressed,
                "rdl_conditions_triggered": rdl_conditions_hit,
            },
            "suppressed_findings": suppressed,
        }
        from fastapi.responses import JSONResponse
        return JSONResponse(
            content=report,
            headers={"Content-Disposition": f"attachment; filename=suppressed_findings_{run_uuid[:8]}.json"},
        )

    if format == "html":
        html = _build_suppressed_html_report(run_uuid, suppressed)
        from fastapi.responses import HTMLResponse
        return HTMLResponse(
            content=html,
            headers={"Content-Disposition": f"attachment; filename=suppressed_findings_{run_uuid[:8]}.html"},
        )

    raise HTTPException(status_code=400, detail="invalid_format")


@protected.post("/api/v1/scans/{run_uuid}/regenerate-reports")
def regenerate_reports(run_uuid: str, db: Session = Depends(db_session)):
    """Regenerate HTML/JSON reports for a scan (e.g. after promoting suppressed findings)."""
    row = db.query(ScanRun).filter(ScanRun.run_uuid == run_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="run_not_found")

    reports_root = _scan_reports_root(row.project_key, run_uuid)
    if not reports_root.exists():
        raise HTTPException(status_code=404, detail="reports_not_found")

    with _report_regen_lock:
        try:
            # The CLI always gets a fresh per-run runtime_dirpath via the
            # DAKSH_RUNTIME_DIR env var at process start, so
            # configure_project_paths() only takes project/run hints and
            # re-derives its runtime_dirpath-relative globals (scan summary,
            # filepaths, etc.) from whatever runtime_dirpath already is.
            # This API process is long-lived and is regenerating a specific
            # *past* run's report on demand, so runtime_dirpath must be
            # pointed at that run's own runtime dir BEFORE calling
            # configure_project_paths(), not after.
            runtime_state.runtime_dirpath = run_dir(run_uuid) / "runtime"
            runtime_state.configure_project_paths(row.project_key, run_uuid)
            core_reports.gen_report(formats="html", include_multifile_pdf=False)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"regenerate_error: {exc}")

    return {"status": "regenerated", "run_uuid": run_uuid}


def _esc(value) -> str:
    """HTML-escape a value that may originate from scanned source content
    before it is interpolated into a report string, to prevent stored XSS
    (a scanned file containing e.g. "<script>" must not execute when the
    generated report is viewed)."""
    return html.escape(str(value if value is not None else ""))


def _build_suppressed_html_report(run_uuid: str, suppressed: list) -> str:
    """Build an HTML report for suppressed (RDL-filtered) findings."""
    total = len(suppressed)
    rdl_hit = len({s.get("rdl_condition", "") for s in suppressed if s.get("rdl_condition")})
    promoted = sum(1 for s in suppressed if s.get("status") == "confirmed_finding")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = ""
    for s in suppressed:
        status_badge = (
            '<span style="background:#22c55e;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px">Promoted</span>'
            if s.get("status") == "confirmed_finding"
            else '<span style="background:#f59e0b;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px">Suppressed</span>'
        )
        rows += f"""
        <tr>
          <td style="padding:8px;border-bottom:1px solid #333">{_esc(s.get("platform",""))}</td>
          <td style="padding:8px;border-bottom:1px solid #333">{_esc(s.get("rule_title",""))}</td>
          <td style="padding:8px;border-bottom:1px solid #333">{_esc(s.get("file",""))}</td>
          <td style="padding:8px;border-bottom:1px solid #333;font-family:monospace;font-size:12px">{_esc(s.get("line",""))}: {_esc(s.get("code",""))}</td>
          <td style="padding:8px;border-bottom:1px solid #333;font-family:monospace;font-size:11px">{_esc(s.get("rdl_condition",""))}</td>
          <td style="padding:8px;border-bottom:1px solid #333;font-size:12px">{_esc(s.get("suppression_reason",""))}</td>
          <td style="padding:8px;border-bottom:1px solid #333">{status_badge}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Suppressed Findings Report - {_esc(run_uuid[:8])}</title>
  <style>
    body {{ background:#0f172a; color:#e2e8f0; font-family:sans-serif; margin:0; padding:24px; }}
    h1 {{ color:#f8fafc; font-size:22px; }}
    .meta {{ color:#94a3b8; font-size:13px; margin-bottom:24px; }}
    .cards {{ display:flex; gap:16px; margin-bottom:32px; flex-wrap:wrap; }}
    .card {{ background:#1e293b; border-radius:8px; padding:16px 24px; min-width:160px; }}
    .card-val {{ font-size:28px; font-weight:700; color:#f8fafc; }}
    .card-lbl {{ font-size:12px; color:#94a3b8; margin-top:4px; }}
    table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:8px; overflow:hidden; }}
    th {{ background:#334155; color:#94a3b8; font-size:12px; text-transform:uppercase; padding:10px 8px; text-align:left; }}
    tr:hover {{ background:#263347; }}
  </style>
</head>
<body>
  <h1>Suppressed Findings Report</h1>
  <div class="meta">Scan: {_esc(run_uuid)} &mdash; Generated: {_esc(generated)}</div>
  <div class="cards">
    <div class="card"><div class="card-val">{total}</div><div class="card-lbl">Total Suppressed</div></div>
    <div class="card"><div class="card-val">{rdl_hit}</div><div class="card-lbl">RDL Conditions Triggered</div></div>
    <div class="card"><div class="card-val">{promoted}</div><div class="card-lbl">Promoted to Findings</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Platform</th><th>Rule</th><th>File</th><th>Code</th>
        <th>RDL Condition</th><th>Suppression Reason</th><th>Status</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""


@protected.get("/api/v1/artifacts")
def get_artifact(path: str = Query(...), embed: bool = Query(False)):
    p = Path(path)
    base = ROOT_DIR
    abs_path = (base / p).resolve() if not p.is_absolute() else p.resolve()

    # Scope this to the actual scan-artifact trees, not the whole repo -
    # this endpoint must not double as a generic file server for configs,
    # the sqlite DB, source code, or another project's reports.
    allowed_roots = [
        (ROOT_DIR / "reports").resolve(),
        (WEB_RUNS_DIR).resolve(),
    ]
    if not any(_is_within(abs_path, root) for root in allowed_roots):
        raise HTTPException(status_code=403, detail="forbidden_artifact")

    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="artifact_not_found")

    if embed and abs_path.suffix.lower() == ".html":
        try:
            html = abs_path.read_text(encoding="utf-8")
            embed_style = """
<style id="daksh-embed-style">
  :root {
    --embed-bg: #f6f8fb;
    --embed-panel: #ffffff;
    --embed-line: #d8dee8;
    --embed-line-strong: #c4cdd9;
    --embed-text: #1f2937;
    --embed-muted: #6b7280;
    --embed-accent: #2563eb;
    --embed-accent-soft: #eef4ff;
  }
  html, body {
    margin: 0 !important;
    padding: 0 !important;
    background: var(--embed-bg) !important;
    color: var(--embed-text) !important;
    font-family: var(--font-sans, Inter, Segoe UI, Arial, sans-serif) !important;
  }
  body {
    padding: 16px !important;
  }
  h1, h2, h3, h4, h5, h6, .h1, .meta, .k, .v, summary.head, td, th, .panel, .mcard, .sec, .quick, .chip, .badge, .lg {
    color: var(--embed-text) !important;
  }
  h1 {
    font-size: 24px !important;
    font-weight: 800 !important;
    margin: 0 0 8px !important;
  }
  body > p:first-of-type,
  .back {
    display: none !important;
  }
  table {
    border-collapse: separate !important;
    border-spacing: 0 8px !important;
  }
  th {
    background: #f8fafc !important;
    color: var(--embed-text) !important;
    border: 1px solid var(--embed-line) !important;
    font-weight: 700 !important;
  }
  td {
    background: var(--embed-panel) !important;
    color: var(--embed-text) !important;
    border: 1px solid var(--embed-line) !important;
  }
  .muted {
    color: var(--embed-muted) !important;
  }
  .badge, .chip, .file-pill, .lg {
    background: var(--embed-accent-soft) !important;
    color: var(--embed-accent) !important;
    border: 1px solid #bfd2ff !important;
    font-weight: 700 !important;
  }
  .panel, .mcard, .sec, details.card, .path-step, .section-card {
    background: var(--embed-panel) !important;
    border: 1px solid var(--embed-line) !important;
    border-radius: 12px !important;
    box-shadow: none !important;
  }
  .code-block, .code, .flow-chain, .graph-note {
    background: #f8fafc !important;
    color: var(--embed-text) !important;
    border: 1px solid var(--embed-line-strong) !important;
  }
  .quick, .xref-link {
    background: var(--embed-accent-soft) !important;
    color: var(--embed-accent) !important;
    border: 1px solid #bfd2ff !important;
    font-weight: 700 !important;
  }
  .graph {
    background: #f8fafc !important;
    border: 1px solid var(--embed-line) !important;
  }
  .graph svg text {
    fill: var(--embed-text) !important;
    font-weight: 700 !important;
  }
  .graph svg path, .graph svg line, .graph svg polyline {
    stroke-width: 2 !important;
    stroke-opacity: 1 !important;
  }
</style>
"""
            if "</head>" in html:
                html = html.replace("</head>", embed_style + "\n</head>", 1)
            else:
                html = embed_style + html
            return HTMLResponse(html)
        except OSError:
            pass
    return FileResponse(abs_path)


app.include_router(protected)
