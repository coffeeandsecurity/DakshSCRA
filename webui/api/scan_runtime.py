import os
import shlex
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional

from .config import ROOT_DIR

RUNTIME_DIR = ROOT_DIR / "runtime"
WEB_RUNS_DIR = RUNTIME_DIR / "web_runs_v2"

# Active subprocess registry — keyed by run_uuid
_active_procs: Dict[str, subprocess.Popen] = {}
_procs_lock = threading.Lock()


def register_proc(run_uuid: str, proc: subprocess.Popen) -> None:
    with _procs_lock:
        _active_procs[run_uuid] = proc


def unregister_proc(run_uuid: str) -> None:
    with _procs_lock:
        _active_procs.pop(run_uuid, None)


def get_proc(run_uuid: str) -> Optional[subprocess.Popen]:
    with _procs_lock:
        return _active_procs.get(run_uuid)


def safe_rel_path(path_str: str) -> str:
    p = Path(path_str)
    if p.is_absolute():
        try:
            rel = p.resolve().relative_to(ROOT_DIR.resolve())
            return str(rel)
        except Exception:
            return ""
    return str(p)


def run_dir(run_uuid: str) -> Path:
    """Per-scan working directory inside WEB_RUNS_DIR."""
    return WEB_RUNS_DIR / run_uuid


def build_cmd(payload: dict) -> List[str]:
    cmd = [sys.executable, "dakshscra.py", "-r", payload["rules"], "-t", payload["target_dir"]]
    ft = (payload.get("file_types") or "").strip()
    if ft and ft.lower() != "auto":
        cmd += ["-f", ft]

    v = int(payload.get("verbosity", 1) or 1)
    if v >= 1:
        cmd.append("-" + ("v" * min(v, 3)))

    rpt = payload.get("report_format", "html")
    if rpt:
        cmd += ["-rpt", rpt]

    if payload.get("recon"):
        cmd.append("--recon")
    if payload.get("estimate"):
        cmd.append("--estimate")
    if payload.get("analysis") is False:
        cmd.append("--skip-analysis")
    if payload.get("loc"):
        cmd.append("--loc")

    return cmd


def scan_artifacts(run_uuid: str) -> List[str]:
    """Collect all artifacts written to the per-scan output directory."""
    if not run_uuid:
        return []
    rdir = run_dir(run_uuid)
    roots = [rdir / "reports", rdir / "runtime"]
    allowed = {".html", ".pdf", ".json", ".txt", ".log"}
    artifacts = []
    for base in roots:
        if not base.exists():
            continue
        for f in base.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix.lower() not in allowed:
                continue
            try:
                rel = safe_rel_path(str(f))
                if rel:
                    artifacts.append(rel)
            except OSError:
                continue
    return sorted(set(artifacts))


def execute_scan_sync(cmd: List[str], log_path: Path, run_uuid: str = "") -> int:
    WEB_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["DAKSH_NON_INTERACTIVE"] = "1"

    # Isolate each scan's output so reports/json/areas_of_interest.json etc.
    # don't get overwritten by concurrent or subsequent scans.
    if run_uuid:
        rdir = run_dir(run_uuid)
        run_reports = rdir / "reports"
        run_runtime = rdir / "runtime"
        run_reports.mkdir(parents=True, exist_ok=True)
        run_runtime.mkdir(parents=True, exist_ok=True)
        env["DAKSH_REPORTS_DIR"] = str(run_reports)
        env["DAKSH_RUNTIME_DIR"] = str(run_runtime)

    with open(log_path, "w", encoding="utf-8") as logf:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=logf,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if run_uuid:
            register_proc(run_uuid, proc)
        try:
            return proc.wait()
        finally:
            if run_uuid:
                unregister_proc(run_uuid)


def read_log_tail(log_path: Path, max_chars: int = 120000) -> str:
    if not log_path.exists():
        return ""
    try:
        txt = log_path.read_text(encoding="utf-8", errors="replace")
        return txt[-max_chars:]
    except Exception:
        return ""


def cmd_as_shell_string(cmd: List[str]) -> str:
    return " ".join(shlex.quote(x) for x in cmd)
