import os
import json
import shlex
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional

from .config import ROOT_DIR

RUNTIME_DIR = ROOT_DIR / "runtime"
WEB_RUNS_DIR = RUNTIME_DIR / "web_runs_v2"

# Active subprocess registry - keyed by run_uuid
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


def project_reports_dir(project_key: str, run_uuid: str = "") -> Path:
    if run_uuid and (run_dir(run_uuid) / 'results').exists():
        return run_dir(run_uuid) / 'results'
    base = (ROOT_DIR / "reports" / str(project_key or "default")).resolve()
    return (base / str(run_uuid)) if run_uuid else base


def cleanup_run_runtime(run_uuid: str) -> None:
    """Remove only the noisy/large scratch data for a finished run.

    scan_summary.json, scan_state.json, filepaths.json etc. under
    runtime/ are read later by /findings, the progress payload, and
    report regeneration, so the whole runtime/ tree must not be deleted
    here - only the decision-trace diagnostics subdirectory, which can
    grow large and has no reader once the run is done.
    """
    if not run_uuid:
        return
    diagnostics_dir = run_dir(run_uuid) / "runtime" / "diagnostics"
    try:
        shutil.rmtree(diagnostics_dir, ignore_errors=True)
    except Exception:
        pass


def build_cmd(payload: dict) -> List[str]:
    cmd = [sys.executable, "dakshscra.py", "-r", payload["rules"], "-t", payload["target_dir"]]
    mode = payload.get("rdl_engine", "both")
    if mode not in {"v1", "v2", "both"}:
        raise ValueError("RDL engine must be v1, v2, or both")
    cmd += ["--rdl-engine", mode]
    custom = payload.get('custom_rdl') or []
    if not isinstance(custom, list) or len(custom) > 8 or not all(isinstance(p, str) and p.strip() for p in custom):
        raise ValueError('Custom RDL must be a list of up to 8 pack paths')
    if custom and mode == 'v1':
        raise ValueError('Custom RDL packs require v2 or both engines')
    for pack in custom:
        cmd += ['--custom-rdl', pack]
    ft = (payload.get("file_types") or "").strip()
    if ft and ft.lower() != "auto":
        cmd += ["-f", ft]

    v = int(payload.get("verbosity", 1) or 1)
    if v >= 1:
        cmd.append("-" + ("v" * min(v, 3)))


    if payload.get("recon", True):
        cmd.append("--recon")
    if payload.get("estimate"):
        cmd.append("--estimate")
        if payload.get('recon') is False:
            cmd.append('--no-recon')
        if payload.get('loc') is False:
            cmd.append('--no-loc')
        if payload.get('estimate_assumptions'):
            cmd += ['--estimate-assumptions', json.dumps(payload['estimate_assumptions'])]
    if payload.get("analysis") is False:
        cmd.append("--skip-analysis")
    if payload.get("loc", True):
        cmd.append("--loc")

    from .schemas import ScanOptions
    options = ScanOptions.model_validate(payload)
    for field, flag in [('exclude_checks', '--exclude-check'), ('exclude_paths', '--exclude-path'),
                        ('exclude_types', '--exclude-type'), ('exclude_keywords', '--exclude-keyword')]:
        for token in getattr(options, field):
            # Equals form prevents a leading '-' in a literal/glob from
            # being mistaken for another CLI option. No shell is involved.
            cmd.append(flag + '=' + token)
    if options.recon_strict:
        cmd.append('--recon-strict')
    if options.baseline_mode == 'disabled':
        cmd.append('--no-baseline')
    elif options.baseline_mode == 'custom':
        cmd += ['--baseline-file', options.baseline_file]
    if options.review_config:
        cmd += ['--review-config', options.review_config]
    if options.state_mode != 'default':
        cmd.append('--state' if options.state_mode == 'enabled' else '--no-state')

    return cmd


def scan_artifacts(run_uuid: str, project_key: str = "") -> List[str]:
    """Collect all artifacts written to the per-scan output directory."""
    if not run_uuid:
        return []
    rdir = run_dir(run_uuid)
    roots = [
        project_reports_dir(project_key, run_uuid),
        ROOT_DIR / "reports" / run_uuid,
        rdir / "reports",
        rdir / "runtime",
    ]
    allowed = {".html", ".pdf", ".json", ".gz", ".txt", ".log"}
    artifacts = []
    seen_roots = set()
    for base in roots:
        base = base.resolve()
        if str(base) in seen_roots:
            continue
        seen_roots.add(str(base))
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


def execute_scan_sync(cmd: List[str], log_path: Path, run_uuid: str = "", project_key: str = "") -> int:
    WEB_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["DAKSH_NON_INTERACTIVE"] = "1"
    env["DAKSH_OUTPUT_MODE"] = "web"

    # Isolate each scan's output so reports/json/areas_of_interest.json etc.
    # don't get overwritten by concurrent or subsequent scans.
    if run_uuid:
        rdir = run_dir(run_uuid)
        run_runtime = rdir / "runtime"
        run_runtime.mkdir(parents=True, exist_ok=True)
        env["DAKSH_REPORTS_DIR"] = str(ROOT_DIR / "reports")
        env["DAKSH_RUNTIME_DIR"] = str(run_runtime)
        env["DAKSH_PROJECT_ID"] = str(project_key or "default")
        env["DAKSH_RUN_ID"] = str(run_uuid)
        # Checkpoint config may otherwise resolve to the shared runtime path.
        # Force every Web UI run (including system-default mode) to its own file.
        cmd = [*cmd, '--state-file', str(run_runtime / 'scan_state.json')]

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
