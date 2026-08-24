import json
import os
import shutil
from datetime import datetime
from pathlib import Path

import state.runtime_state as runtime
from utils.log_utils import get_logger

logger = get_logger(__name__)

MAX_TRACE_LINES_PER_AREA = 50000

_trace_line_counts: dict = {}
_trace_truncated_areas: set = set()


def _trace_enabled() -> bool:
    raw = str(os.environ.get("DAKSH_DECISION_TRACE", "1")).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _trace_dir() -> Path:
    base = Path(runtime.runtime_dirpath) / "diagnostics"
    if runtime.project_id and runtime.run_id:
        # Web UI runs already isolate runtime_dirpath per run via
        # DAKSH_RUNTIME_DIR; plain CLI runs share one fixed runtime_dirpath
        # (see runtime_state.py), so nest by project/run id here too - a
        # no-op for the already-isolated case, real isolation for the CLI.
        base = base / runtime.project_id / runtime.run_id
    return base


def append_trace(area: str, payload: dict) -> None:
    if not _trace_enabled():
        return
    if not area or not isinstance(payload, dict):
        return

    line_count = _trace_line_counts.get(area, 0)
    if line_count >= MAX_TRACE_LINES_PER_AREA:
        if area not in _trace_truncated_areas:
            _trace_truncated_areas.add(area)
            logger.warning("Diagnostics trace '%s' truncated after %d lines.", area, MAX_TRACE_LINES_PER_AREA)
        return

    out_dir = _trace_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{area}.jsonl"
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "area": area,
        **payload,
    }
    try:
        with out_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        _trace_line_counts[area] = line_count + 1
    except OSError as exc:
        logger.error("Failed to append diagnostics trace %s: %s", out_file, exc)


def cleanup_trace_dir() -> None:
    """Remove this run's diagnostics trace directory once it has no more readers.

    The web UI cleans up its own runs via scan_runtime.cleanup_run_runtime;
    this is the equivalent for a plain (non-web-UI) CLI run, which otherwise
    never gets swept.
    """
    shutil.rmtree(_trace_dir(), ignore_errors=True)
