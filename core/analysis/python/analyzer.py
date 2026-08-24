# Standard libraries
from pathlib import Path

import state.runtime_state as state
from core.analysis.common import get_platform_patterns
from core.analysis.interfile import analyze_multifile_flows
from core.analysis.report import write_reports


CFG = get_platform_patterns("python")


def analyze_python_flows(source_root: Path, progress_callback=None):
    return analyze_multifile_flows(source_root, CFG, platform="python", progress_callback=progress_callback)


def run(source_root: Path, progress_callback=None):
    flows = analyze_python_flows(source_root, progress_callback=progress_callback)
    out_dir = Path(state.reports_dirpath) / "analysis/python"
    return write_reports(flows, out_dir, title="Python Dataflow Analysis", platform="python")
