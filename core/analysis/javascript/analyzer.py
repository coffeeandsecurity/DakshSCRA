# Standard libraries
from pathlib import Path

import state.runtime_state as state
from core.analysis.common import get_platform_patterns
from core.analysis.interfile import analyze_multifile_flows
from core.analysis.report import write_reports


CFG = get_platform_patterns("javascript")


def analyze_js_flows(source_root: Path, progress_callback=None):
    return analyze_multifile_flows(source_root, CFG, platform="javascript", progress_callback=progress_callback)


def run(source_root: Path, progress_callback=None):
    flows = analyze_js_flows(source_root, progress_callback=progress_callback)
    out_dir = Path(state.reports_dirpath) / "analysis/javascript"
    return write_reports(flows, out_dir, title="JavaScript Dataflow Analysis", platform="javascript")
