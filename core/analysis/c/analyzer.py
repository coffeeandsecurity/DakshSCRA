# Standard libraries
from pathlib import Path

import state.runtime_state as state
from core.analysis.common import get_platform_patterns
from core.analysis.interfile import analyze_multifile_flows
from core.analysis.report import write_reports


CFG = get_platform_patterns("c")


def analyze_c_flows(source_root: Path):
    return analyze_multifile_flows(source_root, CFG, platform="c")


def run(source_root: Path):
    flows = analyze_c_flows(source_root)
    out_dir = Path(state.reports_dirpath) / "analysis/c"
    return write_reports(flows, out_dir, title="C Dataflow Analysis", platform="c")
