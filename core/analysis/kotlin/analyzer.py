# Standard libraries
from pathlib import Path

import state.runtime_state as state
from core.analysis.common import get_platform_patterns
from core.analysis.interfile import analyze_multifile_flows
from core.analysis.report import write_reports


CFG = get_platform_patterns("kotlin")


def analyze_kotlin_flows(source_root: Path, progress_callback=None):
    return analyze_multifile_flows(source_root, CFG, platform="kotlin", progress_callback=progress_callback)


def run(source_root: Path, progress_callback=None):
    flows = analyze_kotlin_flows(source_root, progress_callback=progress_callback)
    out_dir = Path(state.reports_dirpath) / "analysis/kotlin"
    return write_reports(flows, out_dir, title="Kotlin Dataflow Analysis", platform="kotlin")
