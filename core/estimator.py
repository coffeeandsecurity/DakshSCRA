"""Generate effort plans from completed scan evidence, not file-count bands."""
import json
from pathlib import Path

import state.runtime_state as state
import utils.file_utils as futils


def effort_estimator(json_file_path=None, *, mode='assisted', domains=None, calibration=(), assumptions=None):
    # Recon alone cannot estimate finding and suppression review work.
    from core.effort import workload_from_run, estimate_workload, load_assumptions
    workload = workload_from_run(Path(state.reports_dirpath) / 'data', state.runtime_dirpath,
                                 target=str(state.sourcedir), complete=True)
    rates = dict(load_assumptions(state.estimateConfig), **(assumptions or {}))
    report = estimate_workload(workload, mode, domains, rates, calibration)
    generate_report(report)
    return report


def generate_report(report_data):
    from utils.output_mode import web_scan
    destination = Path(state.reports_dirpath) / 'data' / 'estimation.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report_data, indent=2), encoding='utf-8')
    if web_scan():
        return
    if report_data.get('schema_version') == 2:
        from core.effort import render_estimate
        rendered = render_estimate(report_data)
    else:
        # Retain rendering compatibility for historical estimate payloads.
        from jinja2 import Environment, select_autoescape
        rendered = Environment(autoescape=select_autoescape(default=True)).from_string(
            Path(state.estimation_template).read_text()).render(**report_data)
    destination = Path(state.estimation_Fpath)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered, encoding='utf-8')
    print('     [-] Effort estimation report: ' + str(futils.get_reports_root_path(destination)))
