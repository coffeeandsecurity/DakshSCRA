"""Standalone analysis documents using the established report templates."""
from pathlib import Path
from .presentation import flow_finding


def render_analysis(flows, output_path, title='Advanced Analysis', section='summary', platform=None):
    analysis = {'results': [{'target': platform or Path(output_path).parent.name,
                            'engine': 'dataflow_controlflow',
                            'findings': [flow_finding(flow) for flow in flows]}]}
    return render_analysis_payload(analysis, output_path, title, section)


def render_analysis_payload(analysis, output_path, title='Advanced Analysis', section='summary'):
    from core.report_document import render_document
    return render_document({'report': 'Advanced analysis', 'sections': {'analysis': analysis}}, output_path, title=title)
