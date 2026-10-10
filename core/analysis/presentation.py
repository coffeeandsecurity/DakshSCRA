"""Shared analysis payload used by the web UI and standalone CLI reports."""

def normalize_confidence_score(value, default=50):
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        score = default
    return max(0, min(100, score))


def confidence_label(score):
    if score >= 80:
        return "High"
    if score >= 60:
        return "Medium"
    return "Low"



def flow_finding(flow):
    score = normalize_confidence_score(flow.get("risk_score"), default=55)
    path_steps = flow.get("path", []) if isinstance(flow.get("path", []), list) else []
    source_step = next((step for step in path_steps if str(step.get("role", "")).lower() == "source"), None)
    sink_step = next((step for step in reversed(path_steps) if str(step.get("role", "")).lower() == "sink"), None)
    source_loc = "-"
    sink_loc = "-"
    if isinstance(source_step, dict):
        source_loc = f"{source_step.get('file', '-')}" + (f":{source_step.get('line')}" if source_step.get("line") not in (None, "") else "")
    if isinstance(sink_step, dict):
        sink_loc = f"{sink_step.get('file', '-')}" + (f":{sink_step.get('line')}" if sink_step.get("line") not in (None, "") else "")
    trace_chain = [
        f"{str(step.get('role', 'step')).lower()}:{step.get('file', '-')}" + (f":{step.get('line')}" if step.get("line") not in (None, "") else "")
        for step in path_steps[:8]
        if isinstance(step, dict)
    ]
    return {
        "id": f"FLOW-{flow.get('rank', '')}",
        "title": str(flow.get("sink", "")).strip() or "Sensitive sink flow",
        "description": str(flow.get("description", "")).strip(),
        "analysis_kind": "taint_flow",
        "source": source_loc,
        "sink": sink_loc,
        "trace_chain": trace_chain,
        "path": path_steps,
        "xref": flow.get("xref", []) if isinstance(flow.get("xref", []), list) else [],
        "input_surface": flow.get("input_surface", {}) if isinstance(flow.get("input_surface", {}), dict) else {},
        "attack_vectors": flow.get("attack_vectors", []) if isinstance(flow.get("attack_vectors", []), list) else [],
        "file": str(flow.get("file", "")).strip(),
        "function": str(flow.get("function", "")).strip(),
        "line": flow.get("line"),
        "source_file": source_step.get("file", "") if isinstance(source_step, dict) else "",
        "source_line": source_step.get("line") if isinstance(source_step, dict) else "",
        "sink_file": sink_step.get("file", "") if isinstance(sink_step, dict) else "",
        "sink_line": sink_step.get("line") if isinstance(sink_step, dict) else "",
        "termination_nodes": flow.get("termination_nodes", []) if isinstance(flow.get("termination_nodes", []), list) else [],
        "cross_file": bool(flow.get("cross_file", False)),
        "risk_score": flow.get("risk_score"),
        "severity": str(flow.get("severity", "")).strip(),
        "confidence_score": score,
        "confidence_label": confidence_label(score),
        "source_count": len(path_steps),
    }
