# Standard libraries
import json
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict, Tuple

import yaml

import state.runtime_state as state
from core.analysis.common import load_analysis_config


DEFAULT_RANKING = {
    "base_score": 35,
    "bucket_scores": {
        "critical": 40,
        "high": 28,
        "medium": 16,
        "low": 8,
    },
    "keywords": {
        "critical": ["eval", "exec", "runtime.exec", "process.start", "scriptengine", "command execution", "dynamic code"],
        "high": ["sql", "query", "xss", "innerhtml", "outerhtml", "document.write", "template"],
        "medium": ["httpclient", "openconnection", "webrequest", "file write", "deserialize", "pickle"],
    },
    "bonuses": {
        "cross_file": 15,
        "source_role": 8,
        "call_role": 5,
        "path_step_multiplier": 2,
        "path_step_cap": 5,
    },
    "severity_thresholds": {
        "critical": 85,
        "high": 70,
        "medium": 50,
    },
}

_THEME_CACHE = None


def _merge_dict(base: Dict, override: Dict) -> Dict:
    merged = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_ranking_profile(platform: str = None) -> Dict:
    cfg = load_analysis_config() or {}
    ranking_cfg = cfg.get("ranking", {}) if isinstance(cfg, dict) else {}
    profile = _merge_dict(DEFAULT_RANKING, ranking_cfg)
    overrides = ranking_cfg.get("platform_overrides", {}) if isinstance(ranking_cfg, dict) else {}
    if platform and isinstance(overrides, dict):
        plat_cfg = overrides.get(str(platform).lower(), {})
        if isinstance(plat_cfg, dict):
            profile = _merge_dict(profile, plat_cfg)
    return profile


def _get_report_theme() -> str:
    global _THEME_CACHE
    if _THEME_CACHE:
        return _THEME_CACHE
    theme = "hacker_mode"
    try:
        cfg_path = Path(state.toolConfig)
        if cfg_path.exists():
            data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            analysis_cfg = data.get("analysis", {}) if isinstance(data, dict) else {}
            if isinstance(analysis_cfg, dict):
                candidate = str(analysis_cfg.get("report_theme", "hacker_mode")).strip().lower()
                if candidate in {"hacker_mode", "professional_mode", "both"}:
                    theme = candidate
    except Exception:
        theme = "hacker_mode"
    _THEME_CACHE = theme
    return theme


def _flow_key(flow: Dict) -> Tuple:
    path_key = tuple(
        (step.get("file"), step.get("line"), step.get("role"), (step.get("code") or "").strip())
        for step in flow.get("path", [])
    )
    termination_key = tuple(
        (
            node.get("file"),
            node.get("line"),
            node.get("reason"),
            (node.get("code") or "").strip(),
        )
        for node in flow.get("termination_nodes", [])
    )
    return (
        flow.get("flow_kind", "sink"),
        flow.get("trace_status", "complete"),
        flow.get("sink"),
        flow.get("file"),
        flow.get("function"),
        flow.get("line"),
        path_key,
        termination_key,
    )


def _escape_html(text: str) -> str:
    return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _trace_status(flow: Dict) -> str:
    status = str(flow.get("trace_status", "")).strip().lower()
    return status if status in {"complete", "partial"} else "complete"


def _termination_summary(flow: Dict) -> List[str]:
    lines: List[str] = []
    for node in flow.get("termination_nodes", []) or []:
        reason = str(node.get("reason", "unresolved")).replace("_", " ")
        location = f"{node.get('file', '-')}" + (f":{node.get('line')}" if node.get("line") else "")
        symbol = str(node.get("symbol", "")).strip()
        text = f"{reason} at {location}"
        if symbol:
            text += f" via {symbol}"
        lines.append(text)
    return lines


def _ensure_source_step(flow: Dict) -> Dict:
    normalized = dict(flow)
    path = list(normalized.get("path", []) or [])
    if any(str(step.get("role", "")).lower() == "source" for step in path):
        normalized["path"] = path
        return normalized

    if path:
        first = path[0]
        inferred_code = "[inferred] Upstream tainted input reaches this flow boundary."
        if str(first.get("role", "")).lower() == "param":
            inferred_code = f"[inferred] Upstream tainted input reaches parameter `{first.get('code', 'param')}`."
        inferred_source = {
            "file": first.get("file", normalized.get("file", "")),
            "line": first.get("line", normalized.get("line", "")),
            "role": "source",
            "code": inferred_code,
        }
    else:
        inferred_source = {
            "file": normalized.get("file", ""),
            "line": normalized.get("line", ""),
            "role": "source",
            "code": "[inferred] Source could not be resolved statically; review upstream call chain.",
        }

    normalized["path"] = [inferred_source] + path
    return normalized


def _compute_risk(flow: Dict, profile: Dict) -> Tuple[int, bool]:
    sink = str(flow.get("sink", "")).lower()
    desc = str(flow.get("description", "")).lower()
    explanation = str(flow.get("explanation", "")).lower()
    text = f"{sink} {desc} {explanation}"

    bucket_scores = profile.get("bucket_scores", {})
    keywords = profile.get("keywords", {})
    bonuses = profile.get("bonuses", {})

    score = int(profile.get("base_score", 35))
    critical_words = [str(x).lower() for x in keywords.get("critical", [])]
    high_words = [str(x).lower() for x in keywords.get("high", [])]
    medium_words = [str(x).lower() for x in keywords.get("medium", [])]

    if any(h in text for h in critical_words):
        score += int(bucket_scores.get("critical", 40))
    elif any(h in text for h in high_words):
        score += int(bucket_scores.get("high", 28))
    elif any(h in text for h in medium_words):
        score += int(bucket_scores.get("medium", 16))
    else:
        score += int(bucket_scores.get("low", 8))

    path = flow.get("path", []) or []
    files = {step.get("file") for step in path if step.get("file")}
    cross_file = len(files) > 1
    if cross_file:
        score += int(bonuses.get("cross_file", 15))

    roles = {step.get("role") for step in path}
    if "source" in roles:
        score += int(bonuses.get("source_role", 8))
    if "call" in roles:
        score += int(bonuses.get("call_role", 5))

    step_cap = int(bonuses.get("path_step_cap", 5))
    step_mul = int(bonuses.get("path_step_multiplier", 2))
    score += min(len(path), step_cap) * step_mul
    return min(score, 100), cross_file


def _severity_from_score(score: int, profile: Dict) -> str:
    thresholds = profile.get("severity_thresholds", {})
    critical_t = int(thresholds.get("critical", 85))
    high_t = int(thresholds.get("high", 70))
    medium_t = int(thresholds.get("medium", 50))

    if score >= critical_t:
        return "Critical"
    if score >= high_t:
        return "High"
    if score >= medium_t:
        return "Medium"
    return "Low"


def rank_and_dedupe_flows(flows: List[Dict], platform: str = None) -> List[Dict]:
    best_by_key: Dict[Tuple, Dict] = {}
    profile = _load_ranking_profile(platform=platform)

    for flow in flows:
        if not isinstance(flow, dict):
            continue
        normalized = _ensure_source_step(flow)
        score, cross_file = _compute_risk(normalized, profile)
        normalized["risk_score"] = score
        normalized["cross_file"] = cross_file
        normalized["severity"] = _severity_from_score(score, profile)
        key = _flow_key(normalized)
        prev = best_by_key.get(key)
        if prev is None or normalized["risk_score"] > prev["risk_score"]:
            best_by_key[key] = normalized

    _CONFIDENCE_ORDER = {"high": 2, "medium": 1, "low": 0}
    ranked = sorted(
        best_by_key.values(),
        key=lambda f: (
            -int(f.get("risk_score", 0)),
            -_CONFIDENCE_ORDER.get(str(f.get("confidence", "low")).lower(), 0),
            -int(bool(f.get("cross_file", False))),
            -len(f.get("path", []) or []),
            str(f.get("file", "")),
            int(f.get("line", 0) or 0),
        ),
    )

    for idx, flow in enumerate(ranked, start=1):
        flow["rank"] = idx
    return ranked


def render_html(flows: List[Dict], output_path: Path, title: str = "Dataflow Analysis"):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    attack_summary = _attack_surface_summary(flows)
    complete_count = sum(1 for flow in flows if _trace_status(flow) == "complete")
    partial_count = sum(1 for flow in flows if _trace_status(flow) == "partial")

    lines = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>{}</title>".format(title),
        "<style>",
        "body{font-family:Segoe UI,Arial,sans-serif;background:#0b1120;color:#e2e8f0;padding:24px;}",
        ".summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0;}",
        ".summary-card{background:#0f172a;border:1px solid #1f2937;border-radius:12px;padding:14px;}",
        ".summary-k{font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;}",
        ".summary-v{font-size:26px;font-weight:700;margin-top:6px;color:#93c5fd;}",
        ".section-card{background:#0f172a;border:1px solid #1f2937;border-radius:12px;padding:16px;margin:16px 0;}",
        "table{border-collapse:separate;border-spacing:0 8px;width:100%;margin-top:12px;}",
        "th{background:#0f172a;text-align:left;font-size:12px;letter-spacing:0.05em;color:#94a3b8;padding:8px 10px;}",
        "td{background:#0f172a;border:1px solid #1f2937;padding:12px 10px;font-size:14px;vertical-align:top;border-radius:10px;}",
        ".badge{display:inline-block;padding:6px 10px;border-radius:10px;background:#1d4ed8;color:#e2e8f0;font-size:12px;font-weight:700;}",
        ".muted{color:#94a3b8;}",
        ".path-step{margin-top:6px;padding:10px;border:1px solid #1f2937;border-radius:10px;background:#0d1628;font-size:13px;box-shadow:0 10px 30px rgba(0,0,0,0.35);}",
        ".path-step.source{border-color:#22c55e;background:linear-gradient(135deg,rgba(34,197,94,0.16),rgba(34,197,94,0.08));}",
        ".path-step.assign{border-color:#38bdf8;background:linear-gradient(135deg,rgba(56,189,248,0.16),rgba(56,189,248,0.08));}",
        ".path-step.param{border-color:#60a5fa;background:linear-gradient(135deg,rgba(96,165,250,0.18),rgba(96,165,250,0.08));}",
        ".path-step.call{border-color:#a78bfa;background:linear-gradient(135deg,rgba(167,139,250,0.18),rgba(167,139,250,0.08));}",
        ".path-step.sink{border-color:#f97316;background:linear-gradient(135deg,rgba(249,115,22,0.18),rgba(249,115,22,0.08));}",
        ".path-step.termination{border-color:#facc15;background:linear-gradient(135deg,rgba(250,204,21,0.18),rgba(250,204,21,0.08));}",
        ".code-block{margin-top:6px;padding:10px;border-radius:8px;background:#0b1220;font-family:SFMono-Regular,Consolas,monospace;white-space:pre-wrap;line-height:1.5;border:1px solid #1f2937;}",
        ".flow-chain{margin-top:8px;padding:10px;border-radius:8px;background:#0b1220;border:1px dashed #334155;font-family:SFMono-Regular,Consolas,monospace;font-size:12px;line-height:1.4;}",
        ".sev{display:inline-block;padding:3px 8px;border-radius:8px;font-size:11px;font-weight:700;margin-right:6px;}",
        ".sev-critical{background:#7f1d1d;color:#fecaca;border:1px solid #dc2626;}",
        ".sev-high{background:#7c2d12;color:#fed7aa;border:1px solid #f97316;}",
        ".sev-medium{background:#1e3a8a;color:#bfdbfe;border:1px solid #3b82f6;}",
        ".sev-low{background:#065f46;color:#a7f3d0;border:1px solid #10b981;}",
        ".trace-complete{background:#065f46;color:#d1fae5;border:1px solid #10b981;}",
        ".trace-partial{background:#78350f;color:#fef3c7;border:1px solid #f59e0b;}",
        ".conf-high{background:#4c1d95;color:#ddd6fe;border:1px solid #7c3aed;}",
        ".conf-medium{background:#1e3a5f;color:#bae6fd;border:1px solid #0ea5e9;}",
        ".conf-low{background:#374151;color:#d1d5db;border:1px solid #6b7280;}",
        ".xref-link{display:inline-block;margin-top:8px;padding:6px 10px;border-radius:8px;background:#0f172a;border:1px solid #334155;color:#93c5fd;text-decoration:none;font-size:12px;}",
        "</style>",
        "</head><body>",
        f"<h2>{title} (experimental)</h2>",
        "<p class='muted'>This report lists complete source-to-sink traces and partial trace terminations."
        " XREF details are moved to a separate report for readability.</p>",
        "<div class='summary-grid'>",
        f"<div class='summary-card'><div class='summary-k'>Analyzer Flows</div><div class='summary-v'>{len(flows)}</div></div>",
        f"<div class='summary-card'><div class='summary-k'>Complete Traces</div><div class='summary-v'>{complete_count}</div></div>",
        f"<div class='summary-card'><div class='summary-k'>Partial Traces</div><div class='summary-v'>{partial_count}</div></div>",
        f"<div class='summary-card'><div class='summary-k'>Attack Vectors</div><div class='summary-v'>{len(attack_summary)}</div></div>",
        "</div>",
        "<div class='section-card'><h3>Attack Vector Summary</h3>",
        "<p class='muted'>Attack vectors are tracked separately from trace completeness.</p>",
        "<table>",
        "<tr><th>Vector</th><th>Count</th><th>Example</th></tr>",
    ]

    if attack_summary:
        for row in attack_summary:
            lines.append(
                f"<tr><td>{_escape_html(row.get('label', row.get('kind', 'vector')))}</td>"
                f"<td>{int(row.get('count', 0) or 0)}</td>"
                f"<td>{_escape_html(row.get('example', ''))}</td></tr>"
            )
    else:
        lines.append("<tr><td colspan='3' class='muted'>No attack vectors inferred</td></tr>")

    lines.extend(
        [
            "</table></div>",
            "<table>",
            "<tr><th>#</th><th>File</th><th>Function</th><th>Line</th><th>End Node</th><th>Description</th><th>Attack Surface</th><th>Flow Trace</th><th>XREF</th></tr>",
        ]
    )

    if not flows:
        lines.append("<tr><td colspan='9' class='muted'>No flows detected.</td></tr>")
    else:
        for flow in flows:
            input_surface = flow.get("input_surface") or _infer_input_surface(flow)
            flow["input_surface"] = input_surface
            attack_vectors = flow.get("attack_vectors") or _derive_attack_vectors(flow)
            flow["attack_vectors"] = attack_vectors
            trace_status = _trace_status(flow)
            termination_lines = _termination_summary(flow)
            path_parts = []
            arrow_chain = []
            for step in flow.get("path", []):
                label = step.get("role", "step").capitalize()
                code_raw = step.get("code", "").rstrip()
                code = _escape_html(code_raw)
                role_class = step.get("role", "step")
                step_loc = f"{_escape_html(step.get('file'))}:{_escape_html(step.get('line'))}"
                arrow_chain.append(f"{_escape_html(label)}@{step_loc}")
                path_parts.append(
                    f"<div class='path-step {role_class}'><span class='badge'>{label}</span> "
                    f"<span class='muted'>({step_loc})</span>"
                    f"<div class='code-block'>{code}</div></div>"
                )
            for node in flow.get("termination_nodes", [])[:4]:
                label = f"Termination: {str(node.get('reason', 'unresolved')).replace('_', ' ')}"
                code = _escape_html(str(node.get("code", "")).rstrip())
                step_loc = f"{_escape_html(node.get('file'))}:{_escape_html(node.get('line'))}"
                path_parts.append(
                    f"<div class='path-step termination'><span class='badge'>{_escape_html(label)}</span> "
                    f"<span class='muted'>({step_loc})</span>"
                    f"<div class='code-block'>{code}</div></div>"
                )
            flow_chain_html = f"<div class='flow-chain'>{' &rarr; '.join(arrow_chain)}</div>" if arrow_chain else ""
            path_html = "".join(path_parts) if path_parts else "<span class='muted'>No path details</span>"
            explanation = flow.get("explanation", "")
            description = flow.get("description", "")
            severity = str(flow.get("severity", "Low"))
            sev_class = {
                "Critical": "sev-critical",
                "High": "sev-high",
                "Medium": "sev-medium",
                "Low": "sev-low",
            }.get(severity, "sev-low")
            confidence = str(flow.get("confidence", "low")).lower()
            conf_class = {"high": "conf-high", "medium": "conf-medium"}.get(confidence, "conf-low")
            desc_html = (
                f"<div><span class='sev {sev_class}'>{severity}</span>"
                f"<span class='sev trace-{trace_status}'>{trace_status.capitalize()}</span>"
                f"<span class='sev {conf_class}'>Confidence: {confidence.capitalize()}</span>"
                f"<strong>Score:</strong> {flow.get('risk_score', 0)}</div>"
                f"<div style='margin-top:6px;'>{_escape_html(description)}</div>"
                + (f"<div class='muted' style='margin-top:6px;'><strong>Why this matters:</strong> {_escape_html(explanation)}</div>" if explanation else "")
                + (f"<div class='muted' style='margin-top:6px;'><strong>Termination:</strong> {_escape_html(' | '.join(termination_lines))}</div>" if termination_lines else "")
            )
            attack_html = "".join(
                f"<div class='path-step'><strong>{_escape_html(vector.get('label','vector'))}</strong>"
                f"<div class='muted' style='margin-top:4px;'>{_escape_html(vector.get('reason',''))}</div>"
                f"<div class='code-block'>{_escape_html(' | '.join(vector.get('examples', [])[:2]))}</div></div>"
                for vector in attack_vectors[:3]
            ) or "<span class='muted'>No attack surface details</span>"
            xref_link = f"analysis_xref.html#flow-{flow.get('rank', '')}"
            end_node = _escape_html(flow.get("sink", "") or "trace termination")
            if termination_lines:
                end_node = _escape_html(termination_lines[0])
            lines.append(
                f"<tr>"
                f"<td>{flow.get('rank','')}</td>"
                f"<td>{_escape_html(flow.get('file',''))}</td>"
                f"<td>{_escape_html(flow.get('function',''))}</td>"
                f"<td>{flow.get('line','')}</td>"
                f"<td><span class='badge'>{end_node}</span></td>"
                f"<td>{desc_html}</td>"
                f"<td>{attack_html}</td>"
                f"<td>{flow_chain_html}{path_html}</td>"
                f"<td><a class='xref-link' href='{xref_link}'>Open XREF</a></td>"
                f"</tr>"
            )
    lines.append("</table></body></html>")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def _inject_modern_style(html_text: str, variant: str = "main", theme: str = "hacker_mode") -> str:
    if "</head>" not in html_text:
        return html_text

    if theme == "professional_mode":
        base_style = [
            "<style id='analysis-modern-override'>",
            ":root{--bg:#f4f8fc;--panel:#ffffff;--line:#c8d7ea;--text:#102a43;--muted:#486581;--accent:#0f4a8a;--accent-soft:#e7f0fb;--graph-bg:#0b1322;}",
            "body{background:var(--bg) !important;color:var(--text) !important;font-family:Segoe UI,Arial,sans-serif !important;line-height:1.45 !important;}",
            "h1,h2,h3,h4,h5,h6,.h1,.meta,.k,.v,summary.head,td,th,.panel,.mcard,.sec,.quick,.chip,.badge,.lg{color:var(--text) !important;}",
            "table{border-collapse:separate !important;border-spacing:0 8px !important;}",
            "th{background:#eaf1f9 !important;color:#243b53 !important;border:1px solid var(--line) !important;font-weight:700 !important;}",
            "td{background:var(--panel) !important;color:var(--text) !important;border:1px solid var(--line) !important;}",
            ".muted{color:var(--muted) !important;}",
            ".badge{background:var(--accent-soft) !important;color:var(--accent) !important;border:1px solid #a7c5e6 !important;font-weight:700 !important;}",
            ".chip,.file-pill,.lg{background:#edf4fd !important;color:#153e75 !important;border:1px solid #a7c5e6 !important;}",
            ".panel,.mcard,.sec,details.card,.path-step{background:var(--panel) !important;border:1px solid var(--line) !important;box-shadow:none !important;}",
            ".code-block,.code{background:#f0f6fd !important;color:#102a43 !important;border:1px solid #bfd1e5 !important;}",
            ".xref-link,.back,.quick{background:#edf4fd !important;color:#0f4a8a !important;border:1px solid #a7c5e6 !important;font-weight:600 !important;}",
            ".flow-chain,.graph-note{background:#f0f6fd !important;border:1px solid #bfd1e5 !important;color:#243b53 !important;}",
            ".graph{background:var(--graph-bg) !important;border:1px solid #324d69 !important;}",
            ".graph svg text{fill:#e6edf7 !important;font-weight:600 !important;}",
            ".graph svg path,.graph svg line,.graph svg polyline{stroke-width:2 !important;stroke-opacity:1 !important;}",
            ".graph svg rect{stroke-width:1.6 !important;}",
            ".search{color:var(--text) !important;-webkit-text-fill-color:var(--text) !important;}",
            "</style>",
        ]
    else:
        # Hacker mode (default): dark high-contrast theme tuned for flow tracing.
        base_style = [
            "<style id='analysis-modern-override'>",
            ":root{--bg:#060b14;--panel:#0a1322;--line:#1b3554;--text:#e6f1ff;--muted:#9db3cc;--accent:#36c2ff;--accent-soft:#0f2742;}",
            "body{background:radial-gradient(circle at 20% 0%,#0a1a30 0%,#060b14 55%) !important;color:var(--text) !important;font-family:Segoe UI,Arial,sans-serif !important;line-height:1.45 !important;}",
            "h1,h2,h3,h4,h5,h6,.h1,.meta,.k,.v,summary.head,td,th,.panel,.mcard,.sec,.quick,.chip,.badge,.lg{color:var(--text) !important;}",
            "table{border-collapse:separate !important;border-spacing:0 8px !important;}",
            "th{background:#0d1a2d !important;color:#b8d9ff !important;border:1px solid var(--line) !important;font-weight:700 !important;}",
            "td{background:var(--panel) !important;color:var(--text) !important;border:1px solid var(--line) !important;}",
            ".muted{color:var(--muted) !important;}",
            ".badge{background:var(--accent-soft) !important;color:#8adfff !important;border:1px solid #1f5f8a !important;font-weight:700 !important;}",
            ".chip,.file-pill,.lg{background:#0e2036 !important;color:#8adfff !important;border:1px solid #1f5f8a !important;}",
            ".panel,.mcard,.sec,details.card,.path-step{background:var(--panel) !important;border:1px solid var(--line) !important;box-shadow:0 0 0 1px rgba(15,65,111,0.25) inset !important;}",
            ".code-block,.code{background:#071224 !important;color:#c7e6ff !important;border:1px solid #214467 !important;}",
            ".xref-link,.back,.quick{background:#0f2742 !important;color:#7fd8ff !important;border:1px solid #2a6897 !important;font-weight:600 !important;}",
            ".flow-chain,.graph-note{background:#081728 !important;border:1px solid #244a6f !important;color:#c1dffb !important;}",
            ".graph{background:#040a13 !important;border:1px solid #31587f !important;}",
            ".graph svg text{fill:#ecf6ff !important;font-weight:700 !important;}",
            ".graph svg path,.graph svg line,.graph svg polyline{stroke-width:2.2 !important;stroke-opacity:1 !important;}",
            ".graph svg rect{stroke-width:1.8 !important;}",
            ".search{color:var(--text) !important;-webkit-text-fill-color:var(--text) !important;background:#081728 !important;border:1px solid #2a6897 !important;}",
            "</style>",
        ]

    if variant == "xref":
        base_style.extend(
            [
                "<style id='analysis-modern-override-xref'>",
                ".layout{grid-template-columns:280px 1fr !important;}",
                ".side{background:" + ("#eaf1f9" if theme == "professional_mode" else "#081120") + " !important;border-right:1px solid " + ("#c3d4e8" if theme == "professional_mode" else "#1f4569") + " !important;}",
                ".legend .lg{background:" + ("#edf4fd" if theme == "professional_mode" else "#0e2036") + " !important;border-color:" + ("#a7c5e6" if theme == "professional_mode" else "#1f5f8a") + " !important;color:" + ("#243b53" if theme == "professional_mode" else "#9fdfff") + " !important;}",
                "</style>",
            ]
        )

    injected = "\n".join(base_style)
    return html_text.replace("</head>", injected + "\n</head>", 1)


def render_html_modern(flows: List[Dict], output_path: Path, title: str = "Dataflow Analysis", theme: str = "hacker_mode"):
    temp_path = output_path.parent / f"{output_path.stem}.legacy.tmp"
    render_html(flows, temp_path, title=title)
    html_text = temp_path.read_text(encoding="utf-8")
    modern_text = _inject_modern_style(html_text, variant="main", theme=theme)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(modern_text, encoding="utf-8")
    try:
        temp_path.unlink()
    except OSError:
        pass
    return output_path


TOKEN_RE = re.compile(r"[$@]?[A-Za-z_][A-Za-z0-9_]{2,}")
CALL_NAME_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*(?:(?:->|::|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(")
HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b", re.IGNORECASE)
URI_LITERAL_RE = re.compile(r"""["'](/[^"'?#\s]{1,180}(?:\?[^"'\s]{0,120})?)["']""")
REQ_PARAM_RE = re.compile(
    r"""(?:@RequestParam\s*\(\s*["']([A-Za-z0-9_.$-]+)["']|getParameter\s*\(\s*["']([A-Za-z0-9_.$-]+)["']|(?:query|body|params)\.([A-Za-z_][A-Za-z0-9_]*))""",
    re.IGNORECASE,
)
NOISE_TOKENS = {
    "this", "self", "true", "false", "null", "none", "undefined", "class", "public",
    "private", "protected", "static", "return", "const", "let", "var", "function",
    "string", "int", "bool", "void", "object", "array", "dict", "list", "json",
}

LOCAL_FILE_RE = re.compile(r"\b(open|read(all|text|bytes)?|file|getcontentas|string|readfile|fopen|ifstream|filereader|multipartfile|iformfile|upload(edfile)?)\b", re.IGNORECASE)
ENDPOINT_RE = re.compile(r"\b(@RequestMapping|@GetMapping|@PostMapping|router\.(get|post|put|patch|delete)|Map(Get|Post|Put|Patch|Delete)|Route\(|endpoint|restcontroller|controllerbase)\b", re.IGNORECASE)
ENV_INPUT_RE = re.compile(r"\b(process\.env|system\.getenv|environment\.get(environment)?variable|configurationmanager|appsettings|getproperty)\b", re.IGNORECASE)
NETWORK_INPUT_RE = re.compile(r"\b(httpclient|webrequest|webclient|resttemplate|webclient|fetch\(|axios\.|socket|websocket|recv\(|listen\(|accept\()\b", re.IGNORECASE)


def _extract_call_names(code: str) -> List[str]:
    names = []
    for m in CALL_NAME_RE.finditer(str(code or "")):
        raw = m.group(1)
        names.append(re.split(r"(?:->|::|\.)", raw)[-1].lstrip("$").lower())
    return names


def _extract_security_tokens(text: str) -> List[str]:
    tokens = []
    for token in TOKEN_RE.findall(str(text or "")):
        t = token.lstrip("$@").lower()
        if len(t) < 3 or t.isdigit() or t in NOISE_TOKENS:
            continue
        tokens.append(t)
    return tokens


def _flow_value_hotspots(flow: Dict, limit: int = 12) -> List[Dict]:
    counter: Counter = Counter()
    files_by_token: Dict[str, set] = {}
    roles_by_token: Dict[str, set] = {}

    for step in flow.get("path", []) or []:
        text = f"{step.get('code', '')} {step.get('role', '')}"
        for t in _extract_security_tokens(text):
            counter[t] += 1
            files_by_token.setdefault(t, set()).add(str(step.get("file", "")))
            roles_by_token.setdefault(t, set()).add(str(step.get("role", "step")))

    for x in flow.get("xref", []) or []:
        text = f"{x.get('symbol', '')} {x.get('resolved_name', '')} {x.get('context', '')}"
        for t in _extract_security_tokens(text):
            counter[t] += 1
            files_by_token.setdefault(t, set()).add(str(x.get("file", "")))
            roles_by_token.setdefault(t, set()).add(f"xref:{x.get('type', 'xref')}")

    rows = []
    for token, cnt in counter.most_common(limit):
        rows.append(
            {
                "token": token,
                "count": cnt,
                "files": sorted([f for f in files_by_token.get(token, set()) if f]),
                "roles": sorted(roles_by_token.get(token, set())),
            }
        )
    return rows


def _build_flow_graph_data(flow: Dict) -> Dict:
    path = flow.get("path", []) or []
    xref = flow.get("xref", []) or []

    nodes = []
    edges = []
    path_tokens_by_node: Dict[str, set] = {}
    call_node_by_name: Dict[str, List[str]] = {}
    path_tail = min(len(path), 5)

    for i, step in enumerate(path):
        node_id = f"p{i}"
        role = str(step.get("role", "step"))
        code = str(step.get("code", ""))
        label = role.upper()
        if role == "call":
            call_names = _extract_call_names(code)
            if call_names:
                label = f"CALL {call_names[0][:20]}".upper()
        nodes.append(
            {
                "id": node_id,
                "kind": "path",
                "role": role,
                "label": label,
                "sub": f"{Path(str(step.get('file', ''))).name}:{step.get('line', '')}",
            }
        )
        path_tokens_by_node[node_id] = set(_extract_security_tokens(code))
        if i > 0:
            edges.append({"from": f"p{i-1}", "to": node_id, "kind": "path", "label": f"step {i}"})
        if role == "call":
            for cname in _extract_call_names(code):
                call_node_by_name.setdefault(cname, []).append(node_id)

    sink_node = f"p{len(path)-1}" if path else None
    graph_nodes: List[Dict] = []
    max_per_anchor = {"callsite": 6, "definition": 4, "xref": 3}
    attached_by_anchor: Dict[str, Dict[str, int]] = {}
    related_added = 0
    related_fallback_cap = 2
    max_graph_xnodes = 18
    node_counter = 0

    def _attach_xref(node_obj: Dict, from_node: str, edge_kind: str, edge_label: str) -> bool:
        nonlocal node_counter
        role_key = str(node_obj.get("role", "xref")).lower()
        attached_by_anchor.setdefault(from_node, {})
        used = attached_by_anchor[from_node].get(role_key, 0)
        cap = max_per_anchor.get(role_key, 3)
        if used >= cap:
            return False
        if node_counter >= max_graph_xnodes:
            return False
        node_counter += 1
        graph_nodes.append(node_obj)
        edges.append({"from": from_node, "to": node_obj["id"], "kind": edge_kind, "label": edge_label})
        attached_by_anchor[from_node][role_key] = used + 1
        return True

    for i, x in enumerate(xref):
        node_id = f"x{i}"
        resolved = str(x.get("resolved_name", "")).strip()
        symbol = str(x.get("symbol", "")).strip()
        x_type = str(x.get("type", "xref")).strip() or "xref"
        x_type_l = x_type.lower()
        x_tokens = set(
            _extract_security_tokens(
                " ".join(
                    [
                        resolved,
                        symbol,
                        str(x.get("context", "")),
                    ]
                )
            )
        )
        node_obj = {
            "id": node_id,
            "kind": "xref",
            "role": x_type_l,
            "label": resolved or symbol or "xref",
            "sub": f"{Path(str(x.get('file', ''))).name}:{x.get('line', '')}",
        }
        attached = False
        anchors: List[str] = []
        if resolved:
            anchors.extend(call_node_by_name.get(resolved.lower(), []))

        # fallback token match in tail path nodes to preserve direction near sink.
        if not anchors and x_tokens and path:
            for node_id_path in [f"p{idx}" for idx in range(max(0, len(path) - path_tail), len(path))]:
                if path_tokens_by_node.get(node_id_path, set()).intersection(x_tokens):
                    anchors.append(node_id_path)
                    break

        for from_node in anchors:
            edge_kind = "xref"
            edge_label = "callsite" if x_type_l == "callsite" else ("definition" if x_type_l == "definition" else x_type_l)
            if _attach_xref(node_obj, from_node, edge_kind, edge_label):
                attached = True
                break

        if attached:
            continue

        if sink_node and related_added < related_fallback_cap:
            if _attach_xref(node_obj, sink_node, "xref_related", "related"):
                related_added += 1

    nodes.extend(graph_nodes)
    return {"nodes": nodes, "edges": edges}


def _flow_graph_narrative(flow: Dict, graph: Dict) -> str:
    path = flow.get("path", []) or []
    roles = [str(s.get("role", "step")).upper() for s in path]
    role_chain = " -> ".join(roles) if roles else "NO PATH"
    xnodes = [n for n in (graph.get("nodes", []) or []) if n.get("kind") == "xref"]
    defs = sum(1 for n in xnodes if str(n.get("role", "")).lower() == "definition")
    callsites = sum(1 for n in xnodes if str(n.get("role", "")).lower() == "callsite")
    related = sum(1 for e in (graph.get("edges", []) or []) if e.get("kind") == "xref_related")
    return (
        f"Direction: left-to-right is tainted data flow. "
        f"Trace: {role_chain}. "
        f"Graph-linked references: {len(xnodes)} (definitions: {defs}, callsites: {callsites}, related: {related}). "
        f"Use the tables below for the complete reference list."
    )


def _flow_graph_steps(graph: Dict) -> List[str]:
    nodes = {str(n.get("id")): n for n in (graph.get("nodes", []) or [])}
    edges = graph.get("edges", []) or []
    path_edges = [e for e in edges if e.get("kind") == "path"]
    xref_edges = [e for e in edges if e.get("kind") in {"xref", "xref_related"}]
    steps: List[str] = []

    def node_idx(nid: str) -> int:
        m = re.match(r"^p(\d+)$", str(nid or ""))
        return int(m.group(1)) if m else 9999

    if path_edges:
        path_edges_sorted = sorted(path_edges, key=lambda e: (node_idx(e.get("from")), node_idx(e.get("to"))))
        for e in path_edges_sorted:
            src = nodes.get(str(e.get("from", "")), {})
            dst = nodes.get(str(e.get("to", "")), {})
            steps.append(
                f"Data moves {str(src.get('label', 'STEP')).upper()} -> {str(dst.get('label', 'STEP')).upper()} "
                f"({src.get('sub', '')} -> {dst.get('sub', '')})."
            )

    # Keep descriptions concise but useful.
    for e in xref_edges[:8]:
        src = nodes.get(str(e.get("from", "")), {})
        dst = nodes.get(str(e.get("to", "")), {})
        kind = str(e.get("kind", "xref"))
        if kind == "xref_related":
            steps.append(
                f"Related reference: {dst.get('label', 'xref')} at {dst.get('sub', '')} linked near {src.get('label', 'sink')}."
            )
        else:
            steps.append(
                f"XREF {str(e.get('label', 'xref'))}: from {src.get('label', 'call')} ({src.get('sub', '')}) "
                f"to {dst.get('label', 'xref')} ({dst.get('sub', '')})."
            )
    return steps


def _infer_input_surface(flow: Dict) -> Dict:
    text_chunks: List[str] = []
    for step in flow.get("path", []) or []:
        text_chunks.append(str(step.get("code", "")))
        text_chunks.append(str(step.get("role", "")))
        text_chunks.append(str(step.get("file", "")))
    for x in flow.get("xref", []) or []:
        text_chunks.append(str(x.get("context", "")))
        text_chunks.append(str(x.get("symbol", "")))
        text_chunks.append(str(x.get("resolved_name", "")))
    text = "\n".join(text_chunks)
    text_l = text.lower()

    methods = sorted({m.upper() for m in HTTP_METHOD_RE.findall(text)})
    uris = []
    for u in URI_LITERAL_RE.findall(text):
        if u and u not in uris:
            uris.append(u)
        if len(uris) >= 4:
            break

    params = []
    for m in REQ_PARAM_RE.findall(text):
        cand = next((x for x in m if x), "")
        if cand and cand not in params:
            params.append(cand)
        if len(params) >= 6:
            break
    if not params:
        for step in flow.get("path", []) or []:
            if str(step.get("role", "")).lower() in {"param", "source"}:
                for t in _extract_security_tokens(step.get("code", "")):
                    if t not in params:
                        params.append(t)
                    if len(params) >= 6:
                        break

    channel = "code-path"
    if any(k in text_l for k in ["socket", "listen(", "accept(", "recv(", "datagram", "websocket"]):
        channel = "network-app"
    if any(k in text_l for k in ["swing", "javafx", "wpf", "winforms", "textbox", "button", "onclick", "onchange"]):
        channel = "thick-client"
    if any(k in text_l for k in ["@requestmapping", "@getmapping", "@postmapping", "httpservletrequest", "router.", "express", "restcontroller", "endpoint", "request"]):
        channel = "web-app"
    if channel == "web-app" and (any("/api/" in u.lower() for u in uris) or "restcontroller" in text_l):
        channel = "api"

    if not uris and channel in {"web-app", "api"}:
        file_stem = Path(str(flow.get("file", ""))).stem.lower().replace("controller", "") or "endpoint"
        fn = str(flow.get("function", "")).strip().lower() or "action"
        uris = [f"/{file_stem}/{fn}"]

    examples = []
    method_pick = methods[:2] if methods else (["GET", "POST"] if channel in {"web-app", "api"} else [])
    param_pick = params[:2] if params else ["input"]

    if channel in {"web-app", "api"} and uris:
        for u in uris[:2]:
            for m in method_pick:
                if m == "GET":
                    qp = "&".join([f"{p}=<PAYLOAD>" for p in param_pick])
                    examples.append(f"{m} {u}?{qp}")
                else:
                    body = ", ".join([f'"{p}":"<PAYLOAD>"' for p in param_pick])
                    examples.append(f"{m} {u}  body: {{{body}}}")
                if len(examples) >= 4:
                    break
            if len(examples) >= 4:
                break
    elif channel == "network-app":
        examples.append(f"TCP/UDP message with fields: {', '.join(param_pick)}=<PAYLOAD>")
    elif channel == "thick-client":
        examples.append(f"UI input vector: {', '.join(param_pick)}")
    else:
        examples.append(f"Code-level input vector candidates: {', '.join(param_pick)}")

    return {
        "channel": channel,
        "methods": methods[:4],
        "uris": uris[:4],
        "params": param_pick,
        "examples": examples[:4],
    }


def _derive_attack_vectors(flow: Dict) -> List[Dict]:
    vectors: List[Dict] = []
    path = flow.get("path", []) or []
    input_surface = flow.get("input_surface") or _infer_input_surface(flow)
    collected_vars: List[str] = []
    for step in path:
        for name in (step.get("variables") or []):
            token = str(name).strip()
            if token and token not in collected_vars:
                collected_vars.append(token)
        for key in ("source_symbol", "target_symbol", "symbol"):
            token = str(step.get(key, "")).strip().lstrip("$@")
            if token and token not in collected_vars:
                collected_vars.append(token)
    taint_symbols = collected_vars[:6] or ["input"]

    def add(kind: str, label: str, reason: str, examples: List[str]) -> None:
        if any(existing.get("kind") == kind for existing in vectors):
            return
        vectors.append({"kind": kind, "label": label, "reason": reason, "examples": examples[:3], "taint_symbols": taint_symbols[:4]})

    joined = "\n".join(
        [
            str(flow.get("file", "")),
            str(flow.get("function", "")),
            str(flow.get("description", "")),
            str(flow.get("explanation", "")),
        ]
        + [str(step.get("code", "")) for step in path]
    )
    joined_l = joined.lower()

    if input_surface.get("channel") in {"web-app", "api"} or ENDPOINT_RE.search(joined):
        examples = input_surface.get("examples") or []
        add(
            "endpoint",
            "Endpoint-facing input",
            "Tainted data appears reachable from request handlers, routes, or API endpoints.",
            examples or [f"{method} {uri}" for method in (input_surface.get('methods') or ['GET']) for uri in (input_surface.get('uris') or ['/endpoint'])][:3],
        )

    if any(token in joined_l for token in ["request", "query", "params", "body", "form", "cookie", "header"]):
        add(
            "user_input",
            "User-controlled request input",
            "Request parameters, body fields, headers, or cookies appear to seed the tainted flow.",
            input_surface.get("examples") or [", ".join(input_surface.get("params") or ["input"])],
        )

    if LOCAL_FILE_RE.search(joined):
        add(
            "local_file",
            "Local disk or uploaded file input",
            "The path references file reads, uploads, or local content sources that may be attacker-influenced.",
            [f"File-derived value influencing {flow.get('sink', 'sink')}", "User-controlled file name, path, or content"],
        )

    if ENV_INPUT_RE.search(joined):
        add(
            "environment",
            "Environment or configuration input",
            "Runtime configuration, environment variables, or app settings can influence the tainted path.",
            ["Environment variable override", "Configuration value influencing sensitive sink"],
        )

    if NETWORK_INPUT_RE.search(joined):
        add(
            "network",
            "Upstream service or network input",
            "Remote services, sockets, or upstream endpoints appear capable of feeding data into this flow.",
            ["Upstream API response influences local sink", "Socket/message payload influences local execution path"],
        )

    if not vectors:
        add(
            "code_path",
            "Code-path reachable input",
            "The analyzer found a tainted route to a sink, but the exact external entry point is still weakly resolved.",
            input_surface.get("examples") or ["Manual review required to confirm external entry point"],
        )

    return vectors


def _attack_surface_summary(flows: List[Dict]) -> List[Dict]:
    counts: Counter = Counter()
    examples: Dict[str, str] = {}
    for flow in flows:
        for vector in flow.get("attack_vectors", []) or []:
            kind = str(vector.get("kind", "")).strip()
            label = str(vector.get("label", kind)).strip()
            if not kind:
                continue
            counts[(kind, label)] += 1
            if kind not in examples:
                sample = (vector.get("examples") or [""])[0]
                examples[kind] = str(sample)
    return [
        {"kind": kind, "label": label, "count": count, "example": examples.get(kind, "")}
        for (kind, label), count in counts.most_common()
    ]


def render_xref_html(flows: List[Dict], output_path: Path, title: str = "Dataflow XREF"):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total_xref = sum(len(f.get("xref", []) or []) for f in flows)
    cross_file_count = sum(1 for f in flows if f.get("cross_file"))
    avg_path_len = round((sum(len(f.get("path", []) or []) for f in flows) / len(flows)), 2) if flows else 0.0
    avg_xref_per_flow = round((total_xref / len(flows)), 2) if flows else 0.0

    symbol_counter: Counter = Counter()
    file_counter: Counter = Counter()
    value_counter: Counter = Counter()
    flow_payload = []

    for flow in flows:
        xref = flow.get("xref", []) or []
        for x in xref:
            sym = str(x.get("resolved_name") or x.get("symbol") or "").strip()
            if sym:
                symbol_counter[sym] += 1
            fpath = str(x.get("file", "")).strip()
            if fpath:
                file_counter[fpath] += 1

        value_rows = _flow_value_hotspots(flow, limit=10)
        for row in value_rows:
            value_counter[row["token"]] += row["count"]
        input_surface = flow.get("input_surface") or _infer_input_surface(flow)
        flow["input_surface"] = input_surface
        flow["attack_vectors"] = flow.get("attack_vectors") or _derive_attack_vectors(flow)

        tags = " ".join(
            [
                str(flow.get("sink", "")),
                str(flow.get("file", "")),
                str(flow.get("function", "")),
                str(flow.get("severity", "")),
                str(flow.get("description", "")),
                str(flow.get("explanation", "")),
                str(input_surface.get("channel", "")),
            ]
            + [str(x.get("symbol", "")) for x in xref]
            + [str(x.get("resolved_name", "")) for x in xref]
            + [row["token"] for row in value_rows]
            + [str(v) for v in input_surface.get("methods", [])]
            + [str(v) for v in input_surface.get("uris", [])]
            + [str(v) for v in input_surface.get("params", [])]
        ).lower()

        flow_payload.append(
            {
                "rank": flow.get("rank", ""),
                "severity": flow.get("severity", "Low"),
                "trace_status": _trace_status(flow),
                "risk_score": int(flow.get("risk_score", 0) or 0),
                "sink": str(flow.get("sink", "")),
                "file": str(flow.get("file", "")),
                "function": str(flow.get("function", "")),
                "line": flow.get("line", ""),
                "path_len": len(flow.get("path", []) or []),
                "cross_file": bool(flow.get("cross_file")),
                "confidence": str(flow.get("confidence", "low")),
                "xref_count": len(xref),
                "tags": tags,
                "description": str(flow.get("description", "")),
                "explanation": str(flow.get("explanation", "")),
                "path": flow.get("path", []) or [],
                "xref": xref,
                "value_hotspots": value_rows,
                "graph": _build_flow_graph_data(flow),
                "input_surface": input_surface,
                "attack_vectors": flow.get("attack_vectors", []),
                "termination_nodes": flow.get("termination_nodes", []) or [],
            }
        )
        flow_payload[-1]["graph_narrative"] = _flow_graph_narrative(flow, flow_payload[-1]["graph"])
        flow_payload[-1]["graph_steps"] = _flow_graph_steps(flow_payload[-1]["graph"])

    top_symbols = [{"symbol": s, "count": c} for s, c in symbol_counter.most_common(12)]
    top_files = [{"file": f, "count": c} for f, c in file_counter.most_common(12)]
    top_values = [{"token": t, "count": c} for t, c in value_counter.most_common(12)]
    attack_summary = _attack_surface_summary(flows)

    lines = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>{}</title>".format(title),
        "<style>",
        "body{font-family:Segoe UI,Arial,sans-serif;background:#0b1120;color:#e2e8f0;margin:0;}",
        ".layout{display:grid;grid-template-columns:290px 1fr;min-height:100vh;}",
        ".side{position:sticky;top:0;height:100vh;overflow:auto;border-right:1px solid #1f2937;background:#0a1020;padding:16px;}",
        ".main{padding:18px 20px 40px;}",
        ".h1{font-size:22px;font-weight:700;margin:0 0 6px;}",
        ".muted{color:#94a3b8;font-size:12px;}",
        ".back{display:inline-block;margin:10px 0 14px;padding:6px 10px;border-radius:8px;background:#111827;border:1px solid #334155;color:#93c5fd;text-decoration:none;font-size:12px;}",
        ".search{width:100%;padding:10px;border-radius:9px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;}",
        ".sec{margin-top:12px;padding:10px;border:1px solid #1f2937;border-radius:10px;background:#0f172a;}",
        ".sec h4{margin:0 0 8px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;}",
        ".chips{display:flex;gap:8px;flex-wrap:wrap;}",
        ".chip{padding:6px 10px;border:1px solid #334155;border-radius:999px;background:#111827;color:#93c5fd;font-size:12px;}",
        ".quick{display:block;padding:6px 8px;border-radius:8px;color:#cbd5e1;text-decoration:none;font-size:12px;border:1px solid transparent;}",
        ".quick:hover{border-color:#334155;background:#111827;}",
        ".cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px;}",
        ".mcard{padding:12px;border-radius:12px;background:#0f172a;border:1px solid #1f2937;}",
        ".mcard .k{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;}",
        ".mcard .v{font-size:23px;font-weight:700;color:#93c5fd;margin-top:4px;}",
        "details.card{margin:12px 0;border:1px solid #1f2937;border-radius:12px;background:#0f172a;overflow:hidden;}",
        "summary.head{cursor:pointer;list-style:none;padding:12px 14px;display:flex;justify-content:space-between;align-items:center;gap:10px;}",
        "summary.head::-webkit-details-marker{display:none;}",
        ".head-left{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}",
        ".sev{display:inline-block;padding:3px 8px;border-radius:8px;font-size:11px;font-weight:700;}",
        ".sev-critical{background:#7f1d1d;color:#fecaca;border:1px solid #dc2626;}",
        ".sev-high{background:#7c2d12;color:#fed7aa;border:1px solid #f97316;}",
        ".sev-medium{background:#1e3a8a;color:#bfdbfe;border:1px solid #3b82f6;}",
        ".sev-low{background:#065f46;color:#a7f3d0;border:1px solid #10b981;}",
        ".conf-high{background:#4c1d95;color:#ddd6fe;border:1px solid #7c3aed;}",
        ".conf-medium{background:#1e3a5f;color:#bae6fd;border:1px solid #0ea5e9;}",
        ".conf-low{background:#374151;color:#d1d5db;border:1px solid #6b7280;}",
        ".meta{color:#93c5fd;font-size:13px;}",
        ".card-body{padding:12px 14px;border-top:1px solid #1f2937;display:grid;gap:10px;}",
        ".grid{display:grid;grid-template-columns:1.2fr 1fr;gap:10px;}",
        ".panel{padding:10px;border:1px solid #1f2937;border-radius:10px;background:#0b1220;}",
        ".panel h5{margin:0 0 8px;font-size:12px;letter-spacing:.06em;color:#94a3b8;text-transform:uppercase;}",
        "table{width:100%;border-collapse:collapse;font-size:12px;}",
        "th,td{padding:6px;border-bottom:1px solid #1f2937;text-align:left;vertical-align:top;}",
        "th{color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.05em;}",
        "tr:last-child td{border-bottom:none;}",
        ".code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#cbd5e1;white-space:pre-wrap;}",
        ".graph{overflow:auto;border:1px solid #1f2937;border-radius:10px;background:#0b1220;padding:6px;min-height:180px;}",
        ".legend{display:flex;gap:8px;flex-wrap:wrap;}",
        ".lg{padding:3px 8px;border:1px solid #334155;border-radius:999px;font-size:11px;color:#cbd5e1;}",
        ".graph-note{padding:8px 10px;border:1px solid #243246;border-radius:8px;background:#0a1628;color:#cbd5e1;font-size:12px;line-height:1.45;}",
        ".hot{max-height:240px;overflow:auto;}",
        "@media (max-width:1100px){.layout{grid-template-columns:1fr}.side{position:static;height:auto}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr;}}",
        "@media (max-width:640px){.cards{grid-template-columns:1fr}}",
        "</style></head><body>",
        "<div class='layout'>",
        "<aside class='side'>",
        f"<div class='h1'>{_escape_html(title)}</div>",
        "<div class='muted'>Cross-file call/value tracing with security-oriented xref metrics.</div>",
        "<a class='back' href='analysis.html'>Back To Main Findings</a>",
        "<input id='q' class='search' placeholder='Filter by sink, symbol, file, function, value...'>",
        "<div class='sec'><h4>Overview</h4><div class='chips'>",
        f"<span class='chip'>Flows: {len(flows)}</span>",
        f"<span class='chip'>XREF: {total_xref}</span>",
        f"<span class='chip'>Cross-file: {cross_file_count}</span>",
        f"<span class='chip'>Avg path: {avg_path_len}</span>",
        f"<span class='chip'>XREF/flow: {avg_xref_per_flow}</span>",
        "</div></div>",
        "<div class='sec'><h4>Quick Flow Jump</h4>",
    ]

    if not flow_payload:
        lines.append("<div class='muted'>No XREF entries found.</div>")
    else:
        for fp in flow_payload:
            lines.append(
                f"<a class='quick' href='#flow-{fp['rank']}'>#{fp['rank']} { _escape_html(fp['severity']) } "
                f"{ _escape_html(fp['sink']) }</a>"
            )
    lines.append("</div>")

    if top_symbols:
        lines.append("<div class='sec'><h4>Hot Symbols</h4>")
        for row in top_symbols:
            lines.append(f"<div class='quick'>{_escape_html(row['symbol'])} <span class='muted'>x{row['count']}</span></div>")
        lines.append("</div>")
    if top_values:
        lines.append("<div class='sec'><h4>Hot Values</h4>")
        for row in top_values:
            lines.append(f"<div class='quick'>{_escape_html(row['token'])} <span class='muted'>x{row['count']}</span></div>")
        lines.append("</div>")
    if attack_summary:
        lines.append("<div class='sec'><h4>Attack Surface</h4>")
        for row in attack_summary[:10]:
            lines.append(f"<div class='quick'>{_escape_html(row['label'])} <span class='muted'>x{row['count']}</span></div>")
        lines.append("</div>")

    lines.append("</aside><main class='main'>")
    lines.append("<div class='cards'>")
    lines.append(f"<div class='mcard'><div class='k'>Flows</div><div class='v'>{len(flows)}</div></div>")
    lines.append(f"<div class='mcard'><div class='k'>XREF Entries</div><div class='v'>{total_xref}</div></div>")
    lines.append(f"<div class='mcard'><div class='k'>Cross-file Flows</div><div class='v'>{cross_file_count}</div></div>")
    lines.append(f"<div class='mcard'><div class='k'>Avg Path Length</div><div class='v'>{avg_path_len}</div></div>")
    lines.append("</div>")

    if top_files:
        lines.append("<div class='panel hot'><h5>Top Referenced Files</h5><table><tr><th>File</th><th>Hits</th></tr>")
        for row in top_files:
            lines.append(f"<tr><td>{_escape_html(row['file'])}</td><td>{row['count']}</td></tr>")
        lines.append("</table></div>")

    if not flow_payload:
        lines.append("<p class='muted'>No XREF entries found.</p>")
    for fp in flow_payload:
        sev_class = {
            "Critical": "sev-critical",
            "High": "sev-high",
            "Medium": "sev-medium",
            "Low": "sev-low",
        }.get(str(fp["severity"]), "sev-low")

        lines.append(f"<details class='card' id='flow-{fp['rank']}' data-tags='{_escape_html(fp['tags'])}'>")
        lines.append("<summary class='head'>")
        lines.append("<div class='head-left'>")
        lines.append(f"<span class='sev {sev_class}'>{_escape_html(fp['severity'])}</span>")
        lines.append(
            f"<span class='meta'><strong>Flow #{fp['rank']}</strong> | {_escape_html(fp['sink'])} | "
            f"{_escape_html(fp['file'])}:{_escape_html(fp['line'])}</span>"
        )
        lines.append("</div>")
        _conf = str(fp.get("confidence", "low")).lower()
        _conf_cls = {"high": "conf-high", "medium": "conf-medium"}.get(_conf, "conf-low")
        lines.append(
            f"<div class='chips'><span class='chip'>Risk {fp['risk_score']}</span>"
            f"<span class='chip'>Path {fp['path_len']}</span><span class='chip'>XREF {fp['xref_count']}</span>"
            f"<span class='chip'>Trace { _escape_html(str(fp.get('trace_status', 'complete')).capitalize()) }</span>"
            f"<span class='sev {_conf_cls}'>Confidence: {_escape_html(_conf.capitalize())}</span></div>"
        )
        lines.append("</summary><div class='card-body'>")
        lines.append(f"<div class='muted'>{_escape_html(fp['description'])}</div>")
        if fp.get("explanation"):
            lines.append(f"<div class='muted'><strong>Why it matters:</strong> {_escape_html(fp['explanation'])}</div>")
        if fp.get("termination_nodes"):
            lines.append("<div class='panel'><h5>Trace Termination</h5><table><tr><th>Reason</th><th>Location</th><th>Code</th></tr>")
            for node in fp.get("termination_nodes", [])[:8]:
                location = f"{node.get('file', '-')}" + (f":{node.get('line')}" if node.get("line") else "")
                lines.append(
                    f"<tr><td>{_escape_html(str(node.get('reason', 'unresolved')).replace('_', ' '))}</td>"
                    f"<td>{_escape_html(location)}</td>"
                    f"<td class='code'>{_escape_html(node.get('code', ''))}</td></tr>"
                )
            lines.append("</table></div>")
        surf = fp.get("input_surface", {}) or {}
        methods = ", ".join(surf.get("methods", []) or []) or "N/A"
        uris = surf.get("uris", []) or []
        params = ", ".join(surf.get("params", []) or []) or "N/A"
        examples = surf.get("examples", []) or []
        vectors = fp.get("attack_vectors", []) or []
        lines.append("<div class='panel'><h5>Attack Vectors</h5><table><tr><th>Vector</th><th>Why it matters</th><th>Taint Details</th><th>Examples</th></tr>")
        if not vectors:
            lines.append("<tr><td colspan='4' class='muted'>No attack vectors inferred</td></tr>")
        else:
            for vector in vectors:
                lines.append(
                    f"<tr><td>{_escape_html(vector.get('label','vector'))}</td>"
                    f"<td>{_escape_html(vector.get('reason',''))}</td>"
                    f"<td class='code'>{_escape_html(', '.join(vector.get('taint_symbols', [])[:4]))}</td>"
                    f"<td class='code'>{_escape_html(' | '.join(vector.get('examples', [])[:2]))}</td></tr>"
                )
        lines.append("</table></div>")
        lines.append("<div class='panel'><h5>Input Surface / Pentest Hints</h5><table>")
        lines.append(f"<tr><th>Interface</th><td>{_escape_html(surf.get('channel', 'code-path'))}</td></tr>")
        lines.append(f"<tr><th>Methods / Input Mode</th><td>{_escape_html(methods)}</td></tr>")
        lines.append(f"<tr><th>Candidate Parameters</th><td>{_escape_html(params)}</td></tr>")
        if uris:
            lines.append(f"<tr><th>Observed URI Patterns</th><td class='code'>{_escape_html(' | '.join(uris[:3]))}</td></tr>")
        if examples:
            lines.append(f"<tr><th>Verify During Pentest</th><td class='code'>{_escape_html(' | '.join(examples[:3]))}</td></tr>")
        lines.append("</table></div>")

        lines.append("<div class='legend'><span class='lg'>PATH lane: tainted data direction</span><span class='lg'>CALLSITE lane</span><span class='lg'>DEFINITION lane</span><span class='lg'>Dashed edge: weak relation only</span></div>")
        lines.append(f"<div class='graph-note'>{_escape_html(fp.get('graph_narrative',''))}</div>")
        lines.append(f"<div class='graph' id='graph-{fp['rank']}'></div>")
        lines.append("<div class='panel'><h5>Graph Walkthrough</h5><table><tr><th>#</th><th>Description</th></tr>")
        if not fp.get("graph_steps"):
            lines.append("<tr><td colspan='2' class='muted'>No graph steps available.</td></tr>")
        else:
            for idx, row in enumerate(fp["graph_steps"], start=1):
                lines.append(f"<tr><td>{idx}</td><td>{_escape_html(row)}</td></tr>")
        lines.append("</table></div>")
        lines.append("<div class='grid'>")

        lines.append("<div class='panel'><h5>Flow Path Trace</h5><table><tr><th>Role</th><th>Location</th><th>Code</th></tr>")
        for step in fp["path"]:
            lines.append(
                f"<tr><td>{_escape_html(step.get('role','step'))}</td>"
                f"<td>{_escape_html(step.get('file',''))}:{_escape_html(step.get('line',''))}</td>"
                f"<td class='code'>{_escape_html(step.get('code',''))}</td></tr>"
            )
        lines.append("</table></div>")

        lines.append("<div class='panel'><h5>Cross References</h5><table><tr><th>Type</th><th>Symbol</th><th>Location</th><th>Context</th></tr>")
        if not fp["xref"]:
            lines.append("<tr><td colspan='4' class='muted'>No xref entries</td></tr>")
        else:
            for x in fp["xref"]:
                symbol = x.get("resolved_name") or x.get("symbol") or ""
                lines.append(
                    f"<tr><td>{_escape_html(x.get('type','xref'))}</td>"
                    f"<td>{_escape_html(symbol)}</td>"
                    f"<td>{_escape_html(x.get('file',''))}:{_escape_html(x.get('line',''))}</td>"
                    f"<td>{_escape_html(x.get('context',''))}</td></tr>"
                )
        lines.append("</table></div>")

        lines.append("</div>")

        lines.append("<div class='panel'><h5>Argument / Value Reuse Hotspots</h5><table><tr><th>Token</th><th>Count</th><th>Roles</th><th>Files</th></tr>")
        if not fp["value_hotspots"]:
            lines.append("<tr><td colspan='4' class='muted'>No significant value-reuse patterns</td></tr>")
        else:
            for row in fp["value_hotspots"]:
                lines.append(
                    f"<tr><td>{_escape_html(row['token'])}</td><td>{row['count']}</td>"
                    f"<td>{_escape_html(', '.join(row['roles'][:5]))}</td>"
                    f"<td>{_escape_html(', '.join(row['files'][:4]))}</td></tr>"
                )
        lines.append("</table></div>")
        lines.append("</div></details>")

    payload_json = json.dumps({"flows": flow_payload})
    lines.append(
        "<script>"
        f"window.__XREF_DATA={payload_json};"
        "function drawGraph(container,graph){"
        "if(!container||!graph){return;}const NS='http://www.w3.org/2000/svg';"
        "const nodes=graph.nodes||[];const edges=graph.edges||[];"
        "const idxOf=(id)=>{const m=String(id||'').match(/^p(\\d+)$/);return m?Number(m[1]):9999;};"
        "const trim=(v,n)=>{const s=String(v||'');return s.length>n?(s.slice(0,Math.max(0,n-1))+'...'):s;};"
        "const pathNodes=nodes.filter(n=>n.kind==='path');const xNodes=nodes.filter(n=>n.kind==='xref');"
        "pathNodes.sort((a,b)=>idxOf(a.id)-idxOf(b.id));"
        "const callX=xNodes.filter(n=>String(n.role||'').toLowerCase()==='callsite');"
        "const defX=xNodes.filter(n=>String(n.role||'').toLowerCase()==='definition');"
        "const relX=xNodes.filter(n=>String(n.role||'').toLowerCase()!=='definition' && String(n.role||'').toLowerCase()!=='callsite');"
        "const nodeW=196,nodeH=60,pathStartX=72,pathSpacing=nodeW+110;"
        "const w=Math.max(1260,pathStartX*2+Math.max(4,pathNodes.length)*pathSpacing);"
        "const initialH=900;"
        "const svg=document.createElementNS(NS,'svg');svg.setAttribute('viewBox',`0 0 ${w} ${initialH}`);svg.setAttribute('width',w);svg.setAttribute('height',initialH);"
        "const defs=document.createElementNS(NS,'defs');const m=document.createElementNS(NS,'marker');m.setAttribute('id','arr');m.setAttribute('viewBox','0 0 10 10');m.setAttribute('refX','8');m.setAttribute('refY','5');m.setAttribute('markerWidth','6');m.setAttribute('markerHeight','6');m.setAttribute('orient','auto-start-reverse');"
        "const p=document.createElementNS(NS,'path');p.setAttribute('d','M 0 0 L 10 5 L 0 10 z');p.setAttribute('fill','#94a3b8');m.appendChild(p);defs.appendChild(m);svg.appendChild(defs);"
        "const pos={};"
        "const maxRowsPerCol=3,rowGap=nodeH+10,colGap=nodeW+24,minNodeGap=18,bandPadTop=24,bandPadBottom=16;"
        "const pathTop=42,pathHeight=bandPadTop+nodeH+bandPadBottom,pathY=pathTop+bandPadTop;"
        "let x=pathStartX;pathNodes.forEach((n)=>{pos[n.id]={x:x,y:pathY};x+=pathSpacing;});"
        "const inPathAnchor=(nodeId)=>{const e=edges.find(k=>k.to===nodeId&&String(k.from||'').startsWith('p'));if(!e)return null;return e.from;};"
        "const groupByAnchor=(arr)=>{const g={};arr.forEach((n)=>{const a=inPathAnchor(n.id)||'p999';g[a]=g[a]||[];g[a].push(n);});Object.keys(g).forEach((k)=>{g[k].sort((u,v)=>String(u.label||'').localeCompare(String(v.label||'')));});return g;};"
        "const pathOrder=pathNodes.map(n=>n.id);"
        "const anchorBounds={};"
        "pathOrder.forEach((id,i)=>{const cx=pos[id].x+(nodeW/2);const prev=i>0?(pos[pathOrder[i-1]].x+(nodeW/2)):null;const next=i<pathOrder.length-1?(pos[pathOrder[i+1]].x+(nodeW/2)):null;const left=prev!==null?(prev+cx)/2+minNodeGap:28;const right=next!==null?(cx+next)/2-minNodeGap:(w-28);anchorBounds[id]={left,right};});"
        "anchorBounds['p999']={left:Math.max(pathStartX,pathStartX+pathNodes.length*pathSpacing-nodeW),right:w-28};"
        "const callGroups=groupByAnchor(callX);"
        "const defGroups=groupByAnchor(defX);"
        "const relGroups=groupByAnchor(relX);"
        "const estimateRows=(grp)=>{let m=1;Object.keys(grp).forEach((anchor)=>{const arr=grp[anchor]||[];if(!arr.length)return;const b=anchorBounds[anchor]||anchorBounds['p999'];const avail=Math.max(nodeW,b.right-b.left);const fitCols=Math.max(1,Math.floor((avail+minNodeGap)/(nodeW+minNodeGap)));const preferredCols=Math.max(1,Math.ceil(arr.length/maxRowsPerCol));const cols=Math.min(preferredCols,fitCols);const rows=Math.ceil(arr.length/cols);m=Math.max(m,rows);});return m;};"
        "const laneHeight=(rows)=>bandPadTop+(rows*rowGap)+bandPadBottom;"
        "const callTop=pathTop+pathHeight+26,callHeight=laneHeight(estimateRows(callGroups));"
        "const defTop=callTop+callHeight+18,defHeight=laneHeight(estimateRows(defGroups));"
        "const relTop=defTop+defHeight+18,relHeight=laneHeight(estimateRows(relGroups));"
        "const h=relTop+relHeight+24;svg.setAttribute('viewBox',`0 0 ${w} ${h}`);svg.setAttribute('height',h);"
        "const laneBand=(top,height,color,label)=>{const bg=document.createElementNS(NS,'rect');bg.setAttribute('x',20);bg.setAttribute('y',top);bg.setAttribute('width',w-40);bg.setAttribute('height',height);bg.setAttribute('rx','8');bg.setAttribute('fill',color);bg.setAttribute('fill-opacity','0.05');bg.setAttribute('stroke',color);bg.setAttribute('stroke-opacity','0.26');svg.appendChild(bg);const tx=document.createElementNS(NS,'text');tx.setAttribute('x',28);tx.setAttribute('y',top+14);tx.setAttribute('fill',color);tx.setAttribute('font-size','10');tx.setAttribute('font-family','Segoe UI');tx.textContent=label;svg.appendChild(tx);};"
        "laneBand(pathTop,pathHeight,'#7dd3fc','PATH FLOW (left -> right)');laneBand(callTop,callHeight,'#a78bfa','XREF CALLSITES');laneBand(defTop,defHeight,'#34d399','XREF DEFINITIONS');laneBand(relTop,relHeight,'#94a3b8','RELATED REFERENCES');"
        "const laneTop={callsite:callTop,definition:defTop,related:relTop};"
        "function placeLane(groups,laneKey){Object.keys(groups).forEach((anchor)=>{const arr=groups[anchor]||[];if(!arr.length)return;const b=anchorBounds[anchor]||anchorBounds['p999'];const avail=Math.max(nodeW,b.right-b.left);const fitCols=Math.max(1,Math.floor((avail+minNodeGap)/(nodeW+minNodeGap)));const preferredCols=Math.max(1,Math.ceil(arr.length/maxRowsPerCol));const cols=Math.min(preferredCols,fitCols);const rows=Math.ceil(arr.length/cols);const usedW=(cols*nodeW)+((cols-1)*minNodeGap);const startX=Math.max(24,b.left+Math.max(0,(avail-usedW)/2));arr.forEach((n,i)=>{const col=i%cols;const row=Math.floor(i/cols);const rawX=startX+(col*(nodeW+minNodeGap));const laneY=laneTop[laneKey]+bandPadTop+(row*rowGap);pos[n.id]={x:Math.max(24,Math.min(w-nodeW-24,rawX)),y:laneY};});});}"
        "placeLane(callGroups,'callsite');placeLane(defGroups,'definition');placeLane(relGroups,'related');"
        "edges.forEach((e)=>{if(!pos[e.from]||!pos[e.to])return;const l=document.createElementNS(NS,'path');"
        "const a=pos[e.from],b=pos[e.to];const x1=a.x+nodeW/2,y1=a.y+nodeH/2,x2=b.x+nodeW/2,y2=b.y+nodeH/2;const midY=y1+((y2-y1)*0.52);"
        "l.setAttribute('d',`M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`);"
        "l.setAttribute('fill','none');"
        "const dashed=(e.kind==='xref_related');l.setAttribute('stroke',e.kind==='path'?'#7dd3fc':(dashed?'#94a3b8':'#c4b5fd'));l.setAttribute('stroke-width',e.kind==='path'?'2.2':'1.6');if(dashed){l.setAttribute('stroke-dasharray','5,4');}l.setAttribute('marker-end','url(#arr)');svg.appendChild(l);});"
        "nodes.forEach((n)=>{if(!pos[n.id])return;const r=document.createElementNS(NS,'rect');const t=document.createElementNS(NS,'text');const s=document.createElementNS(NS,'text');const a=pos[n.id];"
        "r.setAttribute('x',a.x);r.setAttribute('y',a.y);r.setAttribute('rx','10');r.setAttribute('ry','10');r.setAttribute('width',nodeW);r.setAttribute('height',nodeH);"
        "if(n.kind==='xref'){const rt=String(n.role||'').toLowerCase();if(rt==='definition'){r.setAttribute('fill','#0f2f2a');r.setAttribute('stroke','#34d399');}else if(rt==='callsite'){r.setAttribute('fill','#22163b');r.setAttribute('stroke','#a78bfa');}else{r.setAttribute('fill','#1f2937');r.setAttribute('stroke','#94a3b8');}}else{r.setAttribute('fill','#111827');r.setAttribute('stroke','#7dd3fc');}"
        "t.setAttribute('x',a.x+10);t.setAttribute('y',a.y+24);t.setAttribute('fill','#e5e7eb');t.setAttribute('font-size','11');t.setAttribute('font-family','Segoe UI');t.textContent=trim((n.label||'').toUpperCase(),24);"
        "s.setAttribute('x',a.x+10);s.setAttribute('y',a.y+43);s.setAttribute('fill','#93c5fd');s.setAttribute('font-size','10');s.setAttribute('font-family','Segoe UI');s.textContent=trim(n.sub||'',30);"
        "svg.appendChild(r);svg.appendChild(t);svg.appendChild(s);});"
        "container.innerHTML='';container.appendChild(svg);}"
        "function renderAllGraphs(){const data=window.__XREF_DATA||{flows:[]};data.flows.forEach((f)=>{drawGraph(document.getElementById(`graph-${f.rank}`),f.graph);});}"
        "const q=document.getElementById('q');q&&q.addEventListener('input',()=>{const term=q.value.toLowerCase().trim();document.querySelectorAll('details.card').forEach(el=>{const tags=(el.getAttribute('data-tags')||'').toLowerCase();el.style.display=(!term||tags.includes(term))?'block':'none';});});"
        "renderAllGraphs();"
        "</script>"
    )
    lines.append("</main></div></body></html>")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def render_xref_html_modern(flows: List[Dict], output_path: Path, title: str = "Dataflow XREF", theme: str = "hacker_mode"):
    temp_path = output_path.parent / f"{output_path.stem}.legacy.tmp"
    render_xref_html(flows, temp_path, title=title)
    html_text = temp_path.read_text(encoding="utf-8")
    modern_text = _inject_modern_style(html_text, variant="xref", theme=theme)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(modern_text, encoding="utf-8")
    try:
        temp_path.unlink()
    except OSError:
        pass
    return output_path


def write_reports(flows: List[Dict], output_dir: Path, title: str, platform: str = None):
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "analysis.json"
    html_path = output_dir / "analysis.html"
    xref_html_path = output_dir / "analysis_xref.html"

    print(f"     [-] Ranking flows      : deduplicating and scoring {len(flows)} flow(s)", flush=True)
    ranked_flows = rank_and_dedupe_flows(flows, platform=platform)
    print(f"     [-] Enriching flows    : inferring input surface and attack vectors", flush=True)
    for flow in ranked_flows:
        flow["input_surface"] = flow.get("input_surface") or _infer_input_surface(flow)
        flow["attack_vectors"] = flow.get("attack_vectors") or _derive_attack_vectors(flow)
    print(f"     [-] Writing JSON       : {len(ranked_flows)} ranked flow(s)", flush=True)
    json_path.write_text(json.dumps(ranked_flows, indent=2), encoding="utf-8")

    # Write themed HTML output directly into output_dir.
    # For theme=both, the default (hacker) uses the standard filenames and
    # the professional variant gets a _professional suffix.
    configured_theme = _get_report_theme()
    themes = ["hacker_mode", "professional_mode"] if configured_theme == "both" else [configured_theme]
    for theme in themes:
        title_suffix = "Hacker Mode" if theme == "hacker_mode" else "Professional Mode"
        if theme == "professional_mode" and configured_theme == "both":
            themed_html_path = output_dir / "analysis_professional.html"
            themed_xref_path = output_dir / "analysis_xref_professional.html"
        else:
            themed_html_path = html_path
            themed_xref_path = xref_html_path
        print(f"     [-] Rendering report   : {title_suffix} analysis HTML", flush=True)
        render_html_modern(ranked_flows, themed_html_path, title=f"{title} - {title_suffix}", theme=theme)
        print(f"     [-] Rendering xref     : {title_suffix} xref HTML", flush=True)
        render_xref_html_modern(ranked_flows, themed_xref_path, title=f"{title} - XREF {title_suffix}", theme=theme)

    print(f"     [-] Reports written    : {output_dir}", flush=True)
    return json_path, html_path
