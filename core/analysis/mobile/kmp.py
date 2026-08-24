# Standard libraries
from pathlib import Path
from typing import List
import re

import state.runtime_state as state
from core.analysis.kotlin.analyzer import analyze_kotlin_flows
from core.analysis.mobile.common import annotate_flows, collect_files, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


MULTIPLATFORM_RE = re.compile(r'kotlin\s*\(\s*["\']multiplatform["\']\s*\)|org\.jetbrains\.kotlin\.multiplatform|kotlin-multiplatform', re.IGNORECASE)
TLS_BYPASS_RE = re.compile(r"\b(?:hostnameVerifier\s*\{.*true|trustAll|InsecureTrustManager(?!\s*=\s*false))", re.IGNORECASE)
HTTP_RE = re.compile(r"http://", re.IGNORECASE)


def _semantic_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    project_files = collect_files(source_root, ("*.gradle", "*.gradle.kts", "*.kt", "*.kts"))
    is_kmp_project = False
    for file_path in project_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        marker_line = first_match_line(lines, MULTIPLATFORM_RE)
        if marker_line:
            is_kmp_project = True
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="multiplatform_config",
                    sink="kmp project marker",
                    description="Kotlin Multiplatform project configuration is present.",
                    explanation="This marks the project as shared mobile Kotlin code and enables dedicated KMP-oriented review paths.",
                    path=[
                        {"file": None, "line": marker_line, "role": "source", "code": "[kmp config] Gradle config selects Kotlin Multiplatform.", "source_symbol": "kmp_project", "variables": ["kmp_project"]},
                        {"file": None, "line": marker_line, "role": "sink", "code": line_text(lines, marker_line, "kotlin(\"multiplatform\")")},
                    ],
                    confidence="high",
                    methods=["BUILD"],
                    params=["multiplatform"],
                    attack_label="Project Marker",
                    attack_reason="The project is Kotlin Multiplatform and should be reviewed as a mobile shared-code target.",
                )
            )
            break

    if not is_kmp_project:
        return flows

    kotlin_files = collect_files(source_root, ("*.kt", "*.kts"))
    for file_path in kotlin_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        tls_line = first_match_line(lines, TLS_BYPASS_RE)
        if tls_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_client",
                    sink="kmp certificate validation bypass",
                    description="Shared Kotlin Multiplatform networking code appears to weaken or bypass TLS validation.",
                    explanation="Trust-all managers or permissive hostname verifiers disable certificate verification and expose both Android and iOS clients to MITM attacks.",
                    path=[
                        {"file": None, "line": tls_line, "role": "source", "code": "[kmp network] Shared mobile networking code configures peer trust handling.", "source_symbol": "shared_network", "variables": ["shared_network"]},
                        {"file": None, "line": tls_line, "role": "sink", "code": line_text(lines, tls_line, "hostnameVerifier { _, _ -> true }")},
                    ],
                    methods=["HTTPS"],
                    uris=["https://<HOST>"],
                    params=["certificate_validation"],
                    attack_label="Certificate Validation Bypass",
                    attack_reason="The shared networking layer appears to disable strict trust validation.",
                )
            )

        http_line = first_match_line(lines, HTTP_RE)
        if http_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_request",
                    sink="kmp insecure http endpoint",
                    description="Shared Kotlin Multiplatform code references a cleartext HTTP endpoint.",
                    explanation="Using `http://` in shared mobile networking code exposes both Android and iOS traffic to interception and tampering.",
                    path=[
                        {"file": None, "line": http_line, "role": "source", "code": "[kmp config] Shared endpoint declared in multiplatform code.", "source_symbol": "endpoint", "variables": ["endpoint"]},
                        {"file": None, "line": http_line, "role": "sink", "code": line_text(lines, http_line, "http://")},
                    ],
                    confidence="medium",
                    methods=["HTTP"],
                    uris=["http://<HOST>"],
                    params=["endpoint"],
                    attack_label="Insecure Transport",
                    attack_reason="The shared mobile code references a cleartext endpoint.",
                )
            )
    return flows


def analyze_kmp_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_kotlin_flows(source_root, progress_callback=progress_callback), platform="kmp", variant="kotlin")
    flows.extend(annotate_flows(_semantic_flows(source_root), platform="kmp", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_kmp_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "kmp")
    return write_reports(flows, out_dir, title="Kotlin Multiplatform Dataflow Analysis", platform="kmp")
