"""Machine-readable RDL corpus execution, metrics, and quality gates."""

import json
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Tuple

from .compiler import compile_rdl
from .executor import ExecutionOutcome, SemanticExecutor


@dataclass(frozen=True)
class CorpusCaseResult:
    case_id: str
    expected: str
    actual: str
    classification: str
    passed: bool
    elapsed_ms: float
    peak_memory_bytes: int
    evidence_count: int
    analysis_depth: int
    errors: Tuple[str, ...] = ()


@dataclass(frozen=True)
class CorpusReport:
    cases: Tuple[CorpusCaseResult, ...]
    metrics: Dict[str, float]
    gates_passed: bool
    gate_failures: Tuple[str, ...]

    def as_dict(self):
        return {
            "cases": [asdict(item) for item in self.cases],
            "metrics": self.metrics,
            "gates_passed": self.gates_passed,
            "gate_failures": list(self.gate_failures),
        }


def load_manifest(path: Path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported corpus manifest schema")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("corpus manifest requires cases")
    identifiers = set()
    defaults = payload.get("defaults", {})
    for case in cases:
        for key in ("license", "expected_report", "max_runtime_ms"):
            if key not in case and key in defaults:
                case[key] = defaults[key]
        required = {"id", "rule", "language", "target", "expected_outcome", "category", "license", "expected_report"}
        missing = sorted(required - set(case))
        if missing:
            raise ValueError("case {0} missing: {1}".format(case.get("id", "<unknown>"), ", ".join(missing)))
        if case["id"] in identifiers:
            raise ValueError("duplicate corpus case ID: {0}".format(case["id"]))
        identifiers.add(case["id"])
        license_data = case["license"]
        if not license_data.get("spdx") or not license_data.get("origin") or license_data.get("redistributable") is not True:
            raise ValueError("case {0} lacks redistributable license provenance".format(case["id"]))
        if case["expected_outcome"] not in {item.value for item in ExecutionOutcome}:
            raise ValueError("case {0} has invalid expected outcome".format(case["id"]))
    return payload


def _evidence_ok(constraint, evidence):
    for item in evidence:
        if item.predicate != constraint.get("predicate"):
            continue
        if "matched" in constraint and item.matched is not constraint["matched"]:
            continue
        if constraint.get("contains") and constraint["contains"] not in item.explanation:
            continue
        return True
    return False


def _depth(evidence):
    depths = []
    for item in evidence:
        if item.predicate == "FLOWS TO":
            depths.append(item.explanation.count("->") + 1)
        elif item.predicate == "INTERPROCEDURAL PATH":
            depths.append(item.explanation.count(" -> ") + 1)
        elif item.predicate.startswith("STATE"):
            depths.append(item.explanation.count(" -> ") + 1)
    return max(depths or [0])


def run_manifest(manifest_path: Path, repository_root: Path, repeat=2):
    manifest = load_manifest(manifest_path)
    root = Path(repository_root)
    executor = SemanticExecutor()
    results = []
    for case in manifest["cases"]:
        rule_path = root / case["rule"]
        target = root / case["target"]
        document = compile_rdl(rule_path.read_text(encoding="utf-8"), str(rule_path))
        signatures = []
        measured = None
        elapsed_ms = 0.0
        peak_memory = 0
        for iteration in range(max(1, repeat)):
            tracemalloc.start()
            started = time.perf_counter()
            execution = executor.execute(document, target, case["language"])
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            duration = (time.perf_counter() - started) * 1000.0
            if iteration == 0:
                measured = execution
                elapsed_ms = duration
                peak_memory = peak
            signatures.append((
                execution.outcome.value,
                tuple((item.predicate, item.matched, item.entity_id, item.explanation) for item in execution.evidence),
                execution.unavailable_capabilities,
                execution.errors,
            ))
        errors = []
        expected = case["expected_outcome"]
        if measured.outcome.value != expected:
            errors.append("expected {0}, got {1}".format(expected, measured.outcome.value))
        report = case["expected_report"]
        plan = document.execution_plan
        if plan is None or plan.severity.value != report["severity"] or plan.confidence.value != report["confidence"]:
            errors.append("severity/confidence mismatch")
        for constraint in case.get("evidence", []):
            if not _evidence_ok(constraint, measured.evidence):
                errors.append("missing evidence: {0}".format(constraint))
        if len(set(signatures)) != 1:
            errors.append("non-deterministic repeated result")
        max_runtime_ms = float(case.get("max_runtime_ms", manifest.get("thresholds", {}).get("max_case_runtime_ms", 5000)))
        if elapsed_ms > max_runtime_ms:
            errors.append("runtime budget exceeded")
        if expected == ExecutionOutcome.MATCH.value:
            classification = "TP" if measured.outcome == ExecutionOutcome.MATCH else "FN"
        elif expected == ExecutionOutcome.NO_MATCH.value:
            classification = "TN" if measured.outcome == ExecutionOutcome.NO_MATCH else "FP" if measured.outcome == ExecutionOutcome.MATCH else "UNRESOLVED"
        else:
            classification = "EXPECTED_{0}".format(expected)
        results.append(CorpusCaseResult(
            case["id"], expected, measured.outcome.value, classification, not errors,
            round(elapsed_ms, 3), peak_memory, len(measured.evidence), _depth(measured.evidence), tuple(errors),
        ))
    counts = {name: sum(item.classification == name for item in results) for name in ("TP", "TN", "FP", "FN")}
    precision = counts["TP"] / float(counts["TP"] + counts["FP"]) if counts["TP"] + counts["FP"] else 1.0
    recall = counts["TP"] / float(counts["TP"] + counts["FN"]) if counts["TP"] + counts["FN"] else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = {
        **{name.lower(): value for name, value in counts.items()},
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "passed": sum(item.passed for item in results),
        "failed": sum(not item.passed for item in results),
        "total": len(results),
        "elapsed_ms": round(sum(item.elapsed_ms for item in results), 3),
        "peak_case_memory_bytes": max((item.peak_memory_bytes for item in results), default=0),
        "max_analysis_depth": max((item.analysis_depth for item in results), default=0),
        "rule_errors": sum(item.actual == ExecutionOutcome.RULE_ERROR.value for item in results),
        "indeterminate": sum(item.actual == ExecutionOutcome.INDETERMINATE.value for item in results),
    }
    thresholds = manifest.get("thresholds", {})
    failures = []
    for metric in ("precision", "recall", "f1"):
        if metrics[metric] < float(thresholds.get("min_" + metric, 0)):
            failures.append("{0} below threshold".format(metric))
    if metrics["rule_errors"] > int(thresholds.get("max_rule_errors", 0)):
        failures.append("rule-error threshold exceeded")
    if metrics["failed"]:
        failures.append("one or more corpus cases failed")
    return CorpusReport(tuple(results), metrics, not failures, tuple(failures))
