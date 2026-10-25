"""Consolidated RDL compatibility, corpus, and performance release gates."""

import json
import time
import tracemalloc
from pathlib import Path

from .compiler import compile_rdl
from .coverage import audit_coverage
from .corpus import run_manifest
from .model import DiagnosticSeverity
from .adapters.registry import default_registry
from .cache import IncrementalIRCache


def audit_rule_tree(root):
    root = Path(root)
    groups = {
        "v1": sorted((root / 'rules/scanning/logic/rdl/v1').rglob("*.rdl")),
        "v2": sorted((root / 'rules/scanning/logic/rdl/v2').rglob("*.rdl")),
    }
    started = time.perf_counter()
    tracemalloc.start()
    errors = []
    pattern_paths = sorted(p for p in (root / 'rules/scanning/platform').rglob('*.yaml') if p.name != '_pack.yaml')
    from core.pattern_rules import load_rule
    for path in pattern_paths:
        try:
            load_rule(path)
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
    for paths in groups.values():
        for path in paths:
            document = compile_rdl(path.read_text(encoding="utf-8"), str(path))
            errors.extend(
                "{0}:{1}:{2}".format(path, item.span.line, item.message)
                for item in document.diagnostics if item.severity == DiagnosticSeverity.ERROR
            )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "v1_rules": len(groups["v1"]),
        "pattern_rules": len(pattern_paths),
        "v2_rules": len(groups["v2"]),
        "errors": len(errors),
        "error_details": errors,
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "peak_memory_bytes": peak,
    }


def run_release_gates(root, config_path=None, repeat=2):
    root = Path(root)
    config_path = Path(config_path or root / "tests/rdl/data/release-gates.json")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("schema_version") != 1:
        raise ValueError("unsupported release-gate schema")
    rule_audit = audit_rule_tree(root)
    corpus = run_manifest(root / "tests" / "rdl" / "corpus" / "manifest.json", root, repeat)
    cache = IncrementalIRCache()
    adapter = default_registry().get("python")
    cache_target = root / "exclude" / "sampleapps" / "rdl_v2" / "python" / "security_vulnerable.py"
    cold_started = time.perf_counter()
    cache.parse(adapter, cache_target)
    cold_ms = (time.perf_counter() - cold_started) * 1000.0
    warm_started = time.perf_counter()
    cache.parse(adapter, cache_target)
    warm_ms = (time.perf_counter() - warm_started) * 1000.0
    cache_measurement = {
        "cold_ms": round(cold_ms, 3),
        "warm_ms": round(warm_ms, 3),
        "hits": cache.stats.hits,
        "misses": cache.stats.misses,
        "entries": cache.stats.entries,
        "source_bytes": cache.stats.source_bytes,
    }
    failures = []

    def maximum(label, actual, key):
        if actual > config[key]:
            failures.append("{0} exceeds {1}".format(label, key))

    def minimum(label, actual, key):
        if actual < config[key]:
            failures.append("{0} below {1}".format(label, key))

    config.setdefault('minimum_pattern_rules', config.get('minimum_v1_rules', 0))
    minimum("Pattern Rule count", rule_audit["pattern_rules"], "minimum_pattern_rules")
    minimum("v2 rule count", rule_audit["v2_rules"], "minimum_v2_rules")
    maximum("rule errors", rule_audit["errors"], "maximum_rule_errors")
    maximum("compile elapsed time", rule_audit["elapsed_ms"], "maximum_compile_elapsed_ms")
    maximum("compile peak memory", rule_audit["peak_memory_bytes"], "maximum_compile_peak_memory_bytes")
    maximum("corpus elapsed time", corpus.metrics["elapsed_ms"], "maximum_corpus_elapsed_ms")
    maximum("corpus peak case memory", corpus.metrics["peak_case_memory_bytes"], "maximum_corpus_peak_case_memory_bytes")
    minimum("corpus precision", corpus.metrics["precision"], "minimum_corpus_precision")
    minimum("corpus recall", corpus.metrics["recall"], "minimum_corpus_recall")
    minimum("corpus F1", corpus.metrics["f1"], "minimum_corpus_f1")
    minimum("incremental cache hits", cache_measurement["hits"], "minimum_incremental_cache_hits")
    failures.extend(corpus.gate_failures)
    coverage = audit_coverage(root)
    failures.extend(coverage["failures"])
    return {
        "passed": not failures,
        "failures": failures,
        "rule_audit": rule_audit,
        "coverage": coverage,
        "corpus": corpus.as_dict(),
        "incremental_cache": cache_measurement,
    }
