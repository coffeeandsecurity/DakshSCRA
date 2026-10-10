"""Fail-isolated v1/v2 shadow comparison for controlled production rollout."""

import json
import os
import tempfile
import zlib
import weakref
from contextlib import contextmanager
from contextvars import ContextVar
from collections import OrderedDict
from pathlib import Path
from utils.source_cache import read_source_text, source_stat

from utils.scan_scope import allows_check
from utils.scan_progress import scan_operation
from .compiler import compile_rdl
from .executor import ExecutionOutcome, ExecutionResult, SemanticExecutor
from .explanation import explain_result, format_issue_title
from .cache import AnalysisBudgetExceeded
from .scratch import DiskIndex
from .result_store import ResultStorageError
from .plan import Capability
from .project import python_dependency_scope, php_dependency_scope, portable_dependency_scope
from .portable_profiles import EXTENSIONS, project_mappings


_TRUE = {"1", "true", "yes", "on"}


class ShadowRunner:
    def __init__(self, repository_root, config_path=None, enabled=None, executor=None, config=None):
        self.root = Path(repository_root)
        self.config_path = Path(config_path or self.root / "config" / "rdl_shadow.json")
        self.config = dict(config) if config is not None else self._load_config(self.config_path)
        self.project_mappings = project_mappings() if self.config.get("project_flow", False) else {}
        self.enabled_override = enabled
        self.v1_enabled = True
        self.executor = executor or SemanticExecutor()
        self._documents = {}
        self._results = OrderedDict()
        self._reviewed = DiskIndex()
        self._review_index = DiskIndex()
        self._review_store = None

    def review_pack_once(self, pack, files, project_root, telemetry_path, progress=None):
        if not self.enabled:
            return
        try:
            if not hasattr(self, '_baseline'):
                from .baseline_runtime import BaselineRunner
                self._baseline = BaselineRunner(self.root)
            self._baseline.review(pack, files, project_root, telemetry_path, self.v1_enabled, progress)
        except ResultStorageError:
            raise
        except Exception as exc:
            append_shadow_record(telemetry_path, self._error_comparison(None, None, exc),
                                 dict(rule_title='Baseline configuration', file_path=str(pack)))

    def review_file_once(self, file_path, project_root, telemetry_path, progress_callback=None):
        """Review all configured properties, independent of framework selection."""
        if not self.enabled:
            return
        path = Path(file_path)
        identity = (str(telemetry_path), str(path))
        if identity in self._reviewed:
            return
        try:
            mappings = self.config.get('mappings')
            if not isinstance(mappings, dict):
                raise ValueError('shadow mappings must be an object')
            relevant = [(reference, mapping) for reference, mapping in dict(mappings, **self.project_mappings).items()
                        if isinstance(mapping, dict) and isinstance(mapping.get('extensions'), list)
                        and path.suffix.lower() in mapping['extensions']
                        and allows_check(Path(mapping['v2_rule']).stem.replace('_', ' '), rule_id=reference)]
            self._reviewed.add(identity)
            if getattr(self, 'custom_runner', None):
                self.custom_runner.review(path, project_root, telemetry_path)
            if not relevant:
                return
            from core.rdl_engine import evaluate_rdl_with_reason
            source = read_source_text(path, encoding='utf-8') if self.v1_enabled else None
            recorded_properties = set()
            dependency_scopes = {}
            with shadow_record_batch(telemetry_path), self.executor.cache.review_snapshot():
                for review_index, (reference, mapping) in enumerate(relevant, 1):
                    try:
                        with scan_operation(
                            progress_callback, phase='semantic_review',
                            message='Reviewing semantic rule {0} of {1}'.format(review_index, len(relevant)),
                            current_function=mapping.get('v2_rule', reference),
                            operation_index=review_index, operation_total=len(relevant),
                        ):
                            legacy = None
                            if self.v1_enabled and not mapping.get('semantic_only'):
                                legacy_source = read_source_text(self.root / 'rules/scanning' / reference, encoding='utf-8')
                                legacy = evaluate_rdl_with_reason(legacy_source, file_text=source, file_path=str(path), project_root=str(project_root))
                            comparison = self.compare(legacy, reference, path, project_root, _dependency_scopes=dependency_scopes)
                    except ResultStorageError:
                        raise
                    except Exception as exc:
                        comparison = self._error_comparison(None, mapping, exc)
                    self._store_review_comparison(telemetry_path, path, comparison)
                    property_key = (comparison.get('v2_rule'), comparison.get('v2_outcome'))
                    # Repeated framework gates share one property/file payload. The first
                    # record owns its evidence; later records retain each distinct v1 decision.
                    telemetry = comparison
                    if property_key in recorded_properties:
                        telemetry = {key: value for key, value in comparison.items()
                                     if key not in {'v2_findings', 'v2_evidence', 'v2_limitations'}}
                    recorded = append_shadow_record(telemetry_path, telemetry,
                        dict(logic_ref=reference, file_path=str(path), rule_title=reference.rsplit('/', 1)[-1],
                             review_scope='all reviewed mappings for scanned file; v1 outcome is the logic gate, not the complete scanner verdict'),
                        self.config.get('maximum_telemetry_bytes', 64 * 1024 * 1024))
                    if recorded:
                        recorded_properties.add(property_key)
        except ResultStorageError:
            raise
        except Exception as exc:
            append_shadow_record(telemetry_path, self._error_comparison(None, None, exc),
                                 dict(file_path=str(path), rule_title='Property coverage'))

    def _review_key(self, telemetry_path, file_path, mapping):
        return (str(telemetry_path), str(file_path), mapping.get('v2_rule'), mapping.get('language'))

    def _store_review_comparison(self, telemetry_path, file_path, comparison):
        if not comparison or comparison.get('v2_outcome') == 'SHADOW_ERROR':
            return
        key = self._review_key(telemetry_path, file_path, comparison)
        if key in self._review_index:
            return
        try:
            encoded = zlib.compress(json.dumps(comparison).encode('utf-8'))
            if self._review_store is None:
                self._review_store = tempfile.TemporaryFile()
                weakref.finalize(self, self._review_store.close)
            self._review_store.seek(0, os.SEEK_END)
            offset = self._review_store.tell()
            self._review_store.write(encoded)
            self._review_index[key] = (offset, len(encoded))
        except (OSError, TypeError, ValueError):
            return

    def comparison_for_review(self, v1_result, logic_ref, file_path, project_root, telemetry_path):
        """Attach this scan's existing semantic review to later v1 rule passes.

        The full evidence and index are retained on disk, so the small
        execution LRU cannot cause each later rule pass to repeat project analysis.
        Standalone compare() and a new telemetry destination still review afresh.
        """
        if not self.enabled:
            return None
        mappings = self.config.get('mappings')
        if isinstance(logic_ref, str) and logic_ref.startswith('rdl/logic/v1/') and logic_ref not in (mappings or {}):
            logic_ref = 'logic/rdl/v1/' + logic_ref[len('rdl/logic/v1/'):]
        elif isinstance(logic_ref, str) and logic_ref.startswith('logic/') and not logic_ref.startswith('logic/rdl/') and logic_ref not in (mappings or {}):
            logic_ref = 'logic/rdl/v1/' + logic_ref[len('logic/'):]
        mapping = mappings.get(logic_ref) if isinstance(mappings, dict) else None
        if not isinstance(mapping, dict):
            return self.compare(v1_result, logic_ref, file_path, project_root)
        location = self._review_index.get(self._review_key(telemetry_path, file_path, mapping))
        if location is not None:
            try:
                self._review_store.seek(location[0])
                comparison = json.loads(zlib.decompress(self._review_store.read(location[1])))
                comparison.update(self._comparison_base(v1_result, mapping))
                comparison['v1_reason'] = (v1_result or {}).get('reason' if (v1_result or {}).get('passes') else 'fail_reason') or ''
                comparison['v1_trace'] = (v1_result or {}).get('trace') or []
                outcome = comparison['v2_outcome']
                comparison['status'] = outcome if outcome in {'INDETERMINATE', 'RULE_ERROR'} else (
                    'V2_ONLY' if not self.v1_enabled else
                    'AGREEMENT' if outcome == comparison['v1_outcome'] else 'DISAGREEMENT')
                return comparison
            except (OSError, ValueError, zlib.error):
                pass
        return self.compare(v1_result, logic_ref, file_path, project_root)

    @staticmethod
    def _load_config(path):
        payload = json.loads(read_source_text(path, encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise ValueError("unsupported RDL shadow configuration schema")
        if payload.get("authoritative_engine") != "v1":
            raise ValueError("shadow rollout requires v1 as the authoritative engine")
        if not isinstance(payload.get("mappings"), dict):
            raise ValueError("shadow rollout requires a mappings object")
        return payload

    @property
    def enabled(self):
        if self.enabled_override is not None:
            return bool(self.enabled_override)
        environment = os.environ.get("DAKSH_RDL_V2_SHADOW")
        if environment is not None:
            return environment.strip().lower() in _TRUE
        return bool(self.config.get("enabled"))

    def compare(self, v1_result, logic_ref, file_path, project_root=None, *, _dependency_scopes=None):
        if not self.enabled:
            return None
        mappings = self.config.get("mappings")
        if not isinstance(mappings, dict):
            return self._error_comparison(v1_result, None, ValueError("shadow mappings must be an object"))
        if isinstance(logic_ref, str) and logic_ref.startswith('rdl/logic/v1/') and logic_ref not in mappings:
            logic_ref = 'logic/rdl/v1/' + logic_ref[len('rdl/logic/v1/'):]
        elif isinstance(logic_ref, str) and logic_ref.startswith('logic/') and not logic_ref.startswith('logic/rdl/') and logic_ref not in mappings:
            logic_ref = 'logic/rdl/v1/' + logic_ref[len('logic/'):]
        mapping = mappings.get(logic_ref) or self.project_mappings.get(logic_ref)
        if mapping is None or not allows_check(Path(mapping["v2_rule"]).stem.replace("_", " "), rule_id=logic_ref):
            return None
        try:
            if not isinstance(mapping, dict):
                raise ValueError("shadow mapping must be an object")
            v2_rule = mapping.get("v2_rule")
            language = mapping.get("language")
            if not isinstance(v2_rule, str) or not v2_rule.strip():
                raise ValueError("shadow mapping requires a non-empty v2_rule")
            if not isinstance(language, str) or not language.strip():
                raise ValueError("shadow mapping requires a non-empty language")
            extensions_value = mapping.get("extensions", ())
            if not isinstance(extensions_value, (list, tuple)) or not all(
                isinstance(item, str) for item in extensions_value
            ):
                raise ValueError("shadow mapping extensions must be a list of strings")
            path = Path(file_path)
            extensions = tuple(item.lower() for item in extensions_value)
            if extensions and path.suffix.lower() not in extensions:
                return None
            comparison = self._comparison_base(v1_result, mapping)
            document = self._document(v2_rule)
            stat = source_stat(path)
            rule_stat = source_stat(self.root / v2_rule)
            source_paths, dependency_key, scope_error = None, (), None
            if language in set(EXTENSIONS) | {'python', 'php'} and project_root and document.execution_plan and Capability.DATA_FLOW in document.execution_plan.capabilities:
                # Share a scope only within this file's review batch. A later
                # review resolves it afresh so changed/new helpers invalidate results.
                scopes = _dependency_scopes if _dependency_scopes is not None else {}
                scope_identity = (language, str(path), str(project_root))
                if scope_identity not in scopes:
                    try:
                        if language in EXTENSIONS:
                            source_paths, dependency_key = portable_dependency_scope(path, project_root, language)
                        else:
                            scope = php_dependency_scope if language == 'php' else python_dependency_scope
                            source_paths, dependency_key = scope(path, project_root)
                    except AnalysisBudgetExceeded as exc:
                        scope_error = str(exc)
                    scopes[scope_identity] = (source_paths, dependency_key, scope_error)
                source_paths, dependency_key, scope_error = scopes[scope_identity]
            identity = (str(path), stat.st_mtime_ns, stat.st_size, v2_rule, rule_stat.st_mtime_ns, language, dependency_key, scope_error)
            cached = self._results.pop(identity, None)
            if cached is None:
                if scope_error:
                    result = ExecutionResult(ExecutionOutcome.INDETERMINATE, document.execution_plan.rule_id, (), errors=(scope_error,))
                elif source_paths and len(source_paths) > 1:
                    result = self.executor.execute(document, path.resolve(), language, source_paths=source_paths, project_root=project_root)
                else:
                    result = self.executor.execute(document, path, language)
                explanation = explain_result(document, result)
                cached = (result, explanation)
            result, explanation = cached
            self._results[identity] = cached
            while len(self._results) > 128:
                self._results.popitem(last=False)
            comparison["v2_outcome"] = result.outcome.value
            comparison["v2_rule_id"] = result.rule_id
            comparison["v2_unavailable_capabilities"] = list(result.unavailable_capabilities)
            comparison["v2_errors"] = list(result.errors)
            comparison.update(explanation)
            comparison['v2_analyzed_files'] = [str(item) for item in source_paths] if source_paths else [str(path)]
            comparison['v2_scope'] = ('entry-file sources and resolved local PHP dependencies' if language == 'php' else 'entry-file sources and explicit local Python imports' if language == 'python' else 'entry-file sources and bounded project call resolution') if source_paths and len(source_paths) > 1 else 'single file'
            if scope_error:
                comparison['v2_analyzed_files'] = []
                comparison['v2_scope'] = 'Project source scope unavailable; semantic evaluation is indeterminate: '+scope_error
            elif language in {'java', 'kotlin'} and source_paths:
                from .project import _portable_source_context
                source_context = _portable_source_context(path, language)
                comparison['v2_source_context'] = source_context
                comparison['v2_scope'] += '; source context: '+source_context
                if source_context == 'production':
                    comparison['v2_scope'] += ' (test/fixture source sets excluded; unresolved build variants remain review limits)'
                elif source_context == 'tests':
                    comparison['v2_scope'] += ' (test behavior does not establish a shipped vulnerability)' 
            comparison['v1_reason'] = (v1_result or {}).get('reason' if (v1_result or {}).get('passes') else 'fail_reason') or ''
            comparison['v1_trace'] = (v1_result or {}).get('trace') or []
            if result.outcome in {ExecutionOutcome.INDETERMINATE, ExecutionOutcome.RULE_ERROR}:
                comparison["status"] = result.outcome.value
            else:
                comparison["status"] = (
                    "V2_ONLY" if not self.v1_enabled or mapping.get("semantic_only") else
                    "AGREEMENT" if result.outcome.value == comparison["v1_outcome"] else "DISAGREEMENT"
                )
        except Exception as exc:
            comparison = self._error_comparison(v1_result, mapping, exc)
        return comparison

    def _comparison_base(self, v1_result, mapping):
        safe_mapping = mapping if isinstance(mapping, dict) else {}
        compare_legacy = self.v1_enabled and not safe_mapping.get("semantic_only")
        return {
            "mode": "shadow" if compare_legacy else "v2",
            "comparison_kind": "semantic",
            "authoritative_engine": "v1" if compare_legacy else "v2",
            "v1_outcome": ("MATCH" if bool((v1_result or {}).get("passes")) else "NO_MATCH") if compare_legacy else "NOT_RUN",
            "v2_rule": safe_mapping.get("v2_rule"),
            "language": safe_mapping.get("language"),
            "affects_finding": False,
        }

    def _error_comparison(self, v1_result, mapping, exc):
        comparison = self._comparison_base(v1_result, mapping)
        comparison["v2_outcome"] = "SHADOW_ERROR"
        comparison["v2_errors"] = ["{0}: {1}".format(type(exc).__name__, exc)]
        comparison["status"] = "SHADOW_ERROR"
        return comparison

    def _document(self, relative_path):
        path = self.root / relative_path
        try:
            stat = source_stat(path)
            identity = (path.as_posix(), stat.st_mtime_ns, stat.st_size)
        except OSError:
            identity = (path.as_posix(), 0, 0)
        cached = self._documents.get(identity)
        if cached is not None:
            return cached
        document = compile_rdl(read_source_text(path, encoding="utf-8"), str(path))
        if len(self._documents) >= 64:
            self._documents.pop(next(iter(self._documents)))
        self._documents[identity] = document
        return document


_DEFAULT_RUNNER = None


def default_shadow_runner(repository_root):
    global _DEFAULT_RUNNER
    root = Path(repository_root).resolve()
    if _DEFAULT_RUNNER is None or _DEFAULT_RUNNER.root.resolve() != root:
        try:
            _DEFAULT_RUNNER = ShadowRunner(root)
        except (OSError, ValueError, json.JSONDecodeError):
            _DEFAULT_RUNNER = ShadowRunner(
                root,
                enabled=False,
                config={"schema_version": 1, "enabled": False, "authoritative_engine": "v1", "mappings": {}},
            )
    return _DEFAULT_RUNNER


_STORAGE_FAILURES = {}


_BATCH_WRITERS = ContextVar('rdl_result_writers', default={})


@contextmanager
def shadow_record_batch(path):
    """Keep a pack's writer open and flush each nested file at its boundary."""
    from .result_store import ResultWriter
    key = str(path)
    active = _BATCH_WRITERS.get()
    owner = key not in active
    writer = ResultWriter(path) if owner else active[key]
    token = _BATCH_WRITERS.set(dict(active, **{key: writer}))
    try:
        yield writer
    finally:
        try:
            if owner:
                writer.close()
            elif not writer.failed:
                writer.flush()
        except ResultStorageError as exc:
            _STORAGE_FAILURES[key] = str(exc)
            Path(path).with_suffix('.storage-error').write_text(str(exc), encoding='utf-8')
            raise
        finally:
            _BATCH_WRITERS.reset(token)


def append_shadow_record(path, comparison, context=None, max_bytes=None):
    """Persist a complete evaluation; max_bytes is accepted for old callers only."""
    if not comparison:
        return False
    from .result_store import ResultStore, ResultStorageError
    record = dict(comparison, context=dict(context or {}))
    if os.environ.get("DAKSH_RDL_RESULT_RETENTION") == "review":
        from .retention import review_record
        record = review_record(record)
        if record is None:
            return False
    try:
        writer = _BATCH_WRITERS.get().get(str(path))
        if writer is None:
            ResultStore(path).append(record)
        else:
            writer.append(record)
        return True
    except ResultStorageError as exc:
        _STORAGE_FAILURES[str(path)] = str(exc)
        try:
            Path(path).with_suffix('.storage-error').write_text(str(exc), encoding='utf-8')
        except OSError:
            pass
        raise


def iter_shadow_records(path):
    """Stream complete original records for export and repository consumers."""
    from .result_store import ResultStore
    yield from ResultStore(path).iter_records()


def summarize_shadow_records(path):
    from .result_store import ResultStorageError
    if str(path) in _STORAGE_FAILURES:
        raise ResultStorageError(_STORAGE_FAILURES[str(path)])
    if Path(path).with_suffix('.storage-error').exists():
        raise ResultStorageError('This scan could not persist all results; see the storage error record')
    return read_shadow_results(path, limit=0)['summary']


def comparison_priority(record):
    if record.get('status') == 'DISAGREEMENT':
        return 0
    if record.get('v2_outcome') == 'MATCH':
        return 1
    if record.get('status') in {'INDETERMINATE', 'RULE_ERROR', 'SHADOW_ERROR'}:
        return 2
    return 3


def read_shadow_results(path, limit=500, offset=0, view='all', search='', kind='all', section='all', after=None):
    """Query indexed decisions, decoding only the requested result page."""
    from .result_store import ResultStore
    data = ResultStore(path).read(limit=limit,offset=offset,view=view,search=search,kind=kind,section=section,after=after)
    records = data['comparisons']
    _refresh_presentation(records)
    data['summary']['storage_error'] = Path(path).with_suffix('.storage-error').exists()
    return data


def _refresh_presentation(records):
    from .trace import build_trace
    from .narratives import refresh_record
    for record in records:
        refresh_record(record)
        if record.get('v2_title'):
            record['v2_title'] = format_issue_title(record['v2_title'])
        for finding in record.get('v2_findings') or []:
            if finding.get('title'):
                finding['title'] = format_issue_title(finding['title'])
            # Refresh presentation for older scans without changing recorded evidence.
            if finding.get('evidence') or not finding.get('trace'):
                finding['trace'] = build_trace(finding.get('evidence') or [], finding.get('cwe', ''))
            if finding.get('path_only') or str(record.get('v2_rule_id', '')).startswith('baseline.filepaths.'):
                finding['path_only'] = True
                finding['path'] = finding.get('path') or (record.get('context') or {}).get('file_path', '')
                finding['trace']['review_note'] = 'Matched path: ' + finding['path'] + '. No source line applies to a path-only check.'


def iter_shadow_results(path):
    from .result_store import ResultStore
    for record in ResultStore(path).iter_groups():
        _refresh_presentation([record])
        yield record


def export_shadow_records(path, destination):
    """Stream every original evaluation into a portable compressed JSONL file."""
    import gzip
    import os
    import tempfile
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
        with gzip.open(temporary, 'wt', encoding='utf-8') as handle:
            for record in iter_shadow_records(path):
                handle.write(json.dumps(record, ensure_ascii=False) + '\n')
        os.replace(temporary,destination)
        return destination
    finally:
        if temporary is not None and temporary.exists(): temporary.unlink()
