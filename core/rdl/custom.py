"""Explicit, per-scan RDL packs; no application code or plugin execution."""
import fnmatch
import hashlib
import json
from pathlib import Path

from utils.source_cache import read_source_text
from utils.scan_scope import allows_check, allows_file
from .compiler import compile_rdl
from .executor import SemanticExecutor, ExecutionResult, ExecutionOutcome
from .cache import AnalysisBudgetExceeded
from .explanation import explain_result
from .plan import Capability
from .portable_profiles import EXTENSIONS


def load_custom_packs(paths):
    """Validate all definitions up front; invalid packs fail the scan visibly."""
    rules, ids = [], set()
    if len(paths) > 8:
        raise ValueError('At most 8 custom RDL packs may be selected')
    for name in paths:
        manifest = Path(name).expanduser().resolve(strict=True)
        if manifest.stat().st_size > 1024 * 1024:
            raise ValueError('Custom RDL manifest exceeds 1 MiB')
        payload = json.loads(manifest.read_text(encoding='utf-8'))
        if not isinstance(payload, dict) or payload.get('schema_version') != 1 or not isinstance(payload.get('rules'), list) or not payload['rules']:
            raise ValueError('Custom RDL pack requires schema_version 1 and a non-empty rules list')
        for entry in payload['rules']:
            if not isinstance(entry, dict):
                raise ValueError('Custom RDL rule must be an object')
            rule_path = (manifest.parent / entry['path']).resolve(strict=True)
            if manifest.parent not in rule_path.parents or rule_path.suffix != '.rdl':
                raise ValueError('Custom definitions must be .rdl files within the pack directory')
            if rule_path.stat().st_size > 256 * 1024:
                raise ValueError('Custom RDL definition exceeds 256 KiB')
            source = rule_path.read_text(encoding='utf-8')
            document = compile_rdl(source, str(rule_path))
            if not hasattr(document, 'execution_plan') or not document.valid or document.execution_plan is None:
                raise ValueError('Invalid custom RDL definition: ' + str(rule_path) + ': ' + str(document.diagnostics))
            rule_id = document.execution_plan.rule_id
            if not rule_id.startswith('custom.') or rule_id in ids:
                raise ValueError('Custom rule IDs must be unique and start with custom.')
            language = entry.get('language', 'text')
            if language not in set(EXTENSIONS) | {'text', 'python', 'php'}:
                raise ValueError('Unsupported custom RDL language: ' + str(language))
            if language == 'text' and document.execution_plan.capabilities - {Capability.TEXT, Capability.PATH, Capability.PROJECT}:
                raise ValueError('Semantic custom RDL requires an executable language')
            patterns = entry.get('file_globs', ['*'])
            if not isinstance(patterns, list) or not patterns or len(patterns) > 32 or not all(isinstance(p, str) and p for p in patterns):
                raise ValueError('Custom RDL requires 1-32 non-empty file_globs')
            file_types = entry.get('file_types', [])
            if not isinstance(file_types, list) or len(file_types) > 32 or not all(
                isinstance(item, str) and item.lstrip('.').isalnum() for item in file_types
            ):
                raise ValueError('file_types must be a list of at most 32 extensions, such as .js or java')
            file_types = list(dict.fromkeys('.' + item.lstrip('.').lower() for item in file_types))
            if entry.get('source_view', 'comments') not in {'comments', 'code', 'raw'}:
                raise ValueError('source_view must be comments, code, or raw')
            for field in ('description', 'impact', 'remediation'):
                if not isinstance(entry.get(field), str) or not entry[field].strip():
                    raise ValueError('Custom RDL requires ' + field)
            ids.add(rule_id)
            rules.append(dict(entry, file_globs=patterns, file_types=file_types, document=document, language=language, rule_id=rule_id,
                              rule_path=str(rule_path), pack=str(manifest),
                              sha256=hashlib.sha256(source.encode('utf-8')).hexdigest()))
            if len(rules) > 128:
                raise ValueError('At most 128 custom RDL definitions may be selected')
    return rules


class CustomRuleRunner:
    def __init__(self, paths):
        self.rules = load_custom_packs(paths)
        self.executor = SemanticExecutor()

    def execute(self, entry, path, project_root):
        from .source_review import source_views
        from .text import execute_text
        document, language = entry['document'], entry['language']
        try:
            if language == 'text':
                if path.stat().st_size > 4 * 1024 * 1024:
                    raise AnalysisBudgetExceeded('Custom text input exceeds 4 MiB')
                content = read_source_text(path)
                comments, code = source_views(path, content)
                view = {'comments': comments, 'code': code, 'raw': content}[entry.get('source_view', 'comments')]
                return execute_text(document, path, project_root, file_text=view, collect_matches=True)
            from .project import portable_dependency_scope, python_dependency_scope, php_dependency_scope
            scope = (python_dependency_scope if language == 'python' else
                     php_dependency_scope if language == 'php' else
                     lambda p, root: portable_dependency_scope(p, root, language))
            sources, _ = scope(path, project_root)
            return self.executor.execute(document, path, language, source_paths=sources, project_root=project_root)
        except (OSError, UnicodeError, ValueError, AnalysisBudgetExceeded) as exc:
            return ExecutionResult(ExecutionOutcome.INDETERMINATE, entry['rule_id'], (), errors=(str(exc),))

    def review(self, path, project_root, telemetry):
        from .shadow import append_shadow_record, shadow_record_batch
        path = Path(path)
        if not allows_file(path):
            return
        relative = path.resolve().relative_to(Path(project_root).resolve()).as_posix()
        with shadow_record_batch(telemetry):
            for entry in self.rules:
                if not allows_check(rule_id=entry["rule_id"]):
                    continue
                if not any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern)
                           for pattern in entry['file_globs']):
                    continue
                if entry['file_types'] and path.suffix.lower() not in entry['file_types']:
                    continue
                document = entry['document']
                language = entry['language']
                result = self.execute(entry, path, project_root)
                explanation = explain_result(document, result)
                for finding in explanation.get('v2_findings', []):
                    finding.update({key: entry[key] for key in ('description', 'impact', 'remediation')})
                    finding['cwe'] = entry.get('cwe', '')
                append_shadow_record(telemetry, dict(mode='custom', comparison_kind='custom',
                    status='V2_CUSTOM', v1_outcome='NOT_APPLICABLE', v2_outcome=result.outcome.value,
                    v2_rule=entry['rule_path'], v2_rule_id=entry['rule_id'], language=language,
                    v2_errors=list(result.errors), affects_finding=False, **explanation),
                    dict(file_path=str(path), rule_title=document.execution_plan.report_title,
                         custom_pack=entry['pack'], custom_rule_sha256=entry['sha256'],
                         review_scope='Optional application-specific RDL; a property match is not exploit proof'))
