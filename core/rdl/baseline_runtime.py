"""Run selected native v2 baseline packs and persist like-for-like decisions."""
import json
from pathlib import Path
from utils.source_cache import read_source_text, source_stat
from utils.scan_scope import allows_check

from .compiler import compile_rdl
from .scratch import DiskIndex
from .result_store import ResultStorageError
from .explanation import explain_result
from .executor import SemanticExecutor


class BaselineRunner:
    def __init__(self, root):
        self.root = Path(root)
        payload = json.loads((self.root / 'config/rdl_baseline.json').read_text())
        self.packs = {}
        additional = json.loads((self.root / 'config/rdl_additional.json').read_text())
        for entry in payload['entries'] + additional['entries']:
            self.packs.setdefault(entry['xml_pack'], []).append(entry)
        self.overlays = {}
        overlay_config = json.loads((self.root / 'config/rdl_platform_overlays.json').read_text())
        for overlay in overlay_config['entries']:
            if overlay['source_pack'] not in self.packs or overlay['target_pack'] not in self.packs:
                raise ValueError('Mobile overlay references an unregistered native pack')
            self.overlays.setdefault(overlay['source_pack'], []).append(overlay)
        self.documents = {}
        self.sources = {}
        self.seen = DiskIndex()
        self.review_views = None
        self.executor = SemanticExecutor()

    def review(self, pack, files, project_root, telemetry, include_v1, progress=None):
        # Traverse selected pack overlays once. Shared mobile/native files still
        # use the per-pack/file identity below, so auto selection cannot duplicate work.
        import fnmatch
        pending = [(Path(pack).resolve().relative_to(self.root.resolve()).as_posix(), list(files))]
        visited = set()
        while pending:
            pack_key, selected = pending.pop(0)
            identity = (pack_key, tuple(map(str, selected)))
            if identity in visited:
                continue
            visited.add(identity)
            self._review_pack(self.root / pack_key, selected, project_root, telemetry, include_v1, progress)
            for overlay in self.overlays.get(pack_key, []):
                targets = [path for path in selected if any(fnmatch.fnmatch(Path(path).name, pattern)
                           for pattern in overlay['patterns'])]
                if targets:
                    pending.append((overlay['target_pack'], targets))

    def _review_pack(self, pack, files, project_root, telemetry, include_v1, progress=None):
        from .shadow import append_shadow_record, shadow_record_batch
        pack_key = Path(pack).resolve().relative_to(self.root.resolve()).as_posix()
        entries = [entry for entry in self.packs.get(pack_key, []) if allows_check(entry.get('title', ''), entry.get('category', ''), entry.get('rule_id', ''))]
        with shadow_record_batch(telemetry):
            for index, file in enumerate(files, 1):
                path = Path(file)
                identity = (str(telemetry), pack_key, str(path))
                if identity in self.seen:
                    continue
                self.seen.add(identity)
                if callable(progress):
                    progress(dict(scope='source_parser', platform=Path(pack).stem.upper(), category='RDL v2 baseline',
                                  rule_title='Native v2 rule comparison', file_index=index, filepath=str(path),
                                  status='parsing', total_items=len(files), matched_evidence_count=0))
                try:
                    if not entries:
                        continue
                    path_rule = entries[0]['path_rule']
                    if path_rule:
                        try:
                            relative = path.resolve().relative_to(Path(project_root).resolve()).as_posix()
                        except ValueError:
                            relative = path.as_posix()
                        target = '/' + relative.lstrip('/')
                        content = target
                    else:
                        target = str(path)
                        from utils.file_utils import detect_encoding_type, readfile_FallbackEncoding
                        if source_stat(path).st_size > 4 * 1024 * 1024:
                            raise ValueError('baseline input exceeds 4 MiB budget')
                        try:
                            content = read_source_text(path, encoding=detect_encoding_type(path) or 'utf-8')
                        except (UnicodeError, LookupError):
                            # An ASCII prefix does not establish the encoding of the
                            # whole file. Retry without skipping every rule for it.
                            with readfile_FallbackEncoding(path) as source:
                                content = source.read()
                    with shadow_record_batch(telemetry):
                        for entry in entries:
                            record = self.evaluate(entry, target, content, project_root, include_v1, refine=True, source_path=str(path))
                            append_shadow_record(telemetry, record, dict(file_path=str(path), rule_title=entry['title'],
                                logic_ref=entry['v1_ref'] or entry['xml_pack'] + '#' + entry['title'],
                                xml_pack=pack_key, review_scope='native v2 source review; raw predicate outcome retained separately, not full scanner triage'))
                except ResultStorageError:
                    raise
                except Exception as exc:
                    append_shadow_record(telemetry, dict(mode='baseline', comparison_kind='baseline',
                        v1_outcome='NOT_RUN', v2_outcome='INDETERMINATE', status='INDETERMINATE',
                        v2_errors=[str(exc)], affects_finding=False),
                        dict(file_path=str(path), rule_title='Baseline coverage: '+pack_key))

    def evaluate(self, entry, target, content, project_root, include_v1, refine=False, source_path=None):
        relative = entry['v2_rule']
        if relative not in self.documents:
            self.documents[relative] = compile_rdl(read_source_text(self.root / relative), relative)
        document = self.documents[relative]
        result = self.executor.execute(document, target, 'text', project_root=project_root, file_text=content)
        baseline_outcome = result.outcome.value
        review_notes, guidance = (), None
        # Source refinements must not bypass compile-time validation or regex
        # work limits by turning an invalid property's error into a match.
        if refine and document.valid:
            from .source_review import source_views, review_source
            if entry['path_rule']:
                views = (content, content)
            else:
                if self.review_views is None or self.review_views[:2] != (target, content):
                    self.review_views = (target, content, source_views(target, content))
                views = self.review_views[2]
            result, review_notes, guidance = review_source(entry, document, result, target, content, project_root, views)
        legacy_outcome = 'NOT_RUN'
        additional = entry['source_kind'] == 'v2_additional'
        if additional:
            legacy_outcome = 'NOT_APPLICABLE'
        if include_v1 and not additional:
            if entry['v1_ref']:
                reference = entry['v1_ref']
                if reference not in self.sources:
                    self.sources[reference] = read_source_text(self.root/'rules/scanning'/reference)
                from core.rdl_engine import evaluate_rdl_with_reason
                old = evaluate_rdl_with_reason(self.sources[reference], file_text=content, file_path=target, project_root=str(project_root))
                legacy_outcome = 'MATCH' if old['passes'] else 'NO_MATCH'
            else:
                # Existing XML-only rules have no RDL gate; compare their pattern
                # decision explicitly, rather than claiming a legacy RDL result.
                import re
                regex = re.compile(entry['pattern'])
                exclude = re.compile(entry['exclude'], re.I) if entry['exclude'] else None
                hit = any(regex.search(line) and not (exclude and exclude.search(line)) for line in content.splitlines())
                legacy_outcome = 'MATCH' if hit else 'NO_MATCH'
        status = result.outcome.value
        if status in {'MATCH','NO_MATCH'}:
            status = ('AGREEMENT' if legacy_outcome == status else 'DISAGREEMENT') if include_v1 else 'V2_ONLY'
        if additional and result.outcome.value in {'MATCH', 'NO_MATCH'}:
            status = 'V2_ADDITIONAL'
        explanation = explain_result(document, result)
        if guidance:
            from .explanation import format_issue_title
            explanation['v2_title'] = format_issue_title(guidance[0])
        if review_notes:
            explanation['v2_explanation'] += ' ' + ' '.join(review_notes)
        # Keep rule-specific review guidance alongside native text evidence.
        for finding in explanation.get('v2_findings', []):
            finding['cwe'] = entry.get('cwe') or finding['cwe']
            finding['description'] = entry.get('description') or finding['description']
            finding['impact'] = entry.get('impact') or finding['impact']
            finding['remediation'] = entry.get('remediation') or entry.get('reviewer') or finding['remediation']
            finding['review_area'] = entry.get('review_area') or entry.get('category', '')
            if guidance:
                finding.update(title=explanation['v2_title'], description=guidance[1], reviewer_note=guidance[2])
            if entry['path_rule']:
                finding['path_only'] = True
                finding['path'] = source_path or target
                finding['confidence_reason'] = 'Filename/path review only; no source operation or vulnerable execution is established.'
                finding['trace']['review_note'] = 'Matched path: ' + (source_path or target) + '. No source line applies to a path-only check.'
        from .assessment import classify_record
        assessment = classify_record(dict(v2_outcome=result.outcome.value, **explanation))
        if result.outcome.value == 'NO_MATCH' and assessment != 'mitigated':
            # Negative baselines dominate large scans. Keep decisions and explanations,
            # but avoid duplicating non-finding evidence/snippets in bounded telemetry.
            explanation.pop('v2_evidence', None)
            explanation.pop('v2_limitations', None)
        return dict(mode='baseline', comparison_kind='supplemental' if additional else 'baseline', authoritative_engine='v1' if include_v1 else 'v2',
            affects_finding=False, v1_outcome=legacy_outcome, v2_outcome=result.outcome.value,
            status=status, v2_rule=relative, v2_rule_id=result.rule_id, language=entry['scope'].split('/')[0],
            v2_baseline_outcome=baseline_outcome, v2_refinements=list(review_notes),
            v2_errors=list(result.errors), **explanation)
