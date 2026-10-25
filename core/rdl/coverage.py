"""Reproducible inventory, dispatch, and paired-source coverage audit."""
import fnmatch
import json
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from core.pattern_rules import resolve_pack
from .baseline import inventory
from .baseline_runtime import BaselineRunner


def registered_packs(root):
    root = Path(root)
    platforms, packs = {}, {}
    for item in ET.parse(root / 'rules/scanning/rulesconfig.xml').getroot():
        platform = item.findtext('platform')
        path = 'rules/scanning/platform/' + item.findtext('path').lstrip('/')
        patterns = [p.strip() for p in item.findtext('platform_ftypes', '').split(',') if p.strip()]
        platforms[platform] = dict(pack=path, patterns=patterns)
        packs[path] = dict(platform=platform, patterns=patterns, framework_patterns=[])
    for item in ET.parse(root / 'rules/scanning/frameworkconfig.xml').getroot():
        platform = item.findtext('platform')
        parent = Path(platforms[platform]['pack']).parent
        path = parent / 'framework' / item.findtext('rule_file')
        if not resolve_pack(root / path).exists():
            path = parent / item.findtext('rule_file')
        key = path.as_posix()
        filters = [p.strip() for p in item.findtext('scan_ftypes', '').split(',') if p.strip()]
        info = packs.setdefault(key, dict(platform=platform, patterns=platforms[platform]['patterns'], framework_patterns=[]))
        # A pack may have several framework aliases; any applicable alias can dispatch it.
        info['framework_patterns'].append(filters)
    return platforms, packs


def selected_file(info, name):
    if not any(fnmatch.fnmatch(name, p) for p in info['patterns']):
        return False
    filters = info['framework_patterns']
    return not filters or any(not patterns or any(fnmatch.fnmatch(name, p) for p in patterns) for patterns in filters)


def audit_coverage(root, run_pairs=True):
    root = Path(root)
    failures = []
    definitions, expected = inventory(root)
    baseline = json.loads((root / 'rules/scanning/metadata/rdl/baseline.json').read_text())['entries']
    additional = json.loads((root / 'rules/scanning/metadata/rdl/additional.json').read_text())['entries']
    shadow_config = json.loads((root / 'rules/scanning/metadata/rdl/shadow-mappings.json').read_text())
    semantic = shadow_config['mappings']
    if shadow_config.get('project_flow'):
        from .portable_profiles import project_mappings
        semantic = dict(semantic, **project_mappings())
    cases = json.loads((root / 'tests/rdl/coverage/manifest.json').read_text())['cases']
    case_index = {case['rule_id']: case for case in cases}
    if len(case_index) != len(cases):
        failures.append('Duplicate paired fixture rule IDs')
    platforms, packs = registered_packs(root)
    if baseline != expected['entries']:
        failures.append('Native baseline manifest is stale')
    for path, content in definitions.items():
        if not (root / path).is_file() or (root / path).read_text() != content:
            failures.append('Stale or missing baseline: ' + path)
    known_packs = {e['xml_pack'] for e in baseline}
    overlays = json.loads((root / 'rules/scanning/metadata/rdl/platform-overlays.json').read_text())['entries']
    for overlay in overlays:
        if overlay['source_pack'] not in known_packs or overlay['target_pack'] not in known_packs:
            failures.append('Invalid mobile overlay: ' + str(overlay))
        if not overlay['patterns']:
            failures.append('Mobile overlay has no file filter: ' + str(overlay))
    for pack in packs:
        if pack not in known_packs:
            failures.append('Registered pack has no native baseline: ' + pack)
    for entry in baseline + additional:
        if entry['xml_pack'] not in packs and not entry['path_rule']:
            failures.append('Rule has no registered dispatch path: ' + entry['rule_id'])
    from .compiler import compile_rdl
    for entry in {e['v2_rule']: e for e in additional}.values():
        definition = root / entry['v2_rule']
        if definition.is_file():
            document = compile_rdl(definition.read_text(), entry['v2_rule'])
            if not document.valid:
                failures.append('Invalid supplemental definition: ' + entry['rule_id'])
            elif document.rule.rule_id != entry['rule_id']:
                failures.append('Supplemental rule ID does not match definition: ' + entry['rule_id'])
    by_path = {e['v2_rule'] for e in baseline + additional} | {e['v2_rule'] for e in semantic.values()}
    corpus = json.loads((root / 'tests/rdl/corpus/manifest.json').read_text())['cases']
    corpus_paths = {e['rule'] for e in corpus}
    development = json.loads((root / 'tests/rdl/coverage/development_samples.json').read_text())['rules']
    sample_paths = set()
    for entry in development:
        if len(entry['samples']) < 2 or any(not sample.get('source', '').strip() for sample in entry['samples']):
            failures.append('Missing paired development samples: ' + entry['rule'])
        else:
            sample_paths.add(entry['rule'])
    all_rules = {p.relative_to(root).as_posix() for p in (root / 'rules/scanning/logic/rdl/v2').rglob('*.rdl')}
    for path in by_path - all_rules:
        failures.append('Missing runtime definition: ' + path)
    for path in all_rules - by_path - corpus_paths - sample_paths:
        failures.append('Definition has neither runtime registration nor paired development samples: ' + path)
    scopes = {}
    for entry in baseline:
        scopes.setdefault(entry['scope'], dict(baseline=0, supplemental=0, paired_checks=0))['baseline'] += 1
    for entry in {e['v2_rule']: e for e in additional}.values():
        scopes.setdefault(entry['scope'], dict(baseline=0, supplemental=0, paired_checks=0))['supplemental'] += 1
    results = []
    if run_pairs:
        runner = BaselineRunner(root)
        with tempfile.TemporaryDirectory() as temporary:
            for index, entry in enumerate(additional):
                case = case_index.get(entry['rule_id'])
                if not case:
                    # Earlier registrations include their own paired source controls.
                    case = dict(positive=[entry['positive']], negative=[entry['negative']], file_name='source.txt')
                info = packs.get(entry['xml_pack'])
                if entry['rule_id'] in case_index and (not info or not selected_file(info, case['file_name'])):
                    failures.append('Fixture cannot reach registered pack: ' + entry['rule_id'] + ' (' + case['file_name'] + ')')
                for label, expected_outcome in [('positive', 'MATCH'), ('negative', 'NO_MATCH')]:
                    for number, content in enumerate(case[label]):
                        project = Path(temporary) / str(index) / label / str(number)
                        path = project / case['file_name']
                        path.parent.mkdir(parents=True)
                        for relative,source in case.get('project_files',{}).get(label,{}).items():
                            fixture=project/relative
                            if project.resolve() not in fixture.resolve().parents:
                                raise ValueError('Project fixture escapes its isolated directory')
                            fixture.parent.mkdir(parents=True,exist_ok=True)
                            fixture.write_text(source)
                        path.write_text(content)
                        record = runner.evaluate(entry, str(path), content, project, False,
                                                 refine=bool(entry.get('mobile_check') or entry.get('project_check') or entry.get('client_check') or entry.get('php_check') or entry.get('java_check')))
                        passed = record['v2_outcome'] == expected_outcome
                        if not passed:
                            failures.append('{} {}{}: {} {}'.format(entry['rule_id'], label, number, record['v2_outcome'], record['v2_errors']))
                        if label == 'positive' and record['v2_outcome'] == 'MATCH':
                            finding = record['v2_findings'][0]
                            if not finding.get('location') or not finding['trace']['blocks']:
                                failures.append('Missing source evidence: ' + entry['rule_id'])
                        results.append(dict(rule_id=entry['rule_id'], pack=entry['xml_pack'], case=label, expected=expected_outcome, actual=record['v2_outcome'], passed=passed))
                        scopes[entry['scope']]['paired_checks'] += 1
    mobile = {key: value for key, value in scopes.items() if key.startswith('mobile/')}
    return dict(passed=not failures, failures=failures,
                v1_definitions=sum(bool(e['v1_ref']) for e in baseline), xml_only_rules=sum(not e['v1_ref'] for e in baseline),
                baseline_rules=len(definitions), registered_platforms=len(platforms), registered_packs=len(packs),
                v2_definitions=len(all_rules), supplemental_rules=len({e['v2_rule'] for e in additional}),
                supplemental_registrations=len(additional), mobile_overlays=len(overlays), semantic_runtime_rules=len({e['v2_rule'] for e in semantic.values()}),
                corpus_only_rules=sorted((all_rules - by_path) & corpus_paths),
                sample_only_rules=sorted(all_rules - by_path - corpus_paths), scopes=scopes, mobile_scopes=mobile,
                mobile_review_areas=dict(Counter(c['review_area'] for c in cases if '/mobile/' in c['xml_pack'])),
                paired_cases=len(results), paired_results=results,
                limitations=[
                    'Baseline parity covers text/path predicates, not full semantic or data-flow analysis.',
                    'Supplemental checks are low-confidence source review leads; mobile refinements filter recognized comments/literals and parse declarations, but dead code, receiver types and build variants require human review.',
                    'Corpus-only and sample-only definitions are not advertised as active runtime checks; sample presence alone does not prove detection.',
                    'Static mobile checks do not certify complete security coverage, backend authorization, runtime pinning, binary integrity or privacy behavior.',
                ])


def markdown_report(report):
    lines = ['# RDL v2 coverage audit', '',
        'Generated by `python3 tools/rdl_coverage_audit.py --markdown docs/rdl/coverage-audit.md`.', '',
        'The portal presents RDL results in Vulnerability Analysis and recorded RDL flows, references and entry points in Advanced Analysis. Legacy CLI comparisons and archived reports remain separate historical evidence.', '',
        '## Verified inventory', '',
        '- {} v1 definitions and {} XML-only rules have {} native v2 baseline definitions.'.format(report['v1_definitions'], report['xml_only_rules'], report['baseline_rules']),
        '- {} registered platforms and {} distinct dispatch packs were audited.'.format(report['registered_platforms'], report['registered_packs']),
        '- {} supplemental definitions have {} pack registrations and {} passing paired-source checks.'.format(report['supplemental_rules'], report['supplemental_registrations'], sum(r['passed'] for r in report['paired_results'])),
        '- {} semantic definitions have production mappings; {} are tested only in the release corpus and {} have only development sample registrations.'.format(report['semantic_runtime_rules'], len(report['corpus_only_rules']), len(report['sample_only_rules'])), '',
        'The separate [baseline differential report](baseline-coverage.md) records every predicate comparison and six unreachable legacy-rule exceptions. Inventory coverage is not equivalent to complete semantic security analysis.', '',
        '## Scope coverage', '', '| Scope | Baseline | Supplemental | Paired checks |', '|---|---:|---:|---:|']
    for scope, item in sorted(report['scopes'].items()):
        lines.append('| {} | {} | {} | {} |'.format(scope, item['baseline'], item['supplemental'], item['paired_checks']))
    lines += ['', '## Mobile coverage', '',
        'Android, iOS, React Native, Flutter, Xamarin, MAUI, Kotlin Multiplatform, Ionic, NativeScript, and Cordova retain their complete registered v1 predicate baseline. Framework coverage includes Jetpack, Room, Retrofit, UIKit, SwiftUI, Alamofire, Core Data, Dio, Hive, and Expo.', '',
        'Mobile additions are organized by storage, cryptography, authentication, networking, platform interaction, code safety, resilience and privacy. These are review categories, not a security certification.', '',
        'The [Android/iOS review guide](mobile-security-review.md) records declaration-local refinements, supplemental backdoor/malware review surfaces, paired edge cases and explicit runtime/binary limits.', '',
        '| Review area | New mobile definitions |', '|---|---:|']
    lines += ['| {} | {} |'.format(key, value) for key, value in sorted(report['mobile_review_areas'].items())]
    lines += ['', 'Source selection includes Android Java/Kotlin/XML/Gradle Kotlin DSL, JavaScript JSX/TSX/module variants, Kotlin scripts, and hybrid native manifests/plists. Source selection is exercised by regression tests; platform and framework filters are checked for every new paired fixture.', '',
        'Mobile selections also dispatch applicable native-language v2 packs through `rules/scanning/metadata/rdl/platform-overlays.json` (for example React Native → JavaScript, MAUI → .NET, KMP → Kotlin, and native Android/iOS bridge files). Duplicate pack/file evaluations are skipped. V1 pack selection and rule predicates remain independent.', '', '## Evidence handling', '',
        'Source snippets retain original credential and sensitive values, including unquoted configuration values. JSON and HTML downloads retain the same evidence. HTML still escapes source markup so code is displayed as text. File/evaluation/telemetry resource limits remain in force; absent or incomplete evidence is not a safety verdict.', '',
        '## Remaining boundaries', '']
    lines += ['- '+item for item in report['limitations']]
    lines += ['', 'Full interprocedural mobile semantics, compiled artifact inspection, server-side authorization enforcement, device/runtime behavior, and every possible vulnerability are not established by this audit. See the [mobile pentest matrix](mobile-pentest-coverage.md) for source coverage and required follow-up.', '', '### Corpus-only definitions', '']
    lines += ['- `{}`'.format(path) for path in report['corpus_only_rules']]
    lines += ['', '### Development sample registrations only', '', 'These definitions are compile-tested and have paired development sample references, but are not runtime mappings or validated detection coverage. They remain explicit development work.', '']
    lines += ['- `{}`'.format(path) for path in report['sample_only_rules']]
    lines += ['', '## Reproduce', '', '```bash', 'python3 tools/rdl_baseline.py --check', 'python3 tools/rdl_compare_baseline.py --output /tmp/rdl-baseline.json', 'python3 tools/rdl_coverage_audit.py --output /tmp/rdl-coverage.json', 'python3 tools/rdl_rule_index.py --check', 'python3 tools/rdl_release_check.py', '```', '']
    return '\n'.join(lines)
