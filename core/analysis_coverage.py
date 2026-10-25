"""Evidence of inputs that cannot receive complete source analysis."""
import json
from pathlib import Path

from core.android_artifacts import source_limitations


TITLE = 'Incomplete Source Analysis'
RULE_ID = 'coverage.incomplete-source-analysis'
REMEDIATION = (
    'Obtain the original source for the exact build, or decompile DEX with JADX and '
    'decode Android resources and the manifest with Apktool. Scan the decoded source '
    'and XML directory. Recover failed methods with another decompiler or inspect '
    'their bytecode manually. Review native libraries with a binary-analysis tool. '
    'Restore read access or missing files, then rerun the scan. Keep unresolved files '
    'and methods in the review scope; a completed scan does not establish full coverage.'
)


class CoverageAudit:
    def __init__(self, root):
        self.root = Path(root)
        self.evidence = []

    def add(self, path, reason, action, line=0):
        try:
            name = Path(path).relative_to(self.root).as_posix()
        except ValueError:
            name = str(path)
        self.evidence.append(dict(file=name, line=line, code=reason + ' Required action: ' + action,
                                  coverage_reason=reason, required_action=action))

    def inspect(self, path, selected=False):
        path = Path(path)
        ext = path.suffix.lower()
        if not selected and ext not in {'.dex', '.xml', '.so', '.apk', '.aab', '.class'}:
            return
        try:
            with path.open('rb') as stream:
                head = stream.read(4096)
                if head.startswith(b'dex\n') and len(head) >= 8 and head[4:7].isdigit() and head[7] == 0:
                    self.add(path, 'DEX bytecode is not Java/Kotlin source.', 'Decompile this DEX or obtain original Java/Kotlin source, then rescan.')
                elif head.startswith(b'\x03\x00\x08\x00') and ext == '.xml':
                    self.add(path, 'Compiled Android XML cannot receive textual XML checks.', 'Decode the manifest/resources with Apktool and rescan the decoded XML.')
                elif head.startswith(b'\x7fELF') and ext == '.so':
                    self.add(path, 'Native ELF code is outside source-analysis coverage.', 'Obtain matching C/C++ source or perform a separate native binary review.')
                elif head.startswith(b'PK\x03\x04') and ext in {'.apk', '.aab'}:
                    self.add(path, 'Packaged Android application has not been decoded for source analysis.', 'Extract and decode/decompile the application; scan the resulting source and textual XML.')
                elif head.startswith(b'\xca\xfe\xba\xbe') and ext == '.class':
                    self.add(path, 'Java class bytecode is not Java source.', 'Obtain matching Java source or decompile this class and rescan.')
                elif selected and b'\x00' in head and not head.startswith((b'\xff\xfe', b'\xfe\xff', b'\x00\x00\xfe\xff')):
                    self.add(path, 'Selected source file contains binary data; textual checks are incomplete.', 'Identify the format and decode it, or supply matching readable source and rescan.')
                elif selected and ext == '.java':
                    raw = head + stream.read()
                    text = raw.decode('utf-8-sig', errors='replace')
                    if list(source_limitations(path, text)):
                        self.add(path, 'Decompiled Java contains unrecovered method bodies.', 'Recover the failed methods using original source, another decompiler or bytecode review; rescan recovered source.')
        except OSError as exc:
            self.add(path, 'File could not be read (' + type(exc).__name__ + ').', 'Restore read access and file availability, then rescan.')

    def report(self):
        return dict(status='incomplete' if self.evidence else 'no_input_limitations_detected',
                    affected_files=len({item['file'] for item in self.evidence}),
                    evidence=self.evidence,
                    scope_note='Input readability checks do not certify rule coverage, parser completeness or absence of vulnerabilities.')


def publish_findings(report, findings_path):
    """Upsert the coverage notice into the normal finding/export contract."""
    path = Path(findings_path)
    findings = json.loads(path.read_text(encoding='utf-8')) if path.exists() else []
    findings = [item for item in findings if item.get('rule_id') != RULE_ID]
    if report.get('evidence'):
        findings.append(dict(platform='Common', rule_id=RULE_ID, rule_title=TITLE,
            category='Analysis Coverage', issue_scope='Analysis Coverage',
            rule_desc='Some input files or method bodies could not receive complete source analysis.',
            issue_desc='Analysis is incomplete for the listed files; review their individual reasons and required actions.',
            security_impact='Security issues may remain undetected in unreadable, compiled or unrecovered code. This is a coverage limitation, not a confirmed application vulnerability.',
            developer_note=REMEDIATION, reviewer_note=REMEDIATION,
            confidence_score=100, confidence_level='high', severity='INFO',
            analysis_coverage_status='incomplete', evidence=report['evidence']))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(findings, indent=2), encoding='utf-8')
    return bool(report.get('evidence'))


def record_read_failure(runtime_dir, root, path, error):
    """Keep failures occurring after discovery in the same run-local notice."""
    output = Path(runtime_dir) / 'analysis_coverage.json'
    audit = CoverageAudit(root)
    if output.exists():
        audit.evidence = json.loads(output.read_text(encoding='utf-8')).get('evidence', [])
    audit.add(path, 'File could not be read (' + type(error).__name__ + ').',
              'Restore read access and file availability, then rescan.')
    unique = {(item['file'], item['coverage_reason']): item for item in audit.evidence}
    audit.evidence = list(unique.values())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit.report(), indent=2), encoding='utf-8')
