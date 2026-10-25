"""Bounded reconnaissance of compiled Android artifacts; no binary source claims."""
import re
from pathlib import Path


def artifact_detections(path):
    """Yield category/name/confidence from validated headers or SDK metadata.

    Presence identifies packaged dependencies, not application use, reachability,
    language of authorship, vulnerability, or verified dependency versions.
    """
    path = Path(path)
    name = path.name
    if not (path.suffix.lower() in {'.dex', '.xml', '.so', '.properties'}):
        return
    try:
        with path.open('rb') as stream:
            head = stream.read(8)
            if path.suffix.lower() == '.dex' and re.fullmatch(rb'dex\n\d{3}\x00', head):
                yield 'Analysis Coverage', 'DEX bytecode (decode before source analysis)', 'high'
                return
            if path.suffix.lower() == '.xml' and head[:4] == b'\x03\x00\x08\x00':
                yield 'Analysis Coverage', 'Binary Android XML (decode before source analysis)', 'high'
                return
            if path.suffix.lower() == '.so' and head[:4] == b'\x7fELF':
                yield 'Packaged Artifacts', 'Native ELF library (binary review required)', 'high'
                return
            if path.suffix.lower() != '.properties' or not name.startswith(('firebase-', 'play-services-')):
                return
            raw = head + stream.read(16385)
    except OSError:
        return
    if len(raw) > 16384 or b'\x00' in raw:
        return
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r'\s*(client|version)\s*=\s*([^\s#]+)\s*', line)
        if match:
            if match[1] in values:
                return
            values[match[1]] = match[2]
    client = name[:-len('.properties')]
    if values.get('client') != client or not re.fullmatch(r'\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?', values.get('version', '')):
        return
    yield 'Packaged SDK Metadata', client + ' (declared ' + values['version'] + ')', 'medium'


def source_limitations(path, text):
    """Identify active decompiler failure stubs without treating them as app behavior."""
    if Path(path).suffix.lower() != '.java' or 'Method not decompiled:' not in text:
        return
    from core.rdl.source_review import source_views
    comments, code = source_views(str(path), text)
    pattern = r'\bthrow\s+new\s+(?:java\.lang\.)?UnsupportedOperationException\s*\(\s*"Method not decompiled:'
    if any(code[hit.start():hit.start()+5] == 'throw' for hit in re.finditer(pattern, comments)):
        yield 'Analysis Coverage', 'Decompiled source with unrecovered methods (manual recovery required)', 'high'
