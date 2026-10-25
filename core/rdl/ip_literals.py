"""Validate address literals and remove proven version or source-syntax matches."""
import ipaddress
import re
from pathlib import Path

IP_PATTERN = (r'(?<![A-Za-z0-9_:.%])(?:[A-Fa-f0-9]{0,4}:){2,8}[A-Fa-f0-9.]{0,45}'
              r'(?:%[A-Za-z0-9_.~-]{1,64})?(?![A-Za-z0-9_:.%])'
              r'|(?<![A-Za-z0-9_:.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.%])')
CANDIDATES = re.compile(IP_PATTERN)
QUOTED = re.compile(r"""(?P<quote>['"`])(?:\\.|(?!(?P=quote))[^\\\r\n])*(?P=quote)""")
VERSION_NAME = r'(?:version|version_number|version_string|package_version|app_version|build_version|release_version|assemblyversion|assemblyfileversion|assemblyinformationalversion|fileversion|productversion|semver|release)'
VERSION_PREFIX = re.compile(rf"""(?ix)(?:\b{VERSION_NAME}\b|['"]{VERSION_NAME}['"])\s*(?:=>|=|:|\()\s*$|\bdefine\s*\(\s*['"]{VERSION_NAME}['"]\s*,\s*$|<version>\s*$|\b(?:versionsFrom|AssemblyVersion|AssemblyFileVersion|AssemblyInformationalVersion)(?:Attribute)?\s*\(\s*$|\bGeneratedCode(?:Attribute)?\s*\(\s*[\'\"][^\'\"\r\n]*[\'\"]\s*,\s*$""")
NON_ADDRESS_PREFIX = re.compile(r"""(?ix)\b(?:separator|delimiter|scope_operator|time_format|date_format|regex|regexp)\s*(?:=|:)\s*$|\b(?:RegExp|re\.compile|preg_match|preg_replace)\s*\(\s*$""")
REGEX_FRAGMENT = re.compile(r'\\[dDsSwWbB]|\(\?[=:!<]|\{\d+,?\d*\}|\[\^')
CONFIG_SUFFIXES = {'.json', '.yaml', '.yml', '.xml', '.ini', '.conf', '.config', '.toml', '.properties', '.env', '.txt', '.rdl'}


def address_view(path, content, without_comments=None, code=None):
    """Preserve offsets; mask rejected tokens individually, never a whole file."""
    if without_comments is None or code is None:
        from .source_review import source_views
        without_comments, code = source_views(path, content)
    selected = list(without_comments)
    literals = list(QUOTED.finditer(without_comments))
    literal_index = 0
    for match in CANDIDATES.finditer(without_comments):
        value = match.group()
        try:
            address = ipaddress.ip_address(value.split('%', 1)[0])
            valid = True
        except ValueError:
            address, valid = None, False
        while literal_index < len(literals) and literals[literal_index].end() <= match.start():
            literal_index += 1
        literal = literals[literal_index] if literal_index < len(literals) and literals[literal_index].start() < match.start() and literals[literal_index].end() >= match.end() else None
        start = literal.start() if literal else match.start()
        prefix = without_comments[max(0, start - 200):start]
        text = literal.group()[1:-1] if literal else value
        # A URL host is an address even if its variable includes a version label.
        is_url_host = bool(re.search(r'[A-Za-z][A-Za-z0-9+.-]*://[^/\s]*$', without_comments[max(0,match.start()-160):match.start()]))
        if valid and not is_url_host:
            if VERSION_PREFIX.search(prefix) or NON_ADDRESS_PREFIX.search(prefix):
                valid = False
            elif literal and text != value and REGEX_FRAGMENT.search(text):
                valid = False
            elif not literal and Path(str(path)).suffix.lower() not in CONFIG_SUFFIXES:
                # IPv6 scope/slice syntax and lexer-classified regex bodies are not address literals.
                if address.version == 6 or not code[match.start():match.end()].strip():
                    valid = False
        if not valid:
            selected[match.start():match.end()] = ' ' * len(value)
    return ''.join(selected)
