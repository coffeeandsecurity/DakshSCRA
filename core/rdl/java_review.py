"""Source-backed Java configuration checks with local evidence."""
import re
import xml.etree.ElementTree as ET
from dataclasses import replace

from .executor import Evidence, ExecutionOutcome
from .text import match_location


def datasource_credentials(result, path, text):
    if not str(path).lower().endswith('.xml'):
        return replace(result, outcome=ExecutionOutcome.NO_MATCH, evidence=(), witnesses=(), errors=())
    try:
        ET.fromstring(text)
    except ET.ParseError as exc:
        return replace(result, outcome=ExecutionOutcome.INDETERMINATE, evidence=(), witnesses=(),
                       errors=('Cannot parse datasource configuration: '+str(exc),))
    witnesses = []
    for bean in re.finditer(r'<(?:\w+:)?bean\b[^>]*?/\s*>|<(?:\w+:)?bean\b[^>]*>.*?</(?:\w+:)?bean\s*>', text, re.S):
        opening = bean.group().split('>', 1)[0]
        if not re.search(r'''\bclass\s*=\s*["'][^"']*(?:DataSource|ConnectionPool)["']''', opening):
            continue
        for tag in re.finditer(r'<(?:\w+:)?property\b[^>]*>', bean.group(), re.S):
            attributes = {match[1]: match[3] for match in re.finditer(r'''([\w:.-]+)\s*=\s*(["'])(.*?)\2''', tag.group(), re.S)}
            value = attributes.get('value', '').strip()
            if attributes.get('name', '').lower() != 'password' or not value or any(marker in value for marker in ('${', '#{', '{cipher}')):
                continue
            start = bean.start()+tag.start()
            witnesses.append((Evidence('TEXT_MATCHES', True, location=match_location(path, text, start, bean.start()+tag.end()),
                                      explanation='Literal password in a datasource bean; verify whether this configuration is deployed and the credential is active.'),))
        for attribute in re.finditer(r'''\bp:password\s*=\s*(["'])(.*?)\1''', opening, re.S):
            value = attribute[2].strip()
            if value and not any(marker in value for marker in ('${', '#{', '{cipher}')):
                start = bean.start()+attribute.start()
                witnesses.append((Evidence('TEXT_MATCHES', True, location=match_location(path, text, start, bean.start()+attribute.end()),
                                          explanation='Literal password in a datasource bean attribute; deployment and credential activity require review.'),))
    return replace(result, outcome=ExecutionOutcome.MATCH if witnesses else ExecutionOutcome.NO_MATCH,
                   evidence=tuple(e for group in witnesses for e in group), witnesses=tuple(witnesses), errors=())
