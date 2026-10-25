"""Escaped paragraphs and real lists for reviewer-facing guidance."""
import re
from html import escape
from markupsafe import Markup


def guidance_html(text):
    text = str(text or '').replace('—', '. ').replace(';', '.')
    # Accept older saved notes whose line breaks were flattened.
    text = re.sub(r'(?<!\d)\s+(\d+\.\s+)(?=[A-Z])', r'\n\1', text)
    text = re.sub(r'(checks|review|steps|actions|verify):\s*(?=\n?\d+\.\s)', r'\1:\n', text, flags=re.I)
    out, items, paragraph = [], [], []
    def flush():
        if paragraph:
            out.append('<p>' + escape(' '.join(paragraph)) + '</p>'); paragraph.clear()
        if items:
            out.append('<ol>' + ''.join('<li>' + escape(item) + '</li>' for item in items) + '</ol>'); items.clear()
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r'^\d+[.)]\s+(.+)', line)
        if match:
            if paragraph:flush()
            items.append(match[1])
        elif not line:
            flush()
        else:
            if items:flush()
            paragraph.append(line)
    flush()
    return Markup(''.join(out))
