"""Explicit, background exports of saved results; never invokes the scanner."""
import json
import logging
import re
import threading
import shutil
import time
from tempfile import TemporaryDirectory
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel
from typing import Literal

class ReportRequest(BaseModel):
    format: Literal['html', 'pdf', 'docx', 'json'] = 'html'
    scope: Literal['full', 'findings', 'analysis', 'suppressed'] = 'full'

_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix='report-export')
_LOCK = threading.Lock()
_ACTIVE = set()
from core.report_document import REPORT_LABELS as LABELS

def _write(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=True), encoding='utf-8')
    temp.replace(path)

def jobs(root):
    result = []
    with _LOCK:
        for path in (root / 'exports').glob('*/job.json'):
            try:
                item = json.loads(path.read_text())
                if item['status'] in ('queued', 'running') and item['id'] not in _ACTIVE:
                    item = dict(item, status='failed', error='Generation was interrupted. Please generate again.', progress=dict(phase='failed', message='Generation was interrupted. Please generate again.'))
                result.append(item)
            except (OSError, ValueError, KeyError):
                continue
    return sorted(result, key=lambda item: item['created_at'], reverse=True)

def start(root, data_dir, request, scan):
    with _LOCK:
        if not data_dir.is_dir():
            raise ValueError('Saved scan data is unavailable. Refresh this scan before generating a report.')
        if len(_ACTIVE) >= 8:
            raise ValueError('Report queue is full. Please try again shortly.')
        # Repeated clicks reuse an in-flight request for this scan and selection.
        for path in (root / 'exports').glob('*/job.json'):
            item = json.loads(path.read_text())
            if item['id'] in _ACTIVE and item['format'] == request.format and item['scope'] == request.scope:
                return item
        ident = uuid4().hex
        folder = root / 'exports' / ident
        folder.mkdir(parents=True)
        item = dict(id=ident, format=request.format, scope=request.scope, status='queued',
                    progress=dict(phase='queued', message='Waiting for the report worker'), created_at=datetime.now(timezone.utc).isoformat(), filename=f'daksh-{request.scope}-{scan["run_uuid"]}.{"zip" if request.format == "html" else request.format}')
        _write(folder / 'job.json', item)
        _ACTIVE.add(ident)
        _POOL.submit(_generate, folder, data_dir, root, item, scan)
        return item

def collect(data_dir, root, scope, scan):
    from core.report_document import saved_document
    return saved_document(data_dir, root / 'runtime', scope, scan)

def blocks(value, depth=0):
    """Stream every saved field, including nested evidence, without truncation."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield min(depth + 1, 6), str(key).replace('_', ' ').title()
            yield from blocks(child, depth + 1)
    elif isinstance(value, list):
        if not value:
            yield 0, '(none)'
        for index, child in enumerate(value, 1):
            if isinstance(child, (dict, list)):
                yield min(depth + 1, 6), f'Item {index}'
            yield from blocks(child, depth + 1)
    else:
        yield 0, str(value) if value is not None else '(not recorded)'

def render(document, destination, fmt, progress=None):
    from core.report_progress import report_progress
    report_progress(progress, "building", "Building report")
    if fmt == 'json':
        from core.report_document import render_json
        report_progress(progress, "packaging", "Writing JSON download")
        render_json(document, destination)
        return
    if fmt in ('html', 'pdf'):
        from core.report_document import render_document
        render_document(document, destination, fmt, progress=progress)
        return
    if fmt == 'docx':
        from core.report_word import render_word
        render_word(document, destination, progress=progress)

def _generate(folder, data_dir, root, item, scan):
    last_update = [0.0, None]
    def progress(event):
        now = time.monotonic()
        if event['phase'] == last_update[1] and now - last_update[0] < 0.5 and event.get('completed') != event.get('total'):
            return
        with _LOCK:
            if not (folder / 'job.json').is_file():
                return
            item['progress'] = dict(event, updated_at=datetime.now(timezone.utc).isoformat())
            _write(folder / 'job.json', item)
        last_update[:] = [now, event['phase']]
    try:
        item.update(status='running', started_at=datetime.now(timezone.utc).isoformat())
        progress(dict(phase='collecting', message='Collecting saved scan results'))
        document = collect(data_dir, root, item['scope'], scan)
        output = folder / item['filename']
        partial = folder / ('partial.' + item['format'])
        with TemporaryDirectory(prefix='scratch-', dir=folder) as temporary:
            rendered = Path(temporary) / item['filename']
            if item['format'] == 'html':
                from core.report_document import render_html_package
                import zipfile
                package = Path(temporary) / 'package'
                outputs = render_html_package(document, package / 'index.html', progress=progress)
                progress(dict(phase='packaging', message='Packaging HTML download', completed=0, total=len(outputs), unit='files'))
                with zipfile.ZipFile(rendered, 'w', zipfile.ZIP_DEFLATED) as archive:
                    for index, path in enumerate(outputs, 1):
                        archive.write(path, path.relative_to(package))
                        progress(dict(phase="packaging", message="Packaging HTML download", completed=index, total=len(outputs), unit="files"))
            else:
                render(document, rendered, item['format'], progress=progress)
            # Rendering cannot recreate a scan removed during generation.
            if not (folder / 'job.json').is_file():
                return
            progress(dict(phase='finalizing', message='Saving download'))
            shutil.copyfile(rendered, partial)
            partial.replace(output)
        item.update(status='complete', size=output.stat().st_size, finished_at=datetime.now(timezone.utc).isoformat(), progress=dict(phase='complete', message='Ready to download'))
        _write(folder / 'job.json', item)
    except Exception as exc:
        logging.getLogger(__name__).exception('Report generation failed')
        if folder.is_dir():
            item.update(status='failed', finished_at=datetime.now(timezone.utc).isoformat(), progress=dict(phase='failed', message='Report generation failed'), error=str(exc) if isinstance(exc, ValueError) else 'Report generation failed. Please retry.')
            _write(folder / 'job.json', item)
            for partial in folder.glob('partial.*'):
                partial.unlink(missing_ok=True)
    finally:
        with _LOCK:
            _ACTIVE.discard(item['id'])
