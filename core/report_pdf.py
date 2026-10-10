"""Bounded Chromium rendering and assembly of complete, navigable PDF reports."""
from pathlib import Path
from tempfile import TemporaryDirectory
from hashlib import sha256
import json
import logging
import re
from urllib.parse import quote, unquote


def print_parts(context, page_size=100):
    """Partition presentation rows, never truncate evidence or recorded locations."""
    def part(key, label, updates=None):
        return dict(context, **dict(updates or {}, page_sections={key},
                                    report_part_title=label, extra_sections={}))
    yield 'Summary & review priorities', part('overview', 'Summary & review priorities')
    if context['show_findings']:
        for platform in context['platform_sections']:
            for finding in platform['findings']:
                sources = finding['evidence_samples']
                for offset in range(0, max(1, len(sources)), page_size):
                    row = dict(finding, evidence_samples=sources[offset:offset+page_size])
                    title = 'Areas of Interest · ' + platform['name']
                    yield title, part('areas-of-interest', title, {'platform_sections': [dict(platform, findings=[row])]})
        if not context['platform_sections']:
            yield 'Areas of Interest', part('areas-of-interest', 'Areas of Interest')
    specs = []
    if context['show_findings']:
        specs += [('paths-aoi', 'Path Areas of Interest', ['parsed_paths_aoi']),
                  ('paths-all', 'File Inventory', ['all_filepaths']),
                  ('rule-index', 'Rule Index', ['rule_index'])]
    if context['show_analysis']:
        specs += [('analysis-overview', 'Analysis Overview', ['analysis_targets']),
                  ('vulnerabilities', 'Vulnerabilities & Mitigations', ['vulnerabilities', 'mitigations', 'manual_reviews', 'rdl_assessments']),
                  ('attack-vectors', 'Attack Vectors', ['attack_vectors', 'semantic_vectors']),
                  ('taint-flows', 'Taint & Data Flows', ['analysis_flows', 'semantic_flows']),
                  ('cross-references', 'Cross References', ['flow_references', 'semantic_references', 'pdf_symbols', 'pdf_calls']),
                  ('rdl-evidence', 'RDL Review Evidence', ['rdl_findings', 'review_limitations']),
                  ('source-evidence', 'Saved Source Evidence', ['evidence_sources'])]
    if context['show_suppressed']:
        specs.append(('suppressed-findings', 'Suppressed Findings', ['suppressed']))
    graph = context['cross_reference']
    context = dict(context, pdf_symbols=graph.get('symbols', []), pdf_calls=graph.get('calls', []))
    for key, title, fields in specs:
        size = max(len(context.get(field, [])) for field in fields)
        limit = min(page_size, 20) if key in ('rdl-evidence', 'source-evidence') else page_size
        count = max(1, (size+limit-1)//limit)
        for index in range(count):
            updates = {field: context.get(field, [])[index*limit:(index+1)*limit] for field in fields}
            if key == 'cross-references' and graph:
                updates['cross_reference'] = dict(graph, symbols=updates['pdf_symbols'], calls=updates['pdf_calls'])
            label = title + (f' · Part {index+1} of {count}' if count > 1 else '')
            yield title, part(key, label, updates)
    if context['recon']:
        yield 'Reconnaissance', part('reconnaissance', 'Reconnaissance')
    for key, value in context['extra_sections'].items():
        title = key.replace('_', ' ').title()
        current = part('additional', title)
        current['extra_sections'] = {key: value}
        yield title, current


def render_pdf(context, destination, cache_dir=None, progress=None):
    from core.report_progress import report_progress
    report_progress(progress, 'building', 'Preparing PDF sections')
    from playwright.sync_api import sync_playwright
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject, DecodedStreamObject
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from core.reports import _render_pdf_html
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    anchors, destinations, sections = {}, {}, {}
    link_prefix = 'https://report.daksh.invalid/'
    log = logging.getLogger(__name__)
    with TemporaryDirectory(prefix='daksh-print-') as temporary, sync_playwright() as playwright:
        cache = Path(cache_dir) if cache_dir else Path(temporary)/'parts'
        cache.mkdir(parents=True, exist_ok=True)
        # Explicit validation caches survive interrupted sessions; ordinary
        # exports use private temporary parts that disappear after generation.
        metadata = cache/'generation.json'
        if metadata.is_file():
            context = dict(context, **json.loads(metadata.read_text()))
        else:
            metadata.write_text(json.dumps({key: context[key] for key in ('generated_at', 'report_date')}))
        total_parts = sum(1 for _ in print_parts(context))
        rendered = []
        browser = playwright.chromium.launch()
        try:
            for index, (title, current) in enumerate(print_parts(context)):
                report_progress(progress, 'building', 'Rendering ' + current['report_part_title'], index, total_parts, 'sections')
                log.info('Rendering PDF section %s: %s', index+1, current['report_part_title'])
                html = _render_pdf_html(current)
                local_anchors = re.findall(r'\bid="([^"\s]+)"', html)
                # Cross-part links become internal PDF destinations after assembly.
                html = re.sub(r'href="#([^"\s]+)"', lambda m: 'href="'+link_prefix+quote(m[1], safe='')+'"', html)
                # Chromium emits exact PDF destinations only for linked IDs.
                # Invisible registration links preserve the target coordinates;
                # their tiny annotations are removed after the sections are joined.
                registration = ''.join('<a aria-hidden="true" style="position:absolute;top:0;left:0;font-size:1px;line-height:1px;color:transparent" href="#'+anchor+'">&#160;</a>'
                                       for anchor in local_anchors)
                html = html.replace('</body>', registration+'</body>')
                output = cache/(sha256(html.encode('utf-8')).hexdigest()+'.pdf')
                rendered.append((title, output, local_anchors))
                if output.is_file():
                    log.info('Reusing completed PDF section %s', index+1)
                    report_progress(progress, 'building', 'Rendering PDF sections', index+1, total_parts, 'sections')
                    continue
                source = Path(temporary)/'part.html'
                source.write_text(html, encoding='utf-8')
                page = browser.new_page()
                try:
                    page.set_default_timeout(120000)
                    page.route('http://**/*', lambda route: route.abort())
                    page.route('https://**/*', lambda route: route.abort())
                    page.goto(source.as_uri(), wait_until='load', timeout=120000)
                    page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
                    page.add_style_tag(content='.page-break{break-before:auto!important;page-break-before:auto!important;}')
                    partial = output.with_suffix('.partial.pdf')
                    page.pdf(path=str(partial), format='A4', print_background=True,
                             margin={'top':'20px','bottom':'40px','left':'20px','right':'20px'})
                    partial.replace(output)
                finally:
                    page.close()
                log.info('PDF section %s complete', index+1)
                report_progress(progress, 'building', 'Rendering PDF sections', index+1, total_parts, 'sections')
        finally:
            browser.close()
        # Assemble only after Chromium has released its DOM/process memory.
        report_progress(progress, 'packaging', 'Assembling PDF sections', 0, len(rendered), 'sections')
        writer = PdfWriter()
        for index, (title, output, local_anchors) in enumerate(rendered):
            offset = len(writer.pages)
            sections.setdefault(title, offset)
            for anchor in local_anchors:
                anchors.setdefault(anchor, offset)
            with output.open('rb') as stream:
                reader = PdfReader(stream)
                for page in reader.pages:
                    writer.add_page(page)
                for name, target in reader.named_destinations.items():
                    anchor = name.lstrip('/')
                    if anchor not in destinations:
                        array = ArrayObject(target.dest_array)
                        number = offset + reader.get_destination_page_number(target)
                        array[0] = writer.pages[number].indirect_reference
                        destinations[anchor] = array
                writer.reset_translation(reader)
            log.info('Assembled PDF section %s/%s; %s pages', index+1, len(rendered), len(writer.pages))
            report_progress(progress, 'packaging', 'Assembling PDF sections', index+1, len(rendered), 'sections')
        for title, offset in sections.items():
            writer.add_outline_item(title, offset)
        # Build the sorted name tree once. Inserting tens of thousands of
        # targets one at a time turns a large source index into quadratic work.
        report_progress(progress, 'packaging', 'Adding PDF bookmarks and navigation')
        log.info('Registering %s PDF destinations', len(anchors))
        names = ArrayObject()
        for anchor, offset in sorted(anchors.items()):
            target = destinations.get(anchor) or ArrayObject([writer.pages[offset].indirect_reference, NameObject('/Fit')])
            names.extend([TextStringObject(anchor), target])
        writer.root_object[NameObject('/Names')] = DictionaryObject({
            NameObject('/Dests'): DictionaryObject({NameObject('/Names'): names})})
        total = len(writer.pages)
        footer_font = writer._add_object(DictionaryObject({
            NameObject('/Type'): NameObject('/Font'), NameObject('/Subtype'): NameObject('/Type1'),
            NameObject('/BaseFont'): NameObject('/Helvetica')}))
        before_content, after_content = DecodedStreamObject(), DecodedStreamObject()
        before_content.set_data(b'q\n')
        after_content.set_data(b'\nQ\n')
        before_content = writer._add_object(before_content)
        after_content = writer._add_object(after_content)
        for index, page in enumerate(writer.pages):
            if index % 250 == 0:
                report_progress(progress, 'packaging', 'Adding links and page numbers', index, total, 'pages')
            if index % 250 == 0:
                log.info('Numbering PDF page %s/%s', index+1, total)
            annotations = ArrayObject()
            for ref in page.get('/Annots', []):
                annotation = ref.get_object()
                rectangle = annotation.get('/Rect', [])
                if annotation.get('/Dest') and len(rectangle) == 4 and rectangle[2]-rectangle[0] < 2 and rectangle[3]-rectangle[1] < 2:
                    continue
                annotations.append(ref)
                action = annotation.get('/A')
                if action and str(action.get('/URI', '')).startswith(link_prefix):
                    anchor = unquote(str(action['/URI'])[len(link_prefix):])
                    if anchor in anchors:
                        annotation[NameObject('/A')] = DictionaryObject({NameObject('/S'): NameObject('/GoTo'),
                                                                         NameObject('/D'): TextStringObject(anchor)})
                    else:
                        del annotation['/A']
            if page.get('/Annots'):
                page[NameObject('/Annots')] = annotations
            # One global page sequence, including assembled evidence sections.
            # Append a separate stream without decoding/reparsing all source
            # content. Large evidence pages otherwise retain huge token trees.
            resources = DictionaryObject(page.get('/Resources', DictionaryObject()).get_object())
            fonts = DictionaryObject(resources.get('/Font', DictionaryObject()).get_object())
            font_name = '/DakshReportFooter'
            while font_name in fonts:
                font_name += '_'
            fonts[NameObject(font_name)] = footer_font
            resources[NameObject('/Font')] = fonts
            page[NameObject('/Resources')] = resources
            label = f'{index+1} / {total}'
            right = float(page.mediabox.width) - 24 - stringWidth(label, 'Helvetica', 8)
            footer = DecodedStreamObject()
            footer.set_data((f'q BT .36 .43 .56 rg {font_name} 8 Tf 1 0 0 1 24 12 Tm '
                             f'(Daksh SCRA | Security Review) Tj 1 0 0 1 {right:.3f} 12 Tm '
                             f'({label}) Tj ET Q').encode('ascii'))
            contents = page.get('/Contents')
            existing = contents.get_object() if contents else None
            streams = ArrayObject(existing) if isinstance(existing, ArrayObject) else ArrayObject([contents] if contents else [])
            # Chromium can leave a page-wide coordinate transform active.
            # Restore default PDF coordinates before drawing the footer.
            streams.insert(0, before_content)
            streams.append(after_content)
            streams.append(writer._add_object(footer))
            page[NameObject('/Contents')] = streams
        writer.add_metadata({'/Title':context['reportTitle'], '/Subject':context['report_scope'], '/Author':'Daksh SCRA'})
        report_progress(progress, 'packaging', 'Writing the consolidated PDF')
        output = Path(temporary)/'complete.pdf'
        writer.write(output)
        # No incomplete PDF becomes visible if a section fails to render.
        import shutil
        shutil.copyfile(output, destination)
    return destination
