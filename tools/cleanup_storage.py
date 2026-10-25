"""List disk usage and clean selected generated application storage."""
import argparse
import getpass
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import storage_cleanup


def size(value):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return f'{value:.1f} {unit}'
        value /= 1024


class Portal:
    def __init__(self, url, username, password):
        parts = urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.netloc or parts.username or parts.query or parts.fragment:
            raise ValueError('Use a portal URL such as http://localhost:3030')
        if parts.scheme == 'http' and parts.hostname not in {'localhost', '127.0.0.1', '::1'}:
            raise ValueError('Use HTTPS for a remote portal; HTTP is supported only on localhost.')
        self.url = url.rstrip('/')
        self.client = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.call('POST', '/api/v1/auth/login', dict(username=username, password=password))

    def call(self, method, path, body=None):
        request = Request(self.url + path, method=method, headers={'Content-Type': 'application/json'},
                          data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.client.open(request, timeout=180) as response:
                return json.load(response)
        except HTTPError as exc:
            try:
                message = json.load(exc).get('detail', str(exc.code))
            except (ValueError, OSError):
                message = str(exc.code)
            raise ValueError('Portal request failed: ' + str(message)) from exc


def rows(payload):
    result = []
    for area in payload['cleanup']['areas']:
        result.append(dict(id='area:' + area['id'], label=area['label'], bytes=area['bytes'],
                           reclaimable_bytes=area['reclaimable_bytes'], files=area['file_count'],
                           kind='area', area=area['id'], location=area['location']))
    for project in payload.get('projects', []):
        for scan in project['scans']:
            run = scan['run_uuid']
            result.append(dict(id='scan:' + run, label=project['project_name'] + ' / ' + run,
                               bytes=scan['bytes'], reclaimable_bytes=0 if scan['active'] else scan['bytes'],
                               files=sum(u['file_count'] for u in scan['units']), kind='scan', run=run,
                               location='All saved results/reports/logs/runtime; retains history', active=scan['active']))
            for unit in scan['units']:
                result.append(dict(id='unit:' + run + ':' + unit['id'], label=unit['label'], bytes=unit['bytes'],
                                   reclaimable_bytes=unit['bytes'] if unit['removable'] else 0,
                                   files=unit['file_count'], kind='unit', run=run, unit=unit['id'], location=unit['path']))
    for item in payload.get('unassigned', []):
        result.append(dict(id='retained:' + hashlib.sha256(item['path'].encode()).hexdigest()[:16],
                           label='Unassigned application files (retained)', bytes=item['bytes'], reclaimable_bytes=0,
                           files=item['file_count'], kind='retained', location=item['path']))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog='Preview is the default. --all selects generated areas and independently removable scan items; saved findings require explicit --select scan:RUN. --force skips confirmation, never safety checks.')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1], help='Local project checkout (default: this project)')
    parser.add_argument('--url', help='Portal URL; includes its saved scan storage and uses server-side cleanup guards')
    parser.add_argument('--username', default='admin', help='Portal account for --url')
    parser.add_argument('--password-env', default='DAKSH_CLEANUP_PASSWORD', help='Environment variable containing portal password; otherwise prompt securely')
    parser.add_argument('--select', action='append', default=[], metavar='ID', help='Area, scan or unit ID from inventory; repeat for multiple selections')
    parser.add_argument('--all', action='store_true', help='Select all eligible generated areas and removable scan units; excludes whole scan data')
    parser.add_argument('--execute', action='store_true', help='Perform selected cleanup (otherwise preview)')
    parser.add_argument('--force', action='store_true', help='Skip interactive confirmation; requires --execute')
    parser.add_argument('--json', action='store_true', help='Print machine-readable inventory/result')
    args = parser.parse_args(argv)
    if args.force and not args.execute:
        parser.error('--force requires --execute')
    if args.execute and not (args.all or args.select):
        parser.error('--execute requires --select ID or --all')
    if args.url and args.root != Path(__file__).resolve().parents[1]:
        parser.error('--root and --url select different storage locations; use one')
    portal = None
    results = []
    try:
        if args.url:
            password = os.getenv(args.password_env) or getpass.getpass('Portal password: ')
            portal = Portal(args.url, args.username, password)
            payload = portal.call('GET', '/api/v1/system/disk')
        else:
            payload = {'cleanup': storage_cleanup.public_plan(storage_cleanup.plan(args.root, local=True))}
        if not isinstance(payload.get('cleanup'), dict):
            raise ValueError('This portal does not provide generated-storage cleanup yet. Update its API deployment.')
        items = rows(payload)
        by_id = {item['id']: item for item in items}
        unknown = set(args.select) - by_id.keys()
        if unknown:
            raise ValueError('Unknown storage selection: ' + ', '.join(sorted(unknown)))
        selected = set(args.select)
        if args.all:
            selected.update(item['id'] for item in items if item['kind'] != 'scan' and item['reclaimable_bytes'] > 0)
        # A whole scan already contains its units. Never charge or delete twice.
        chosen = [item for item in items if item['id'] in selected and not (item['kind'] == 'unit' and 'scan:' + item['run'] in selected)]
        protected = [item['id'] for item in chosen if item['kind'] == 'retained' or (item['reclaimable_bytes'] <= 0 and item['bytes'] > 0)]
        if args.execute and protected:
            raise ValueError('Selection is protected or has no eligible files: ' + ', '.join(protected))
        document = dict(inventory=items, cleanup=payload['cleanup'], selected=[i['id'] for i in chosen],
                        selected_bytes=sum(i['reclaimable_bytes'] for i in chosen), mode='execute' if args.execute else 'preview')
        if not args.json:
            print('Storage inventory (logical file sizes; scan totals include their units):')
            for item in items:
                print(f"{item['id']}\n  {item['label']}: {size(item['bytes'])} used; {size(item['reclaimable_bytes'])} eligible; {item['files']} files\n  {item['location']}")
            print(payload['cleanup']['note'])
            if payload['cleanup'].get('ownership_warning'):
                print(payload['cleanup']['ownership_warning'])
            if not args.url:
                print('Local mode retains runtime diagnostics and saved scan data. Use --url http://localhost:3030 --username USER to inspect/clean portal storage, including its Docker runtime volume.')
            print(f"Selected: {len(chosen)} sections/items; {size(document['selected_bytes'])} eligible.")
        if args.execute and chosen:
            if not args.force:
                if not sys.stdin.isatty():
                    raise ValueError('Noninteractive execution requires --force; preview first.')
                print(f"Delete selected generated files ({size(document['selected_bytes'])})?", file=sys.stderr)
                if input('Type CLEAN to continue: ') != 'CLEAN':
                    raise ValueError('Cleanup cancelled')
            areas = [i['area'] for i in chosen if i['kind'] == 'area']
            if areas:
                results.append(portal.call('POST', '/api/v1/system/disk/cleanup', {'areas': areas}) if portal else storage_cleanup.cleanup(args.root, areas, local=True))
            for item in chosen:
                if item['kind'] == 'area':
                    continue
                path = '/api/v1/system/disk/scans/' + quote(item['run'], safe='')
                if item['kind'] == 'unit':
                    path += '/units/' + quote(item['unit'], safe='')
                results.append(portal.call('DELETE', path))
            document['results'] = results
            document['removed_bytes'] = sum(r.get('removed_bytes', 0) for r in results)
            if not args.json:
                print('Removed: ' + size(document['removed_bytes']) + '. Refresh inventory to see remaining files.')
        if args.json:
            print(json.dumps(document, indent=2))
        return 1 if any(r.get('failed_files', 0) for r in document.get('results', [])) else 0
    except (ValueError, OSError, URLError, EOFError) as exc:
        if args.json:
            print(json.dumps({'error': str(exc), 'results': results, 'removed_bytes': sum(r.get('removed_bytes', 0) for r in results)}))
        else:
            print(str(exc), file=sys.stderr)
            if results: print('Removed before cleanup stopped: ' + size(sum(r.get('removed_bytes', 0) for r in results)), file=sys.stderr)
        return 1
    finally:
        if portal is not None:
            try:
                portal.call('POST', '/api/v1/auth/logout')
            except (ValueError, OSError):
                pass


if __name__ == '__main__':
    sys.exit(main())
