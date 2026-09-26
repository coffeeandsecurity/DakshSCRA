#!/usr/bin/env python3
"""Start the Docker Web UI with host directories discovered before container creation."""
import argparse
import json
import os
from pathlib import Path
import platform
import string
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def discover_locations(system=None, release=None, home=None, is_dir=None, environ=None, is_mount=None):
    system = system or platform.system()
    release = release if release is not None else platform.release()
    home = str(home or Path.home()).replace('\\', '/')
    is_dir = is_dir or (lambda p: Path(p).is_dir())
    is_mount = is_mount or (lambda p: Path(p).is_mount())
    environ = os.environ if environ is None else environ
    wsl = system == 'Linux' and ('microsoft' in release.lower() or bool(environ.get('WSL_DISTRO_NAME')))
    kind = 'WSL' if wsl else system
    locations = []

    def add(source, target, label):
        source = str(source).replace('\\', '/')
        if is_dir(source) and not any(x['source'].rstrip('/') == source.rstrip('/') for x in locations):
            locations.append(dict(source=source, path=target, label=label))

    if system == 'Windows':
        # The base root mount represents the system drive. Other drives get
        # distinct mounts; a missing drive is never replaced by a temp folder.
        primary = environ.get('SystemDrive', 'C:').rstrip('/\\') + '/'
        add(primary, '/host/root', f'{primary[:2]} drive')
        for letter in string.ascii_uppercase:
            add(f'{letter}:/', f'/host/drives/{letter.lower()}', f'{letter}: drive')
    else:
        add('/', '/host/root', 'WSL filesystem' if wsl else f'{system} filesystem')
        if wsl:
            for letter in string.ascii_lowercase:
                if is_mount(f'/mnt/{letter}'):
                    add(f'/mnt/{letter}', f'/host/drives/{letter}', f'{letter.upper()}: drive')
        for source, label in [('/Users', 'Users'), ('/Volumes', 'Volumes'),
                              ('/home', 'Home folders'), ('/mnt', 'Mounted filesystems'),
                              ('/media', 'Removable media'), ('/srv', 'Server files')]:
            add(source, '/host/locations/' + source.strip('/'), label)
    add(home, '/host/user', 'My home')
    return kind, locations


def bind(source, target):
    return dict(type='bind', source=source, target=target, read_only=True,
                bind={'create_host_path': False})


def make_override(kind, locations, values):
    locations = [dict(x) for x in locations]
    custom = [('DAKSH_HOST_MOUNT', '/host/root', 'Host filesystem'),
              ('DAKSH_HOST_SOURCE', '/host/source', 'Source folder')]
    custom += [(f'DAKSH_HOST_{c.upper()}', f'/host/drives/{c}', f'{c.upper()}: drive') for c in string.ascii_lowercase]
    for key, target, label in custom:
        source = values.get(key, '').strip()
        if source:
            locations = [x for x in locations if x['path'] != target]
            locations.append(dict(source=source.replace('\\', '/'), path=target, label=label))
    scan_root = values.get('DAKSH_SCAN_ROOT', '').strip() or str(ROOT)
    locations.insert(0, dict(source=scan_root.replace('\\', '/'), path='/scan-targets', label='Scan targets'))
    mounts = [bind(x['source'], x['path']) for x in locations]
    environment = {'DAKSH_HOST_OS': kind, 'DAKSH_HOST_PATHS': json.dumps(locations)}
    return {'services': {name: {'volumes': mounts, 'environment': environment} for name in ('api', 'cli')}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-d', '--detach', action='store_true', help='Run in the background')
    parser.add_argument('--no-build', action='store_true', help='Use existing images')
    parser.add_argument('--dry-run', action='store_true', help='Show detected mounts without starting or changing anything')
    args = parser.parse_args()
    base = ['docker', 'compose', '--project-directory', str(ROOT), '-f', str(ROOT / 'docker-compose.yml')]
    try:
        # Compose owns .env parsing, including quoted values and shell overrides.
        result = subprocess.run(base + ['config', '--environment'], capture_output=True, text=True, check=True)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        kind, locations = discover_locations()
        override = make_override(kind, locations, values)
        if not any(x['path'] == '/host/root' for x in locations):
            raise RuntimeError('Could not detect a host root directory.')
        if args.dry_run:
            print(json.dumps(override, indent=2))
            return 0
        context = subprocess.run(['docker', 'context', 'inspect'], capture_output=True, text=True, check=True)
        endpoint = os.environ.get('DOCKER_HOST') or json.loads(context.stdout)[0]['Endpoints']['docker']['Host']
        if endpoint.startswith(('ssh://', 'tcp://', 'http://', 'https://')):
            raise RuntimeError('Automatic mounts require a local Docker engine. Run this launcher on the Docker host.')
        output = ROOT / 'runtime' / 'docker-host.compose.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        # Escape Compose interpolation in literal paths (for example a $ in a username).
        output.write_text(json.dumps(override, indent=2).replace('$', '$$'), encoding='utf-8')
        print(f'Detected {kind}. Host folders are mounted read-only:')
        for item in override['services']['api']['volumes']:
            print(f"  {item['source']} -> {item['target']}")
        cmd = base + ['-f', str(output), 'up']
        if not args.no_build:
            cmd.append('--build')
        if args.detach:
            cmd.append('-d')
        cmd += ['api', 'web']
        result = subprocess.run(cmd)
        if result.returncode:
            print('If Docker reports a denied mount, allow that host directory in Docker Desktop file sharing and retry.', file=sys.stderr)
        return result.returncode
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'Unable to start Web UI: {exc}', file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
