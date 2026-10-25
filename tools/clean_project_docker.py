#!/usr/bin/env python3
"""Remove this Compose project's containers, volumes, networks and service images."""
import argparse
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Delete project Docker data; otherwise preview only')
    parser.add_argument('--project-name', help='Compose project name, if startup used a custom name')
    args = parser.parse_args()
    command = ['docker', 'compose', '--project-directory', str(ROOT), '-f', str(ROOT / 'docker-compose.yml')]
    if args.project_name:
        command += ['--project-name', args.project_name]
    command += ['down', '--rmi', 'all', '--volumes', '--remove-orphans']
    print('Deletes project containers, networks, service images and volumes, including accounts and saved scans.', flush=True)
    print('Shared build cache and bind-mounted host files are preserved. Shared service images may fail to remove if in use.', flush=True)
    print(shlex.join(command), flush=True)
    if not args.execute:
        print('Preview only. Add --execute to delete.')
        return 0
    if input('Type DELETE DAKSH to continue: ') != 'DELETE DAKSH':
        print('Cancelled.')
        return 1
    return subprocess.run(command, check=False).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc) or 'Cancelled.')
