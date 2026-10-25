#!/usr/bin/env python3
"""Purge all projects on the selected Docker engine, including running containers and named volumes."""
import argparse
import subprocess


def run(*args):
    subprocess.run(['docker', *args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Delete all Docker project data; otherwise preview only')
    args = parser.parse_args()
    print('Deletes ALL running/stopped containers, unused images, networks, named/anonymous volumes and default-builder cache.', flush=True)
    print('Scope: selected Docker context / DOCKER_HOST, which may be remote. Docker installation and bind-mounted host files remain.', flush=True)
    print('Plan: container ls -aq -> container rm --force; system prune --all --volumes --force; volume prune --all --force; builder prune --all --force.', flush=True)
    if not args.execute:
        print('Preview only. Add --execute to delete.')
        return 0
    run('context', 'show')
    run('info', '--format', 'Engine: {{.Name}} ({{.ID}})')
    if input('Permanently delete ALL Docker containers and data, including accounts and saved scans? [y/N]: ').strip().lower() not in ('y', 'yes'):
        print('Cancelled.')
        return 1
    containers = subprocess.run(['docker', 'container', 'ls', '-aq'], capture_output=True, text=True, check=True).stdout.split()
    for container in containers:
        run('container', 'rm', '--force', container)
    run('system', 'prune', '--all', '--volumes', '--force')
    run('volume', 'prune', '--all', '--force')
    run('builder', 'prune', '--all', '--force')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, EOFError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc) or 'Cancelled.')
