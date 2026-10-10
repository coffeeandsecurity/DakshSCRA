"""Run-local exclusions shared by discovery, dependencies and analyzers."""
import fnmatch
import os
from pathlib import Path

from core.scan_catalog import CHECK_IDS, check_class, registered_classes

OPTION_FIELDS = ('exclude_checks', 'exclude_paths', 'exclude_types', 'exclude_keywords',
                 'recon_strict', 'baseline_mode', 'baseline_file', 'review_config', 'state_mode')


class ScanScope:
    def __init__(self, root=None, exclude_checks=(), exclude_paths=(), exclude_types=(), exclude_keywords=()):
        self.root = Path(root).expanduser().resolve() if root else None
        unknown = set(exclude_checks) - CHECK_IDS
        if unknown:
            raise ValueError('Unknown check classes: ' + ', '.join(sorted(unknown)))
        self.exclude_checks = frozenset(exclude_checks)
        self.paths = tuple(p.strip().replace('\\', '/') for p in exclude_paths if p.strip())
        self.types = tuple(p.strip().lower() for p in exclude_types if p.strip())
        self.keywords = tuple(p.strip().casefold() for p in exclude_keywords if p.strip())
        self.cache = {}

    def allows_check(self, title='', category='', rule_id=''):
        if not self.exclude_checks:
            return True
        key = registered_classes().get(rule_id) or check_class(title, category, rule_id)
        return key not in self.exclude_checks

    def _relative(self, path):
        path = Path(os.path.abspath(path))
        if self.root is None:
            return None
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return None

    def allows_path(self, path):
        if not self.paths:
            return True
        relative = self._relative(path)
        if relative is None:
            return True
        parts = relative.split('/')
        ancestors = ['/'.join(parts[:index]) for index in range(1, len(parts) + 1)]
        for pattern in self.paths:
            token = pattern.rstrip('/')
            # A trailing /** includes the directory itself; globstar also
            # matches root-level files, unlike plain fnmatch('**/*.ext').
            candidates = (token, token[3:]) if token.startswith('**/') else (token,)
            for candidate in candidates:
                if any(fnmatch.fnmatchcase(item, candidate) or item == (candidate[:-3] if candidate.endswith('/**') else candidate)
                       for item in ancestors):
                    return False
        return True

    def allows_file(self, path):
        if not (self.paths or self.types or self.keywords):
            return True
        if not self.allows_path(path):
            return False
        if self._relative(path) is None:
            return True
        path = Path(path)
        name = path.name.lower()
        for token in self.types:
            pattern = token if any(c in token for c in '*?[') else '*' + (token if token.startswith('.') else '.' + token)
            if fnmatch.fnmatchcase(name, pattern):
                return False
        if not self.keywords or not path.is_file():
            return True
        try:
            stat = path.stat()
            identity = (str(path), stat.st_size, stat.st_mtime_ns)
            if identity not in self.cache:
                # Stream with overlap so keywords across chunk boundaries
                # remain detectable without loading arbitrarily large files.
                with path.open('rb') as source:
                    prefix = source.read(4)
                encoding = ('utf-32' if prefix.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff'))
                            else 'utf-16' if prefix.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
                for candidate in (encoding, 'ISO-8859-1'):
                    try:
                        with path.open(encoding=candidate) as source:
                            overlap = max(map(len, self.keywords))
                            tail, allowed = '', True
                            while chunk := source.read(65536):
                                text = tail + chunk.casefold()
                                if any(word in text for word in self.keywords):
                                    allowed = False
                                    break
                                tail = text[-overlap:]
                        break
                    except UnicodeError:
                        continue
                self.cache[identity] = allowed
            return self.cache[identity]
        except (OSError, UnicodeError):
            # Unreadable files remain candidates and retain scanner diagnostics.
            return True


_scope = ScanScope()


def configure_scope(root=None, **options):
    global _scope
    _scope = ScanScope(root, **{key: options.get(key, ()) for key in
                              ('exclude_checks', 'exclude_paths', 'exclude_types', 'exclude_keywords')})
    return _scope


def current_scope():
    return _scope


def allows_check(title='', category='', rule_id=''):
    return _scope.allows_check(title, category, rule_id)


def allows_file(path):
    return _scope.allows_file(path)


def walk_source(root, **options):
    if not (_scope.paths or _scope.types or _scope.keywords):
        yield from os.walk(root, **options)
        return
    for directory, children, names in os.walk(root, **options):
        children[:] = [name for name in children if _scope.allows_path(Path(directory) / name)]
        yield directory, children, [name for name in names if allows_file(Path(directory) / name)]


def glob_source(root, pattern):
    if not (_scope.paths or _scope.types or _scope.keywords):
        return Path(root).rglob(pattern)
    return (path for path in Path(root).rglob(pattern)
            if (_scope.allows_path(path) and (not path.is_file() or allows_file(path))))
