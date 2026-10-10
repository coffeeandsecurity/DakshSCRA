"""Directory navigation must not hide access errors or escape configured roots."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from fastapi import HTTPException
from . import config, main


class FilesystemBrowserTests(TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root / 'project' / 'src').mkdir(parents=True)
        self.env = patch.dict(os.environ, {'DAKSH_BROWSE_ROOTS': str(self.root), 'DAKSH_HOST_PATHS': '[]'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_navigate_select_and_up(self):
        listing = main.fs_list('')
        self.assertEqual(str(self.root), listing.current)
        self.assertIsNone(listing.parent)
        project = next(x.path for x in listing.directories if x.name == 'project')
        listing = main.fs_list(project)
        self.assertEqual(str(self.root), listing.parent)
        self.assertEqual(['src'], [x.name for x in listing.directories])
        empty = main.fs_list(listing.directories[0].path)
        self.assertEqual([], empty.directories)
        self.assertEqual(Path(empty.current), main._resolve_target_path(empty.current, [self.root]))

    def test_permission_error_is_not_an_empty_success(self):
        with patch.object(Path, 'iterdir', side_effect=PermissionError('denied')):
            with self.assertRaises(HTTPException) as error:
                main.fs_list(str(self.root))
        self.assertEqual(403, error.exception.status_code)
        self.assertIn('Permission denied', error.exception.detail)

    def test_outside_and_symlink_escape_rejected(self):
        (self.root / 'escape').symlink_to(self.root.parent, target_is_directory=True)
        for path in (self.root.parent, self.root / 'escape'):
            with self.assertRaises(HTTPException) as error:
                main.fs_list(str(path))
            self.assertEqual(403, error.exception.status_code)
        self.assertNotIn('escape', [x.name for x in main.fs_list('').directories])

    def test_invalid_allowlist_does_not_expand_access(self):
        with patch.dict(os.environ, {'DAKSH_BROWSE_ROOTS': str(self.root / 'missing')}):
            self.assertEqual([], config.get_browse_roots())
            with self.assertRaises(HTTPException) as error:
                main.fs_list('')
            self.assertEqual(503, error.exception.status_code)

    def test_nested_shortcut_can_navigate_to_allowed_parent(self):
        with patch.dict(os.environ, {'DAKSH_BROWSE_ROOTS': f'{self.root}/project,{self.root}'}):
            self.assertEqual(str(self.root), main.fs_list(str(self.root / 'project')).parent)

    def test_all_windows_drive_aliases_and_canonical_target(self):
        metadata = json.dumps([{'source': 'Z:/', 'path': str(self.root), 'label': 'Z: drive'}])
        with patch.dict(os.environ, {'DAKSH_HOST_PATHS': metadata}):
            for raw in ('Z:\\project', '/mnt/z/project', '/run/desktop/mnt/host/z/project'):
                self.assertEqual(str(self.root / 'project'), main.fs_list(raw).current)
                self.assertEqual(self.root / 'project', main._resolve_target_path(raw, [self.root]))
            self.assertEqual('Z: drive', main.fs_list('').shortcuts[0].name)

    def test_pasted_unix_root_and_host_symlinks(self):
        metadata = json.dumps([{'source': '/', 'path': str(self.root), 'label': 'Host filesystem'}])
        (self.root / 'host-link').symlink_to('/project/src', target_is_directory=True)
        with patch.dict(os.environ, {'DAKSH_HOST_PATHS': metadata}):
            self.assertEqual(str(self.root), main.fs_list('/').current)
            self.assertEqual(str(self.root / 'project'), main.fs_list('/project').current)
            entries = {x.name: x.path for x in main.fs_list('').directories}
            self.assertEqual(str(self.root / 'project/src'), entries['host-link'])

    def test_roots_deduplicate_and_keep_explicit_boundary(self):
        with patch.dict(os.environ, {'DAKSH_BROWSE_ROOTS': f'{self.root},{self.root}/.'}):
            self.assertEqual([str(self.root)], config.get_browse_roots())
