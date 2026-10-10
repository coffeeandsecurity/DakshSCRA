"""Cached structural project-flow adapter for executable language profiles."""
from .base import LanguageAdapter
from ..portable_profiles import EXTENSIONS


class PortableAdapter(LanguageAdapter):
    def __init__(self, language, catalog=None):
        super().__init__(catalog)
        self.language_id = language
        self.adapter_name = language + '-project-flow'
        self.adapter_version = '1'
        self.extensions = EXTENSIONS[language]

    def parse_file(self, path):
        from ..portable_flow import parse_portable
        return parse_portable(path, self.language_id)
