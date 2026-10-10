"""Language-adapter registry with explicit selection and capabilities."""

from pathlib import Path
from typing import Dict, Iterable, Optional

from .base import LanguageAdapter


class AdapterRegistry:
    def __init__(self):
        self._adapters: Dict[str, LanguageAdapter] = {}

    def register(self, adapter: LanguageAdapter):
        if not adapter.language_id:
            raise ValueError("adapter language_id is required")
        if adapter.language_id in self._adapters:
            raise ValueError("adapter already registered: {0}".format(adapter.language_id))
        descriptor = adapter.descriptor()
        if not descriptor.adapter_name or not descriptor.adapter_version:
            raise ValueError("adapter name and version are required")
        if descriptor.ir_schema_version != 1:
            raise ValueError("unsupported IR schema version: {0}".format(descriptor.ir_schema_version))
        if not descriptor.extensions or any(not item.startswith(".") or item != item.lower() for item in descriptor.extensions):
            raise ValueError("adapter extensions must be unique lowercase suffixes")
        if len(set(descriptor.extensions)) != len(descriptor.extensions):
            raise ValueError("adapter extensions must be unique lowercase suffixes")
        self._adapters[adapter.language_id] = adapter

    def get(self, language_id: str) -> Optional[LanguageAdapter]:
        return self._adapters.get(language_id)

    def for_path(self, path: Path) -> Optional[LanguageAdapter]:
        return next((adapter for adapter in self._adapters.values() if adapter.supports(path)), None)

    def languages(self):
        return tuple(sorted(self._adapters))


def default_registry():
    from .c import CAdapter
    from .python import PythonAdapter
    from .toy import DakshScriptAdapter
    from .tokenized import CppAdapter, GoAdapter, JavaScriptAdapter, PHPAdapter
    registry = AdapterRegistry()
    registry.register(CAdapter())
    registry.register(PythonAdapter())
    registry.register(DakshScriptAdapter())
    registry.register(JavaScriptAdapter())
    registry.register(GoAdapter())
    registry.register(CppAdapter())
    registry.register(PHPAdapter())
    from .portable import PortableAdapter
    from ..portable_profiles import EXTENSIONS
    for language in EXTENSIONS:
        if registry.get(language) is None:
            registry.register(PortableAdapter(language, catalog=registry.get("python").catalog))
    return registry
