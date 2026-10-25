"""Semantic concept catalog shared by language adapters."""

import json
import re
from pathlib import Path
from typing import Dict, Iterable, Set


class SemanticCatalog:
    def __init__(self, data=None):
        self.data = data or {}

    @classmethod
    def load(cls, path=None):
        catalog_path = Path(path) if path else Path(__file__).resolve().parents[2] / "rules/scanning/semantics/rdl/catalog.json"
        return cls(json.loads(catalog_path.read_text(encoding="utf-8")))

    def concepts_for_call(self, language: str, qualified_name: str) -> Set[str]:
        mappings: Dict[str, Iterable[str]] = self.data.get("languages", {}).get(language, {}).get("calls", {})
        result = set()
        lowered = qualified_name.lower()
        for name, concepts in mappings.items():
            expected = name.lower()
            if lowered == expected or lowered.endswith("." + expected):
                result.update(concepts)
        for concept, patterns in self.data.get("languages", {}).get(language, {}).get("symbol_patterns", {}).items():
            if any(re.search(pattern, qualified_name, re.IGNORECASE) for pattern in patterns):
                result.add(concept)
        return result

    def secret_name(self, name: str) -> bool:
        lowered = name.lower()
        if lowered.startswith(('code_', 'text_', 'message_', 'error_', 'label_')) or lowered.endswith(('_name', '_label', '_field', '_key_name', '_message', '_error', '_regex', '_pattern')):
            return False
        return any(marker in lowered for marker in self.data.get("secret_name_markers", []))

    def weak_secret_literal(self, value: str, name: str = '') -> bool:
        minimum = int(self.data.get("secret_literal_min_length", 12))
        if any(marker in name.lower() for marker in ('password', 'passwd')):
            minimum = 1
        return len(value) >= minimum and not value.startswith(("http://", "https://", "/"))
