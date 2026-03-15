# Standard libraries
import re
from pathlib import Path
from typing import Dict, List

import yaml

_CONFIG_CACHE = None


def load_analysis_config(config_path: Path = None) -> Dict:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE
    config_path = config_path or Path(__file__).parent / "config.yaml"
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            _CONFIG_CACHE = yaml.safe_load(fh) or {}
    except Exception:
        _CONFIG_CACHE = {}
    return _CONFIG_CACHE


def get_platform_patterns(platform: str) -> Dict[str, List[re.Pattern]]:
    cfg = load_analysis_config()
    plat_cfg = cfg.get(platform.lower(), {})
    def compile_list(key):
        out = []
        for pattern in plat_cfg.get(key, []):
            try:
                out.append(re.compile(pattern))
            except re.error:
                continue
        return out
    sinks = {}
    for entry in plat_cfg.get("sinks", []):
        try:
            name, desc, pattern = entry
            sinks[name] = (re.compile(pattern), desc)
        except (ValueError, re.error):
            continue
    return {
        "sources": compile_list("sources"),
        "sinks": sinks,
        "sanitizers": compile_list("sanitizers"),
        "safe_callees": set(plat_cfg.get("safe_callees", [])),
        "max_taint_passes": int(cfg.get("max_taint_passes", 7)),
        "_analyzer_block": plat_cfg.get("analyzer", {}),
    }
