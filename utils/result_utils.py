# Standard libraries
import json
import os

# Local application imports
import state.runtime_state as runtime
from utils.log_utils import get_logger

logger = get_logger(__name__)


def _default_summary():
    return {
        "inputs_received": {
            "rule_selected": "",
            "total_rules_loaded": 0,
            "platform_specific_rules": 0,
            "common_rules": 0,
            "target_directory": "",
            "filetypes_selected": "",
            "file_extensions_selected": [],
        },
        "detection_summary": {
            "total_project_files_identified": 0,
            "total_files_identified": 0,
            "total_files_scanned": 0,
            "file_extensions_identified": {},
            "areas_of_interest_identified": 0,
            "file_paths_areas_of_interest_identified": 0,
            "suppressed_findings": 0,
        },
        "scanning_timeline": {
            "scan_start_time": "",
            "scan_end_time": "",
            "scan_duration": "",
        },
        "source_files_scanning_summary": {
            "matched_rules": [],
            "unmatched_rules": [],
        },
        "paths_scanning_summary": {
            "matched_rules": [],
            "unmatched_rules": [],
        },
    }


def _load_or_create_summary(path):
    if not os.path.isfile(path):
        data = _default_summary()
        with open(path, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, indent=4)
        return data

    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            data = json.load(file_obj)
            return data if isinstance(data, dict) else _default_summary()
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to read scan summary %s: %s", path, exc)
        data = _default_summary()
        with open(path, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, indent=4)
        return data


def _ensure_nested_dict(data, levels):
    current = data
    for level in levels:
        if level not in current or not isinstance(current[level], dict):
            current[level] = {}
        current = current[level]
    return current


def update_scan_summary(key, value):
    """
    Updates a specified entry in the scan summary JSON file.

    If the JSON file is missing, it creates one with default data.

    Parameters:
        key (str): The key path to the entry in the JSON structure to update.
        value (any): The new value to assign to the specified key.

    Returns:
        None: The function modifies the JSON file in place.
    """
    json_filename = runtime.scanSummary_Fpath
    data = _load_or_create_summary(json_filename)

    levels = key.split(".")
    if len(levels) < 2:
        logger.error("Invalid scan summary key path: %s", key)
        return

    parent = _ensure_nested_dict(data, levels[:-1])
    leaf = levels[-1]

    # Merge platform extension map to preserve previous values.
    if key == "detection_summary.file_extensions_identified" and isinstance(value, dict):
        if leaf not in parent or not isinstance(parent[leaf], dict):
            parent[leaf] = {}
        for platform, extensions in value.items():
            existing = parent[leaf].setdefault(platform, [])
            existing.extend(extensions if isinstance(extensions, list) else [extensions])
            parent[leaf][platform] = sorted(set(filter(None, existing)))
    else:
        parent[leaf] = value

    try:
        with open(json_filename, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, indent=4)
    except OSError as exc:
        logger.error("Failed to write scan summary %s: %s", json_filename, exc)


# Backward-compatible alias for legacy callers.
updateScanSummary = update_scan_summary
