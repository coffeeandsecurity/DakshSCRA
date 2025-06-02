# Standard libraries
import json
import os

# Local application imports
import state.runtime_state as runtime



def updateScanSummary(key, value):
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

    # Create the JSON file with default data if the file is missing.
    if not os.path.isfile(json_filename):
        default_data = {
            "inputs_received": {
                "rule_selected": "",
                "total_rules_loaded": 0,
                "platform_specific_rules": 0,
                "common_rules": 0,
                "target_directory": "",
                "filetypes_selected": "",
                "file_extensions_selected": []
            },
            "detection_summary": {
                "total_project_files_identified": 0,
                "total_files_identified": 0,
                "total_files_scanned": 0,
                "file_extensions_identified": {},
                "areas_of_interest_identified": 0,
                "file_paths_areas_of_interest_identified": 0
            },
            "scanning_timeline": {
                "scan_start_time": "",
                "scan_end_time": "",
                "scan_duration": ""
            },
            "source_files_scanning_summary": {
                "matched_rules": [],
                "unmatched_rules": []
            },
            "paths_scanning_summary": {
                "matched_rules": [],
                "unmatched_rules": []
            }
        }

        with open(json_filename, "w") as file:
            json.dump(default_data, file, indent=4)

    try:
        with open(json_filename, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        data = {}

    # Split the key into nested levels
    levels = key.split(".")
    current = data

    try:
        # Traverse the levels to access the innermost dictionary
        for level in levels[:-1]:
            current = current[level]

        # If updating file extensions, ensure it's grouped by platform
        if key == "detection_summary.file_extensions_identified":
            # Merge new platform-specific extensions with existing ones
            if not isinstance(current[levels[-1]], dict):
                current[levels[-1]] = {}  # Initialize as a dictionary if not already

            for platform, extensions in value.items():
                current[levels[-1]].setdefault(platform, []).extend(extensions)
                # Remove duplicates
                current[levels[-1]][platform] = list(set(current[levels[-1]][platform]))

        else:
            # Update the specific entry in the dictionary
            current[levels[-1]] = value

        with open(json_filename, "w") as file:
            json.dump(data, file, indent=4)

    except (KeyError, TypeError) as e:
        print(f"An error occurred while updating entry '{key}': {str(e)}")
        print(f"Entry '{key}' does not exist or is not accessible.")
    except Exception as e:
        print(f"An error occurred while updating entry '{key}': {str(e)}")

