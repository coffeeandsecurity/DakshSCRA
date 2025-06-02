# Standard libraries
import fnmatch
import os
import re

# Local application imports
import state.runtime_state as runtime
import utils.file_utils as fileops
import utils.result_utils as result
import utils.rules_utils as rulesops
from utils.rules_utils import getAvailableRules, getRulesPath_OR_FileTypes



def discoverFiles(codebase, sourcepath, mode):
    """
    Discovers files for specified platforms and logs paths to platform-specific and master log files.

    Parameters:
        codebase (str): Comma-separated list of platforms to discover files for.
        sourcepath (str): Directory path to search for files.
        mode (int): Determines file type retrieval method (1 for specific types, 2 for all types).

    Returns:
        tuple: Paths to the master log file and platform-specific log files.
    """

    platforms = list(dict.fromkeys(re.sub(r"\s+", "", codebase).split(",")))
    print(f"     [-] Selected Platforms and Respective Filetypes:")

    platform_filetypes = {}  # Store platform-specific filetypes
    platform_extensions = {}  # Store identified extensions per platform
    matches, total_files_count = [], 0
    identified_files_count = 0

    # Create or return the /runtime/platform directory and clear existing logs
    platform_dir = runtime.runtime_dirpath / "platform"
    platform_dir.mkdir(parents=True, exist_ok=True)

    # Clear all existing platform-specific log files
    for log_file in platform_dir.glob("filepaths_*.log"):
        log_file.unlink()

    # Initialize platform-specific filetypes if mode is 1
    if mode == 1:
        for platform in platforms:
            ft = rulesops.getRulesPath_OR_FileTypes(platform, "filetypes")
            platform_filetypes[platform] = list(dict.fromkeys(ft.split(",")))
            platform_extensions[platform] = []  # Initialize empty list for each platform

            print(f"         [-] {platform.capitalize()} Filetypes: {platform_filetypes[platform]}")

    elif mode == 2:  # Default to *.* if mode 2 is used
        platform_filetypes = {platform: ['*.*'] for platform in platforms}
        platform_extensions = {platform: [] for platform in platforms}

    master_file_paths = runtime.runtime_dirpath / "filepaths.log"
    platform_file_paths = []  # List to store paths of platform-specific logs

    with open(master_file_paths, "w+") as master_log:

        # Traverse the source path to discover and log files
        for root, _, filenames in os.walk(sourcepath):
            total_files_count += len(filenames)

            for platform, extensions in platform_filetypes.items():
                platform_log_path = platform_dir / f"filepaths_{platform}.log"
                platform_file_paths.append(platform_log_path)  # Append each platform log path

                with open(platform_log_path, "a") as platform_log:
                    for ext in extensions:
                        ext = ext.strip()  # Remove spaces
                        matched_files = fnmatch.filter(filenames, ext)

                        for filename in matched_files:
                            full_path = os.path.join(root, filename)

                            platform_log.write(full_path + "\n")
                            master_log.write(full_path + "\n")

                            matches.append(full_path)
                            identified_files_count += 1

                            ext_value = fileops.getFileExtention(full_path)
                            if ext_value and ext_value not in platform_extensions[platform]:
                                platform_extensions[platform].append(ext_value)

    # Filter out platforms with no valid extensions before writing to summary
    platform_extensions_filtered = {
        platform: exts for platform, exts in platform_extensions.items() if exts
    }

    # Print identified extensions by platform
    print("     [-] Discovered/Identified File Types:")
    for platform, exts in platform_extensions_filtered.items():
        print(f"         [-] {platform.capitalize()}: {exts}")
    '''
    for platform, exts in platform_extensions.items():
        if exts:  # Check if the list is not empty
            print(f"         [-] {platform.capitalize()}: {exts}")
        else:
            print(f"         [-] {platform.capitalize()}: None")
        '''
    # Print and update scan summary
    print(f"     [-] Total project files in the directory: {total_files_count}")
    print(f"     [-] Total files to be scanned: {identified_files_count}")

    result.updateScanSummary("detection_summary.total_project_files_identified", str(total_files_count))
    result.updateScanSummary("detection_summary.total_files_identified", str(identified_files_count))
    result.updateScanSummary("detection_summary.file_extensions_identified", platform_extensions_filtered)
    #result.updateScanSummary("detection_summary.file_extensions_identified", platform_extensions)

    runtime.totalFilesIdentified = identified_files_count

    return master_file_paths, platform_file_paths  # Return master log path and platform log paths



# This is a test function and will be merged with the above function
def reconDiscoverFiles(codebase, sourcepath, mode):
    if mode == 1:
        ft = re.sub(r"\s+", "", rulesops.getRulesPath_OR_FileTypes(codebase, "filetypes"))
        filetypes = list(ft.split(","))
        print("     [-] Filetypes Selected: " + str(filetypes))
        result.updateScanSummary("inputs_received.file_extensions_selected", str(filetypes))
    elif mode == 2:
        filetypes = ['*.*']
        result.updateScanSummary("inputs_received.file_extensions_selected", str(filetypes))

    matches = []
    fext = []

    # print("     [-] DakshSCRA Directory Path: " + runtime.root_dir)
    
    identified_files = []  # List to store discovered file paths

    for root, dirnames, filenames in os.walk(sourcepath):
        for extensions in filetypes:
            for filename in fnmatch.filter(filenames, extensions):
                file_path = os.path.join(root, filename)
                matches.append(file_path)
                identified_files.append(file_path)
                fext.append(fileops.getFileExtention(filename))

    print("     [-] Total files to be scanned: " + str(len(identified_files)))
    result.updateScanSummary("detection_summary.total_files_identified", str(len(identified_files)))
    result.updateScanSummary("detection_summary.file_extensions_identified", str(fext))

    runtime.totalFilesIdentified = str(len(identified_files))

    fext = list(dict.fromkeys(filter(None, fext)))

    print("     [-] File Extensions Identified: " + str(fext))
    result.updateScanSummary("detection_summary.file_extensions_identified", str(fext))

    return identified_files


def autoDetectRuleTypes(sourcepath):
    """
    Automatically detects which rule platforms (e.g., php, java, cpp) are applicable
    based on the file extensions found in the target directory.

    Parameters:
        sourcepath (str or Path): Directory path to search for files.

    Returns:
        str: Comma-separated platform names whose filetypes match discovered files.
    """

    supported_rules = rulesops.getAvailableRules(exclude=["common"])
    #print(f"     [-] Supported platform types: {supported_rules}")

    detected_platforms = []
    platform_filetypes = {}

    for rule in supported_rules.split(','):
        filetypes = rulesops.getRulesPath_OR_FileTypes(rule, "filetypes")
        platform_filetypes[rule] = list(dict.fromkeys(filetypes.split(',')))

    for platform, filetypes in platform_filetypes.items():
        for root, _, files in os.walk(sourcepath):
            for pattern in filetypes:
                pattern = pattern.strip()
                if not pattern:
                    continue
                matched = fnmatch.filter(files, pattern)
                if matched:
                    #print(f"[DEBUG] Match found in platform: {platform} | Pattern: {pattern} | Sample match: {matched[0]}")
                    detected_platforms.append(platform)
                    break  # Found a match for this platform

    # Deduplicate and sort
    unique_platforms = sorted(set(detected_platforms))
    result_str = ",".join(unique_platforms)

    return result_str
