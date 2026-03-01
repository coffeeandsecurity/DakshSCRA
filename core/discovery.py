# Standard libraries
import fnmatch
import json
import os
import re

# Local application imports
import state.runtime_state as runtime
import utils.file_utils as fileops
from utils.log_utils import get_logger
import utils.result_utils as result
import utils.rules_utils as rulesops
from utils.rules_utils import get_available_rules, get_rules_path_or_filetypes

logger = get_logger(__name__)


def _read_text_limited(file_path, max_bytes=200000):
    """
    Read up to max_bytes from a text-like file using utf-8 fallback decoding.
    """
    try:
        with open(file_path, "rb") as f_obj:
            raw = f_obj.read(max_bytes)
        return raw.decode("utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return ""


def detect_mobile_rule_types(sourcepath):
    """
    Detect mobile platforms/frameworks from common project markers.

    Returns:
        set: Detected platform names compatible with rulesconfig.xml.
    """

    detected = set()

    for root, dirs, files in os.walk(sourcepath):
        files_set = set(files)

        # Native Android markers
        if "AndroidManifest.xml" in files_set or "proguard-rules.pro" in files_set:
            detected.add("android")

        for gradle_name in ("build.gradle", "build.gradle.kts"):
            if gradle_name in files_set:
                gradle_content = _read_text_limited(os.path.join(root, gradle_name))
                if re.search(r"com\.android\.(application|library)", gradle_content):
                    detected.add("android")

        # Native iOS markers
        if "Info.plist" in files_set or "Podfile" in files_set or "project.pbxproj" in files_set:
            detected.add("ios")
        if "AppDelegate.swift" in files_set or "AppDelegate.m" in files_set:
            detected.add("ios")
        if any(d.endswith(".xcodeproj") or d.endswith(".xcworkspace") for d in dirs):
            detected.add("ios")

        # Flutter markers (cross-platform)
        if "pubspec.yaml" in files_set:
            pubspec = _read_text_limited(os.path.join(root, "pubspec.yaml"))
            if re.search(r"(?m)^\s*flutter\s*:", pubspec):
                detected.update({"flutter", "android", "ios"})
        for dart_file in [f for f in files if f.endswith(".dart")]:
            dart_content = _read_text_limited(os.path.join(root, dart_file))
            if re.search(r"import\s+['\"]package:flutter/", dart_content):
                detected.update({"flutter", "android", "ios"})
                break

        # JS-based mobile frameworks (React Native / Ionic / NativeScript / Cordova)
        if "package.json" in files_set:
            package_json_path = os.path.join(root, "package.json")
            content = _read_text_limited(package_json_path)

            try:
                package_data = json.loads(content) if content.strip() else {}
            except json.JSONDecodeError:
                package_data = {}

            deps = {}
            deps.update(package_data.get("dependencies", {}))
            deps.update(package_data.get("devDependencies", {}))
            dep_names = set(deps.keys())
            dep_blob = " ".join(dep_names).lower() + " " + content.lower()

            if "react-native" in dep_blob or "expo" in dep_blob:
                detected.update({"reactnative", "android", "ios"})
            if "@ionic/" in dep_blob or "@capacitor/" in dep_blob:
                detected.update({"ionic", "android", "ios"})
            if "@nativescript/" in dep_blob or "tns-core-modules" in dep_blob:
                detected.update({"nativescript", "android", "ios"})
            if "cordova" in dep_blob:
                detected.update({"cordova", "android", "ios"})

        if "capacitor.config.json" in files_set or "capacitor.config.ts" in files_set:
            detected.update({"ionic", "android", "ios"})
        if "config.xml" in files_set:
            cfg_content = _read_text_limited(os.path.join(root, "config.xml")).lower()
            if "cordova" in cfg_content or "phonegap" in cfg_content:
                detected.update({"cordova", "android", "ios"})

        # .NET mobile (Xamarin / MAUI)
        for csproj in [f for f in files if f.endswith(".csproj")]:
            csproj_content = _read_text_limited(os.path.join(root, csproj))
            if re.search(r"(Xamarin|UseMaui|Maui|net\d+\.\d+-android|net\d+\.\d+-ios)", csproj_content, re.IGNORECASE):
                detected.update({"xamarin", "android", "ios"})

    return detected


def discover_files(codebase, sourcepath, mode):
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
            ft = rulesops.get_rules_path_or_filetypes(platform, "filetypes")
            platform_filetypes[platform] = list(dict.fromkeys(ft.split(",")))
            platform_extensions[platform] = []  # Initialize empty list for each platform

            print(f"         [-] {platform.capitalize()} Filetypes: {platform_filetypes[platform]}")

    elif mode == 2:  # Default to *.* if mode 2 is used
        platform_filetypes = {platform: ['*.*'] for platform in platforms}
        platform_extensions = {platform: [] for platform in platforms}

    master_file_paths = runtime.runtime_dirpath / "filepaths.log"
    platform_file_paths = []  # List to store paths of platform-specific logs

    try:
        with open(master_file_paths, "w+") as master_log:

            # Traverse the source path to discover and log files
            for root, _, filenames in os.walk(sourcepath):
                total_files_count += len(filenames)

                for platform, extensions in platform_filetypes.items():
                    platform_log_path = platform_dir / f"filepaths_{platform}.log"
                    if platform_log_path not in platform_file_paths:
                        platform_file_paths.append(platform_log_path)  # Append each platform log path

                    try:
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

                                    ext_value = fileops.get_file_extension(full_path)
                                    if ext_value and ext_value not in platform_extensions[platform]:
                                        platform_extensions[platform].append(ext_value)
                    except OSError as exc:
                        logger.error("Failed to write platform log %s: %s", platform_log_path, exc)
    except OSError as exc:
        logger.error("Failed to write master filepath log at %s: %s", master_file_paths, exc)
        return master_file_paths, platform_file_paths  # Early return; nothing else to do

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

    result.update_scan_summary("detection_summary.total_project_files_identified", str(total_files_count))
    result.update_scan_summary("detection_summary.total_files_identified", str(identified_files_count))
    result.update_scan_summary("detection_summary.file_extensions_identified", platform_extensions_filtered)
    #result.update_scan_summary("detection_summary.file_extensions_identified", platform_extensions)

    runtime.totalFilesIdentified = identified_files_count

    return master_file_paths, platform_file_paths  # Return master log path and platform log paths



# This is a test function and will be merged with the above function
def recon_discover_files(codebase, sourcepath, mode):
    if mode == 1:
        ft = re.sub(r"\s+", "", rulesops.get_rules_path_or_filetypes(codebase, "filetypes"))
        filetypes = list(ft.split(","))
        print("     [-] Filetypes Selected: " + str(filetypes))
        result.update_scan_summary("inputs_received.file_extensions_selected", str(filetypes))
    elif mode == 2:
        filetypes = ['*.*']
        result.update_scan_summary("inputs_received.file_extensions_selected", str(filetypes))

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
                fext.append(fileops.get_file_extension(filename))

    print("     [-] Total files to be scanned: " + str(len(identified_files)))
    result.update_scan_summary("detection_summary.total_files_identified", str(len(identified_files)))
    result.update_scan_summary("detection_summary.file_extensions_identified", str(fext))

    runtime.totalFilesIdentified = str(len(identified_files))

    fext = list(dict.fromkeys(filter(None, fext)))

    print("     [-] File Extensions Identified: " + str(fext))
    result.update_scan_summary("detection_summary.file_extensions_identified", str(fext))

    return identified_files


def auto_detect_rule_types(sourcepath):
    """
    Automatically detects which rule platforms (e.g., php, java, cpp) are applicable
    based on the file extensions found in the target directory.

    Parameters:
        sourcepath (str or Path): Directory path to search for files.

    Returns:
        str: Comma-separated platform names whose filetypes match discovered files.
    """

    supported_rules = rulesops.get_available_rules(exclude=["common"])

    platform_patterns = {}
    for rule in supported_rules.split(','):
        filetypes = rulesops.get_rules_path_or_filetypes(rule, "filetypes")
        patterns = [p.strip() for p in list(dict.fromkeys(filetypes.split(","))) if p.strip()]
        platform_patterns[rule] = patterns

    # Build reverse lookup to avoid walking tree once per platform.
    pattern_to_platforms = {}
    for platform, patterns in platform_patterns.items():
        for patt in patterns:
            pattern_to_platforms.setdefault(patt, set()).add(platform)

    detected_platforms = set()
    pending_platforms = set(platform_patterns.keys())
    all_patterns = list(pattern_to_platforms.keys())

    for _, _, files in os.walk(sourcepath):
        if not pending_platforms:
            break
        for filename in files:
            for patt in all_patterns:
                if fnmatch.fnmatch(filename, patt):
                    newly_detected = pattern_to_platforms[patt].intersection(pending_platforms)
                    if newly_detected:
                        detected_platforms.update(newly_detected)
                        pending_platforms.difference_update(newly_detected)
                    if not pending_platforms:
                        break
            if not pending_platforms:
                break

    mobile_platforms = detect_mobile_rule_types(sourcepath)

    # Deduplicate and sort
    unique_platforms = sorted(detected_platforms.union(mobile_platforms))
    result_str = ",".join(unique_platforms)

    return result_str


# Backward-compatible aliases for legacy callers.
detectMobileRuleTypes = detect_mobile_rule_types
discoverFiles = discover_files
reconDiscoverFiles = recon_discover_files
autoDetectRuleTypes = auto_detect_rule_types
