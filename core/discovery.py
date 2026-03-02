# Standard libraries
import fnmatch
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# Local application imports
import state.runtime_state as runtime
import utils.file_utils as fileops
from utils.log_utils import get_logger
import utils.result_utils as result
import utils.rules_utils as rulesops
from utils.rules_utils import get_available_rules, get_rules_path_or_filetypes

logger = get_logger(__name__)

# In auto mode, these platforms/frameworks are validated using project markers
# instead of extension-only matching to avoid overlap-based false positives.
AUTO_MARKER_VALIDATED_PLATFORMS = {
    "android",
    "ios",
    "reactnative",
    "flutter",
    "xamarin",
    "ionic",
    "nativescript",
    "cordova",
    "javascript",
}

JSON_DEP_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "require",
    "require-dev",
)


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
    Detect platforms/frameworks from common project and framework markers.

    Returns:
        set: Detected platform names compatible with rulesconfig.xml.
    """

    detected = set()
    ext_counts = {}

    def _bump_ext(fname):
        ext = os.path.splitext(fname)[1].lower()
        if ext:
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

    def _load_json(path_value):
        raw = _read_text_limited(path_value)
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    for root, dirs, files in os.walk(sourcepath):
        files_set = set(files)
        files_set_lower = {f.lower() for f in files_set}
        for file_name in files:
            _bump_ext(file_name)

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
            package_data = _load_json(package_json_path)

            deps = {}
            deps.update(package_data.get("dependencies", {}))
            deps.update(package_data.get("devDependencies", {}))
            dep_names = set(deps.keys())
            dep_blob = " ".join(dep_names).lower() + " " + content.lower()

            # Generic JavaScript ecosystem markers (non-mobile included)
            js_markers = (
                "express", "koa", "fastify", "@nestjs/", "next", "nuxt",
                "react", "vue", "svelte", "@angular/", "@remix-run/", "gatsby",
                "webpack", "vite", "typescript",
            )
            if any(marker in dep_blob for marker in js_markers):
                detected.add("javascript")

            if "react-native" in dep_blob or "expo" in dep_blob:
                detected.update({"reactnative", "android", "ios"})
            if "@ionic/" in dep_blob or "@capacitor/" in dep_blob:
                detected.update({"ionic", "android", "ios"})
            if "@nativescript/" in dep_blob or "tns-core-modules" in dep_blob:
                detected.update({"nativescript", "android", "ios"})
            if "cordova" in dep_blob:
                detected.update({"cordova", "android", "ios"})

        if {"angular.json", "next.config.js", "next.config.ts", "next.config.mjs", "nuxt.config.js", "nuxt.config.ts"}.intersection(files_set_lower):
            detected.add("javascript")

        if "capacitor.config.json" in files_set or "capacitor.config.ts" in files_set:
            detected.update({"ionic", "android", "ios"})
        if "config.xml" in files_set:
            cfg_content = _read_text_limited(os.path.join(root, "config.xml")).lower()
            if "cordova" in cfg_content or "phonegap" in cfg_content:
                detected.update({"cordova", "android", "ios"})

        # PHP + popular frameworks
        if "composer.json" in files_set:
            composer_path = os.path.join(root, "composer.json")
            composer_content = _read_text_limited(composer_path).lower()
            composer_data = _load_json(composer_path)
            req = {}
            req.update(composer_data.get("require", {}))
            req.update(composer_data.get("require-dev", {}))
            req_blob = " ".join(req.keys()).lower() + " " + composer_content
            php_framework_markers = (
                "laravel", "codeigniter", "symfony", "yii", "cakephp",
                "drupal", "joomla", "magento", "laminas", "zendframework", "wordpress",
            )
            if any(m in req_blob for m in php_framework_markers):
                detected.add("php")
            else:
                detected.add("php")
        if {"artisan", "wp-config.php"}.intersection(files_set_lower):
            detected.add("php")

        # Python + popular frameworks
        if {"requirements.txt", "pyproject.toml", "setup.py", "pipfile", "manage.py", "wsgi.py", "asgi.py"}.intersection(files_set_lower):
            detected.add("python")
        if "requirements.txt" in files_set_lower:
            req_content = _read_text_limited(os.path.join(root, "requirements.txt")).lower()
            if any(m in req_content for m in ("django", "flask", "fastapi", "pyramid", "tornado", "sanic", "celery")):
                detected.add("python")
        if "pyproject.toml" in files_set_lower:
            pyproject_content = _read_text_limited(os.path.join(root, "pyproject.toml")).lower()
            if any(m in pyproject_content for m in ("django", "flask", "fastapi", "pyramid", "tornado", "sanic", "celery")):
                detected.add("python")

        # Java + popular frameworks
        if {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}.intersection(files_set_lower):
            detected.add("java")
        if "pom.xml" in files_set_lower:
            pom_content = _read_text_limited(os.path.join(root, "pom.xml")).lower()
            if any(m in pom_content for m in ("spring-boot", "springframework", "hibernate", "struts", "micronaut", "quarkus")):
                detected.add("java")

        # Go + frameworks
        if {"go.mod", "go.sum"}.intersection(files_set_lower):
            detected.add("go")
        if "go.mod" in files_set_lower:
            gomod_content = _read_text_limited(os.path.join(root, "go.mod")).lower()
            if any(m in gomod_content for m in ("gin-gonic/gin", "labstack/echo", "gofiber/fiber", "beego", "go-chi/chi")):
                detected.add("go")

        # Rust + frameworks
        if {"cargo.toml", "cargo.lock"}.intersection(files_set_lower):
            detected.add("rust")
        if "cargo.toml" in files_set_lower:
            cargo_content = _read_text_limited(os.path.join(root, "cargo.toml")).lower()
            if any(m in cargo_content for m in ("rocket", "actix", "axum", "warp")):
                detected.add("rust")

        # Ruby + frameworks
        if {"gemfile", "gemfile.lock", "rakefile", "config.ru"}.intersection(files_set_lower):
            detected.add("ruby")
        if "gemfile" in files_set_lower:
            gem_content = _read_text_limited(os.path.join(root, "Gemfile")).lower()
            if any(m in gem_content for m in ("rails", "sinatra", "hanami")):
                detected.add("ruby")

        # .NET mobile (Xamarin / MAUI)
        for csproj in [f for f in files if f.endswith(".csproj")]:
            csproj_content = _read_text_limited(os.path.join(root, csproj))
            detected.add("dotnet")
            if re.search(r"(Xamarin|UseMaui|Maui|net\d+\.\d+-android|net\d+\.\d+-ios)", csproj_content, re.IGNORECASE):
                detected.update({"xamarin", "android", "ios"})
            if re.search(r"(Microsoft\.AspNetCore|Microsoft\.EntityFrameworkCore|WebApplication\.CreateBuilder)", csproj_content, re.IGNORECASE):
                detected.add("dotnet")

        if any(name.lower().endswith(".sln") for name in files):
            detected.add("dotnet")

        # Kotlin marker for backend/non-mobile kotlin projects.
        if any(name.lower().endswith(".kt") for name in files):
            detected.add("kotlin")

        # C / C++ ecosystem markers
        if "CMakeLists.txt" in files_set:
            cmake_content = _read_text_limited(os.path.join(root, "CMakeLists.txt")).lower()
            if any(m in cmake_content for m in ("project(", "add_executable(", "add_library(")):
                detected.update({"c", "cpp"})
            if any(m in cmake_content for m in ("find_package(qt", "boost", "find_package(poco")):
                detected.add("cpp")
        if {"makefile", "configure.ac", "config.h"}.intersection(files_set_lower):
            detected.update({"c", "cpp"})

    # Extension-informed refinement for C/C++ and JavaScript:
    # avoid adding C just because C++ headers/sources matched C patterns in config.
    c_count = ext_counts.get(".c", 0)
    cpp_count = ext_counts.get(".cpp", 0) + ext_counts.get(".cc", 0) + ext_counts.get(".cxx", 0)
    if c_count:
        detected.add("c")
    if cpp_count:
        detected.add("cpp")
    if "c" in detected and not c_count and cpp_count:
        detected.discard("c")

    js_count = ext_counts.get(".js", 0) + ext_counts.get(".jsx", 0) + ext_counts.get(".ts", 0) + ext_counts.get(".tsx", 0)
    if js_count >= 20:
        detected.add("javascript")

    return detected


def detect_framework_rule_files(sourcepath, selected_platforms=None):
    """
    Detect framework rule files to apply per selected platform using marker validation.

    Returns:
        dict[str, list[Path]]: platform -> framework XML paths
    """
    selected = set(selected_platforms or [])

    def _load_framework_registry():
        entries = []
        try:
            tree = ET.parse(runtime.frameworkConfig)
        except (ET.ParseError, OSError) as exc:
            logger.error("Failed to load framework registry %s: %s", runtime.frameworkConfig, exc)
            return entries

        root = tree.getroot()
        for node in root.findall("framework"):
            name = (node.findtext("name") or "").strip().lower()
            platform = (node.findtext("platform") or "").strip().lower()
            rule_file = (node.findtext("rule_file") or "").strip()
            if not name or not platform or not rule_file:
                continue

            marker_files = []
            dep_rules = []
            regex_rules = []
            scan_ftypes = []
            markers = node.find("markers")
            if markers is not None:
                for file_node in markers.findall("file"):
                    value = (file_node.text or "").strip().lower()
                    if value:
                        marker_files.append(value)
                for dep_node in markers.findall("dep"):
                    value = (dep_node.text or "").strip().lower()
                    dep_file = (dep_node.get("file") or "*").strip().lower()
                    if value:
                        dep_rules.append((dep_file, value))
                for regex_node in markers.findall("regex"):
                    value = (regex_node.text or "").strip()
                    target_file = (regex_node.get("file") or "*").strip().lower()
                    if value:
                        try:
                            regex_rules.append((target_file, re.compile(value, re.IGNORECASE)))
                        except re.error as exc:
                            logger.error("Invalid registry regex (%s:%s): %s", platform, name, exc)

            scan_ftypes_text = (node.findtext("scan_ftypes") or "").strip()
            if scan_ftypes_text:
                scan_ftypes = [p.strip() for p in scan_ftypes_text.split(",") if p.strip()]

            entries.append({
                "name": name,
                "platform": platform,
                "rule_file": rule_file,
                "marker_files": marker_files,
                "dep_rules": dep_rules,
                "regex_rules": regex_rules,
                "scan_ftypes": scan_ftypes,
            })
        return entries

    registry = _load_framework_registry()
    if not registry:
        return {}

    file_index = {}
    dep_index = {}
    content_cache = {}

    for root, _, files in os.walk(sourcepath):
        for fname in files:
            fpath = os.path.join(root, fname)
            lower_name = fname.lower()
            file_index.setdefault(lower_name, []).append(fpath)

            if lower_name.endswith(".json"):
                raw = _read_text_limited(fpath)
                if raw:
                    content_cache[fpath] = raw
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        data = {}
                    if isinstance(data, dict):
                        dep_keys = set()
                        for section in JSON_DEP_SECTIONS:
                            section_value = data.get(section, {})
                            if isinstance(section_value, dict):
                                dep_keys.update(str(k).lower() for k in section_value.keys())
                        dep_index[fpath] = dep_keys
            else:
                ext = os.path.splitext(lower_name)[1]
                if ext in {".toml", ".txt", ".xml", ".yml", ".yaml", ".gradle", ".kts", ".csproj", ".sln", ".rb", ".py", ".php", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp", ".m", ".swift", ".config", ".ini", ".plist"}:
                    raw = _read_text_limited(fpath)
                    if raw:
                        content_cache[fpath] = raw

    platform_to_files = {}
    for entry in registry:
        platform = entry["platform"]
        if selected and platform not in selected:
            continue

        matched = False

        for marker in entry["marker_files"]:
            if marker in file_index:
                matched = True
                break

        if not matched and entry["dep_rules"]:
            for dep_file, dep_key in entry["dep_rules"]:
                if dep_file == "*":
                    candidate_paths = dep_index.keys()
                elif any(token in dep_file for token in ("*", "?", "[")):
                    candidate_paths = []
                    for fname, paths in file_index.items():
                        if fnmatch.fnmatch(fname, dep_file):
                            candidate_paths.extend([p for p in paths if p in dep_index])
                else:
                    candidate_paths = [p for p in file_index.get(dep_file, []) if p in dep_index]
                for path_item in candidate_paths:
                    keys = dep_index.get(path_item, set())
                    if dep_key in keys:
                        matched = True
                        break
                if matched:
                    break

        if not matched and entry["regex_rules"]:
            for target_file, regex_obj in entry["regex_rules"]:
                if target_file == "*":
                    candidates = content_cache.items()
                elif any(token in target_file for token in ("*", "?", "[")):
                    candidates = []
                    for fname, paths in file_index.items():
                        if fnmatch.fnmatch(fname, target_file):
                            for p in paths:
                                if p in content_cache:
                                    candidates.append((p, content_cache[p]))
                else:
                    candidates = [(p, content_cache[p]) for p in file_index.get(target_file, []) if p in content_cache]
                for _, content in candidates:
                    if regex_obj.search(content):
                        matched = True
                        break
                if matched:
                    break

        if not matched:
            continue

        rules_rel_path = rulesops.get_rules_path_or_filetypes(platform, "rules")
        if not rules_rel_path:
            continue
        parent_rel = os.path.dirname(rules_rel_path.strip("/"))
        if not parent_rel:
            continue
        fw_path = runtime.rulesRootDir / parent_rel / "framework" / entry["rule_file"]
        if fw_path.exists():
            platform_to_files.setdefault(platform, []).append({
                "name": entry["name"],
                "path": fw_path,
                "scan_ftypes": entry.get("scan_ftypes", []),
            })

    # De-duplicate per platform/rule file.
    # Multiple framework markers (e.g., reactnative-ios, ionic-ios) can intentionally
    # map to the same native pack (e.g., ios/uikit.xml). Apply each pack once.
    deduped = {}
    for platform, entries in platform_to_files.items():
        grouped = {}
        for entry in entries:
            path_key = str(entry.get("path", "")).lower()
            if not path_key:
                continue
            group = grouped.setdefault(path_key, {
                "path": entry.get("path"),
                "names": [],
                "scan_ftypes": set(),
            })
            name_val = str(entry.get("name", "")).strip()
            if name_val and name_val not in group["names"]:
                group["names"].append(name_val)
            for patt in entry.get("scan_ftypes", []) or []:
                patt_val = str(patt).strip()
                if patt_val:
                    group["scan_ftypes"].add(patt_val)

        normalized_entries = []
        for grp in grouped.values():
            names_sorted = sorted(grp["names"])
            normalized_entries.append({
                "name": names_sorted[0] if names_sorted else Path(str(grp["path"])).stem,
                "names": names_sorted,
                "path": grp["path"],
                "scan_ftypes": sorted(grp["scan_ftypes"]),
            })

        deduped[platform] = sorted(
            normalized_entries,
            key=lambda e: (str(e.get("path", "")).lower(), str(e.get("name", "")).lower()),
        )

    return deduped


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
    Hybrid auto-detection for rules.

    Core language/platform rules are selected using fast extension matching.
    Overlap-prone mobile/framework rules are selected only via marker validation
    (manifest/config/dependency checks from detect_mobile_rule_types).

    Parameters:
        sourcepath (str or Path): Directory path to search for files.

    Returns:
        str: Comma-separated platform names whose filetypes match discovered files.
    """

    supported_rules = rulesops.get_available_rules(exclude=["common"])
    supported_rule_list = [r for r in supported_rules.split(",") if r]
    marker_validated_rules = AUTO_MARKER_VALIDATED_PLATFORMS.intersection(set(supported_rule_list))
    extension_matched_rules = [r for r in supported_rule_list if r not in marker_validated_rules]

    platform_patterns = {}
    for rule in extension_matched_rules:
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
    validated_mobile_platforms = mobile_platforms.intersection(marker_validated_rules)

    # Deduplicate and sort
    unique_platforms = sorted(detected_platforms.union(validated_mobile_platforms))
    result_str = ",".join(unique_platforms)

    return result_str


# Backward-compatible aliases for legacy callers.
detectMobileRuleTypes = detect_mobile_rule_types
discoverFiles = discover_files
reconDiscoverFiles = recon_discover_files
autoDetectRuleTypes = auto_detect_rule_types
detectFrameworkRuleFiles = detect_framework_rule_files
