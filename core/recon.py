import base64
import fnmatch
import json
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import yaml
from jinja2 import Template

import state.runtime_state as state
import utils.cli_utils as cli
import utils.file_utils as futils
import utils.result_utils as result
from utils.log_utils import get_logger

logger = get_logger(__name__)


# Exclusion list for file extensions
exclusion_list = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".tiff", ".zip",
    ".svg", ".ttf", ".woff", ".woff2",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    "dist", "build", "target", ".next", ".nuxt",
}

MAX_CONTENT_BYTES = 1024 * 1024  # 1 MB per file

CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}

MANIFEST_RULES = [
    {"category": "Mobile Platforms", "name": "Android", "file": "AndroidManifest.xml", "confidence": "high"},
    {"category": "Mobile Platforms", "name": "Flutter", "file": "pubspec.yaml", "regex": r"\bflutter:\b", "confidence": "high"},
    {"category": "Mobile Platforms", "name": "iOS", "file": "Podfile", "confidence": "high"},
    {"category": "Mobile Platforms", "name": "Cordova", "file": "config.xml", "regex": r"\bcordova\b", "confidence": "high"},
    {"category": "Mobile Platforms", "name": "Capacitor", "file": "capacitor.config.json", "confidence": "high"},
    {"category": "Mobile Platforms", "name": "Capacitor", "file": "capacitor.config.ts", "confidence": "high"},
    {"category": "Mobile Platforms", "name": "React Native", "file": "app.json", "regex": r"react-native|expo", "confidence": "high"},
    {"category": "Frontend", "name": "Next.js", "file": "next.config.js", "confidence": "high"},
    {"category": "Frontend", "name": "Next.js", "file": "next.config.mjs", "confidence": "high"},
    {"category": "Frontend", "name": "Next.js", "file": "next.config.ts", "confidence": "high"},
    {"category": "Frontend", "name": "Nuxt", "file": "nuxt.config.js", "confidence": "high"},
    {"category": "Frontend", "name": "Nuxt", "file": "nuxt.config.ts", "confidence": "high"},
    {"category": "Frontend", "name": "Angular", "file": "angular.json", "confidence": "high"},
    {"category": "Frontend", "name": "Svelte", "file": "svelte.config.js", "confidence": "high"},
    {"category": "Backend", "name": "Go", "file": "go.mod", "confidence": "high"},
    {"category": "Backend", "name": "Rust", "file": "Cargo.toml", "confidence": "high"},
    {"category": "Backend", "name": "Python", "file": "pyproject.toml", "confidence": "high"},
    {"category": "Backend", "name": "Python", "file": "requirements.txt", "confidence": "high"},
    {"category": "Backend", "name": "Java", "file": "pom.xml", "confidence": "high"},
    {"category": "Backend", "name": "Java", "file": "build.gradle", "confidence": "high"},
    {"category": "Backend", "name": "Java", "file": "build.gradle.kts", "confidence": "high"},
    {"category": "Backend", "name": ".NET", "file": "*.csproj", "confidence": "high"},
    {"category": "Backend", "name": ".NET", "file": "*.sln", "confidence": "high"},
    {"category": "Infrastructure", "name": "Docker", "file": "Dockerfile", "confidence": "high"},
    {"category": "Infrastructure", "name": "Docker", "file": "docker-compose.yml", "confidence": "high"},
    {"category": "Infrastructure", "name": "Docker", "file": "docker-compose.yaml", "confidence": "high"},
    {"category": "Infrastructure", "name": "Terraform", "file": "*.tf", "confidence": "high"},
    {"category": "Infrastructure", "name": "Terraform", "file": "terraform.tfvars", "confidence": "high"},
    {"category": "Infrastructure", "name": "Kubernetes", "file": "kustomization.yaml", "confidence": "high"},
    {"category": "Infrastructure", "name": "Kubernetes", "file": "kustomization.yml", "confidence": "high"},
    {"category": "Infrastructure", "name": "Helm", "file": "Chart.yaml", "confidence": "high"},
]


def _default_recon_tuning():
    return {
        "exclude_path_globs": [],
        "exclude_path_contains": [],
        "disable_categories": [],
        "disable_detections": [],
        "confidence_overrides": {},
    }


def _load_json_file(path, label):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load %s from %s: %s", label, path, exc)
        return {}


def _load_recon_tuning():
    tuning_path = Path(str(state.root_dir) + "/config/recon_tuning.json")
    if not tuning_path.exists():
        return _default_recon_tuning()

    data = _load_json_file(tuning_path, "recon tuning")
    tuning = _default_recon_tuning()
    for key in tuning:
        if key in data:
            tuning[key] = data[key]
    return tuning


def _compile_regex(pattern, label):
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        logger.error("Invalid regex (%s): %s (%s)", label, pattern, exc)
        return None


def _normalize_extensions(exts):
    normalized = set()
    for ext in exts or []:
        if not isinstance(ext, str):
            continue
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith(".") and ext != "*":
            ext = "." + ext
        normalized.add(ext)
    return normalized


def _read_text(file_path):
    try:
        with open(file_path, "rb") as fh:
            raw = fh.read(MAX_CONTENT_BYTES)
    except OSError:
        return None

    if not raw or b"\x00" in raw:
        return None

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("ISO-8859-1", errors="ignore")


def _format_elapsed(seconds):
    hours, rem = divmod(seconds, 3600)
    minutes, sec = divmod(rem, 60)
    sec_i = int(sec)
    msec = int((sec - sec_i) * 1000)
    return "{:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), sec_i, f"{msec:03d}")


def _build_technology_specs(technologies):
    ext_specs = defaultdict(list)
    regex_specs = defaultdict(list)
    known_extensions = set()

    for category, tech_list in technologies.items():
        if not isinstance(tech_list, list):
            continue
        for tech in tech_list:
            if not isinstance(tech, dict):
                continue
            name = tech.get("name")
            if not name:
                continue
            extensions = _normalize_extensions(tech.get("fileExtensions", []))
            known_extensions.update(extensions)
            regex_flag = str(tech.get("regexFlag", "1"))
            regex_obj = _compile_regex(tech.get("regex", ""), f"{category}:{name}")

            spec = {
                "category": category,
                "name": name,
                "extensions": extensions or {"*"},
                "regex_flag": regex_flag,
                "regex": regex_obj,
            }

            bucket = ext_specs if regex_flag == "0" else regex_specs
            for ext in spec["extensions"]:
                bucket[ext].append(spec)

    return ext_specs, regex_specs, known_extensions


def _build_framework_specs(frameworks):
    mapping = {}
    all_exts = set()

    for language, framework_list in frameworks.items():
        if not isinstance(framework_list, list):
            continue

        compiled = []
        for framework in framework_list:
            if not isinstance(framework, dict):
                continue
            name = framework.get("name")
            regex_obj = _compile_regex(framework.get("regex", ""), f"{language}:{name}")
            extensions = _normalize_extensions(framework.get("fileExtensions", []))
            all_exts.update(extensions)
            if name and regex_obj:
                compiled.append({"name": name, "regex": regex_obj, "extensions": extensions or {"*"}})
        mapping[language] = compiled

    return mapping, all_exts


def _build_other_specs(others):
    specs = []
    for category, entries in others.items():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            regex_obj = _compile_regex(item.get("regex", ""), f"{category}:{name}")
            if name and regex_obj:
                specs.append({"category": category, "name": name, "regex": regex_obj})
    return specs


def _merge_confidence(current, incoming):
    if current is None:
        return incoming
    return incoming if CONFIDENCE_ORDER.get(incoming, 0) >= CONFIDENCE_ORDER.get(current, 0) else current


def _add_match(store, category, name, file_path, confidence="medium"):
    existing = store[category][name].get(file_path)
    store[category][name][file_path] = _merge_confidence(existing, confidence)


def _should_skip_file(file_path, tuning):
    normalized = file_path.replace("\\", "/")

    for patt in tuning.get("exclude_path_globs", []):
        if isinstance(patt, str) and patt and fnmatch.fnmatch(normalized, patt):
            return True

    lowered = normalized.lower()
    for token in tuning.get("exclude_path_contains", []):
        if isinstance(token, str) and token and token.lower() in lowered:
            return True

    return False


def _should_skip_detection(category, name, tuning):
    disabled_categories = set(tuning.get("disable_categories", []))
    if category in disabled_categories:
        return True

    disabled_detections = set(tuning.get("disable_detections", []))
    return f"{category}:{name}" in disabled_detections


def _apply_confidence_override(category, name, confidence, tuning):
    key = f"{category}:{name}"
    overrides = tuning.get("confidence_overrides", {})
    override = overrides.get(key) if isinstance(overrides, dict) else None
    if isinstance(override, str) and override.lower() in CONFIDENCE_ORDER:
        return override.lower()
    return confidence


def _walk_project_files(targetdir):
    started = time.time()
    last_print = started
    visited_dirs = 0
    total_files_seen = 0
    log_filepaths = []
    for root, dirs, files in os.walk(targetdir):
        visited_dirs += 1
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        total_files_seen += len(files)
        for file_name in files:
            file_path = os.path.join(root, file_name)
            ext = Path(file_name).suffix.lower()
            if ext in exclusion_list:
                continue
            log_filepaths.append(file_path)

        now = time.time()
        # Print at most once per ~1.2s to keep overhead negligible on large scans.
        if now - last_print >= 1.2:
            elapsed = now - started
            print(
                "     [-] Enumerating... "
                f"dirs:{visited_dirs} files:{total_files_seen} candidates:{len(log_filepaths)} "
                f"elapsed:{elapsed:.1f}s",
                end="\r",
            )
            last_print = now

    print(" " * 110, end="\r")
    return log_filepaths


def _matches_manifest_pattern(pattern, path_obj):
    if "*" in pattern:
        return path_obj.match(pattern)
    return path_obj.name.lower() == pattern.lower()


def _apply_manifest_detections(file_paths, recon_output_map, add_match_fn=None):
    add_match_cb = add_match_fn if add_match_fn else _add_match
    for fp in file_paths:
        p = Path(fp)
        for rule in MANIFEST_RULES:
            if not _matches_manifest_pattern(rule["file"], p):
                continue
            if "regex" in rule:
                content = _read_text(fp)
                if not content:
                    continue
                if not re.search(rule["regex"], content, re.IGNORECASE):
                    continue
            add_match_cb(rule["category"], rule["name"], fp, rule.get("confidence", "high"))


def detect_framework(language, file_path):
    """
    Backward-compatible framework detector for one language + file.
    """
    frameworks = _load_json_file(state.framework_Fpath, "framework definitions")
    framework_specs, _ = _build_framework_specs(frameworks)
    content = _read_text(file_path)
    if content is None:
        return None

    extension = Path(file_path).suffix.lower()
    for framework in framework_specs.get(language, []):
        extensions = framework.get("extensions", {"*"})
        if "*" not in extensions and extension not in extensions:
            continue
        if framework["regex"].search(content):
            return framework["name"]
    return None


def recon(targetdir, flag=False, strict_mode=False):
    """
    Perform reconnaissance (software composition analysis) for a target directory.
    """
    if flag is False:
        cli.section_print("[*] Reconnaissance (a.k.a Software Composition Analysis)")

    targetdir = str(Path(targetdir).expanduser().resolve())

    recon_started_ts = time.time()
    recon_started_at = datetime.now()
    print(f"     [-] Recon started at: {recon_started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"     [-] Recon target    : {targetdir}")
    print(f"     [-] Recon strict    : {'enabled' if strict_mode else 'disabled'}")
    result.update_scan_summary("scanning_timeline.recon_start_time", recon_started_at.strftime('%Y-%m-%d %H:%M:%S'))
    result.update_scan_summary("inputs_received.recon_target_directory", targetdir)
    result.update_scan_summary("inputs_received.recon_strict_mode", str(bool(strict_mode)).lower())

    if Path(state.inventory_Fpathext).is_file():
        os.remove(state.inventory_Fpathext)

    print("     [-] Enumerating project files and directories")
    log_filepaths = _walk_project_files(targetdir)
    print(f"     [-] Total recon candidate files: {len(log_filepaths)}")
    result.update_scan_summary("detection_summary.recon_candidate_files", str(len(log_filepaths)))

    technologies = _load_json_file(state.technologies_Fpath, "technology definitions")
    frameworks = _load_json_file(state.framework_Fpath, "framework definitions")
    others = _load_json_file(Path(str(state.root_dir) + "/rules/recon/others.json"), "other recon definitions")
    tuning = _load_recon_tuning()

    if not technologies:
        return log_filepaths, {}

    tech_ext_specs, tech_regex_specs, known_exts = _build_technology_specs(technologies)
    framework_specs, framework_exts = _build_framework_specs(frameworks)
    other_specs = _build_other_specs(others)

    content_scan_exts = set(known_exts).union(framework_exts)
    if not content_scan_exts:
        content_scan_exts = {".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs", ".kt"}

    print("     [-] Performing reconnaissance...")
    recon_output_map = defaultdict(lambda: defaultdict(dict))
    filtered_filepaths = [fp for fp in log_filepaths if not _should_skip_file(fp, tuning)]
    if len(filtered_filepaths) != len(log_filepaths):
        print(f"     [-] Recon tuning excluded files: {len(log_filepaths) - len(filtered_filepaths)}")
    log_filepaths = filtered_filepaths

    def add_match(category, name, file_path, confidence):
        if _should_skip_detection(category, name, tuning):
            return
        tuned_confidence = _apply_confidence_override(category, name, confidence, tuning)
        _add_match(recon_output_map, category, name, file_path, tuned_confidence)

    _apply_manifest_detections(log_filepaths, recon_output_map, add_match)

    for idx, file_path in enumerate(log_filepaths, start=1):
        ext = Path(file_path).suffix.lower()
        matched_languages = set()

        for spec in tech_ext_specs.get(ext, []):
            add_match(spec["category"], spec["name"], file_path, "medium")
            matched_languages.add(spec["name"])

        wildcard_ext_specs = tech_ext_specs.get("*", [])
        for spec in wildcard_ext_specs:
            add_match(spec["category"], spec["name"], file_path, "medium")
            matched_languages.add(spec["name"])

        regex_candidates = list(tech_regex_specs.get(ext, [])) + list(tech_regex_specs.get("*", []))
        needs_content = bool(regex_candidates or other_specs or matched_languages)
        content = _read_text(file_path) if (needs_content and ext in content_scan_exts) else None

        for spec in regex_candidates:
            regex = spec.get("regex")
            if not regex:
                continue
            matches_path = bool(regex.search(file_path))
            matches_content = bool(content and regex.search(content))
            if matches_path or matches_content:
                conf = "medium" if matches_content else "low"
                add_match(spec["category"], spec["name"], file_path, conf)
                matched_languages.add(spec["name"])

        if content and matched_languages:
            for language in matched_languages:
                for framework in framework_specs.get(language, []):
                    fw_exts = framework.get("extensions", {"*"})
                    if "*" not in fw_exts and ext not in fw_exts:
                        continue
                    if framework["regex"].search(content):
                        add_match("Framework", framework["name"], file_path, "high")

        if content and other_specs:
            for spec in other_specs:
                if spec["regex"].search(content):
                    add_match(spec["category"], spec["name"], file_path, "low")

        if idx % 500 == 0:
            print(f"     [-] Recon processed files: {idx}/{len(log_filepaths)}", end="\r")

    print(" " * 90, end="\r")
    print("     [-] Reconnaissance completed.")
    recon_completed_at = datetime.now()
    elapsed = time.time() - recon_started_ts
    print(f"     [-] Recon completed at: {recon_completed_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"     [-] Recon time taken : {_format_elapsed(elapsed)}")
    result.update_scan_summary("scanning_timeline.recon_end_time", recon_completed_at.strftime('%Y-%m-%d %H:%M:%S'))
    result.update_scan_summary("scanning_timeline.recon_duration", _format_elapsed(elapsed))

    recon_output = {}
    strict_high_only_categories = {"Framework", "Mobile Platforms", "Frontend", "Backend"}
    for category in sorted(recon_output_map.keys()):
        recon_output[category] = {}
        for tech_name in sorted(recon_output_map[category].keys()):
            file_conf_map = recon_output_map[category][tech_name]
            kept = []
            kept_conf = {}
            for path_value, conf in file_conf_map.items():
                if strict_mode:
                    if category in strict_high_only_categories:
                        if conf != "high":
                            continue
                    elif CONFIDENCE_ORDER.get(conf, 0) < CONFIDENCE_ORDER["medium"]:
                        continue
                kept.append(path_value)
                kept_conf[path_value] = conf
            if kept:
                sorted_paths = sorted(set(kept))
                confidence_counts = {
                    "high": sum(1 for p in sorted_paths if kept_conf.get(p) == "high"),
                    "medium": sum(1 for p in sorted_paths if kept_conf.get(p) == "medium"),
                    "low": sum(1 for p in sorted_paths if kept_conf.get(p) == "low"),
                }
                dominant = max(confidence_counts.items(), key=lambda x: x[1])[0] if sorted_paths else "low"
                recon_output[category][tech_name] = {
                    "files": sorted_paths,
                    "confidenceByFile": {p: kept_conf.get(p, "low") for p in sorted_paths},
                    "confidenceCounts": confidence_counts,
                    "dominantConfidence": dominant,
                }
        if not recon_output[category]:
            del recon_output[category]

    output_file_path = Path(state.reconOutput_Fpath)
    try:
        output_file_path.parent.mkdir(parents=True, exist_ok=True)
        output_file_path.write_text(json.dumps(recon_output, indent=4, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        logger.error("Error saving reconnaissance output to %s: %s", output_file_path, exc)

    rec_summary_path = summarize_recon(output_file_path)
    return log_filepaths, rec_summary_path


def extract_parent_directory(file_paths):
    """
    Extracts unique parent directories of the most common project folder.
    """
    project_folder_names = [os.path.basename(os.path.dirname(file_path)) for file_path in file_paths]
    common_project_folder = Counter(project_folder_names).most_common(1)

    if common_project_folder:
        most_common_folder = common_project_folder[0][0]
        parent_directories = set()
        for file_path in file_paths:
            directory_path = os.path.dirname(file_path)
            parent_directory = os.path.dirname(directory_path)
            if os.path.basename(parent_directory) == most_common_folder:
                parent_directories.add(parent_directory)
        return list(parent_directories)

    return []


def summarize_recon(json_file_path):
    """
    Generates summary JSONs and recon text/HTML reports.
    """
    runtime_summary_path = Path(state.reconSummary_Fpath)
    reports_summary_path = Path(state.outputRecSummary_JSON)

    try:
        with open(json_file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load recon json %s: %s", json_file_path, exc)
        return str(runtime_summary_path)

    summary = {}
    for category, files in data.items():
        if not isinstance(files, dict):
            continue

        category_summary = {}
        for file_type, file_paths in files.items():
            confidence_by_file = {}
            confidence_counts = {"high": 0, "medium": 0, "low": 0}
            dominant_confidence = "low"

            if isinstance(file_paths, dict):
                raw_files = file_paths.get("files", [])
                if isinstance(raw_files, list):
                    unique_paths = sorted(set(raw_files))
                else:
                    unique_paths = []
                raw_conf_map = file_paths.get("confidenceByFile", {})
                if isinstance(raw_conf_map, dict):
                    confidence_by_file = {str(k): str(v) for k, v in raw_conf_map.items()}
                if isinstance(file_paths.get("confidenceCounts"), dict):
                    cc = file_paths.get("confidenceCounts", {})
                    confidence_counts = {
                        "high": int(cc.get("high", 0)),
                        "medium": int(cc.get("medium", 0)),
                        "low": int(cc.get("low", 0)),
                    }
                else:
                    for p in unique_paths:
                        confidence_counts[confidence_by_file.get(p, "low")] += 1
                dominant_confidence = str(file_paths.get("dominantConfidence", "low"))
            else:
                unique_paths = sorted(set(file_paths))
                confidence_by_file = {p: "medium" for p in unique_paths}
                confidence_counts["medium"] = len(unique_paths)
                dominant_confidence = "medium"

            directory_counts = Counter(str(Path(p).parent) for p in unique_paths)
            directories = [
                {"directory": directory, "fileCount": count}
                for directory, count in sorted(directory_counts.items(), key=lambda x: (-x[1], x[0]))
            ]
            category_summary[file_type] = {
                "directories": directories,
                "totalFiles": len(unique_paths),
                "totalDirectories": len(directory_counts),
                "sampleFiles": unique_paths[:5],
                "confidenceCounts": confidence_counts,
                "dominantConfidence": dominant_confidence,
            }
        summary[category] = category_summary

    summary_payload = {
        "meta": {
            "recon_target_directory": _load_json_file(state.scanSummary_Fpath, "scan summary")
            .get("inputs_received", {})
            .get("recon_target_directory", ""),
            "recon_strict_mode": _load_json_file(state.scanSummary_Fpath, "scan summary")
            .get("inputs_received", {})
            .get("recon_strict_mode", "false"),
            "recon_tuning_enabled": str(Path(str(state.root_dir) + "/config/recon_tuning.json").exists()).lower(),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "categories": summary,
    }

    for out_path in (runtime_summary_path, reports_summary_path):
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(summary_payload, indent=4, sort_keys=True), encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to write recon summary to %s: %s", out_path, exc)

    # Cleanup: remove any legacy text/html recon report from old output paths.
    for legacy_path in [
        Path(str(state.root_dir)) / "reports" / "text" / "reconnaissance.txt",
        Path(str(state.reports_dirpath)) / "html" / "reconnaissance.html",
    ]:
        try:
            if legacy_path.exists():
                legacy_path.unlink()
        except OSError as exc:
            logger.error("Failed to remove legacy recon report %s: %s", legacy_path, exc)

    recon_summary_html_report(runtime_summary_path, state.reconreport_Fpath)
    return str(runtime_summary_path)


def recon_summary_html_report(json_file_path, output_file_path):
    """
    Generates a modern HTML reconnaissance summary report aligned with modern report style.
    """
    try:
        with open(json_file_path, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load recon summary json %s: %s", json_file_path, exc)
        return

    if "categories" in data and isinstance(data["categories"], dict):
        meta = data.get("meta", {})
        categories = data["categories"]
    else:
        # Backward compatibility for old summary schema.
        meta = {}
        categories = data

    report_title = "Daksh SCRA - Source Code Analysis Report"
    report_subtitle = None
    logo_image_path = ""
    try:
        with open(state.projectConfig, "r", encoding="utf-8") as stream:
            config = yaml.safe_load(stream) or {}
            report_title = config.get("title", report_title)
            subtitle = config.get("subtitle", "")
            report_subtitle = subtitle if subtitle and str(subtitle).lower() != "none" else None
    except (OSError, yaml.YAMLError) as exc:
        logger.error("Failed to load project config %s: %s", state.projectConfig, exc)

    try:
        with open(state.staticLogo, "rb") as logo_file:
            logo_image_path = f"data:image/svg+xml;base64,{base64.b64encode(logo_file.read()).decode('utf-8')}"
    except OSError as exc:
        logger.error("Failed to load logo image %s: %s", state.staticLogo, exc)

    sections = []
    total_tech = 0
    total_files = 0
    total_dirs = 0
    for category, items in sorted(categories.items()):
        tech_rows = []
        for tech_name, tech_data in items.items():
            dirs = tech_data.get("directories", [])
            tfiles = int(tech_data.get("totalFiles", 0))
            tdirs = int(tech_data.get("totalDirectories", 0))
            tech_rows.append(
                {
                    "name": tech_name,
                    "total_files": tfiles,
                    "total_dirs": tdirs,
                    "directories": dirs,
                    "sample_files": tech_data.get("sampleFiles", []),
                    "confidence": tech_data.get("dominantConfidence", "medium"),
                    "confidence_counts": tech_data.get("confidenceCounts", {"high": 0, "medium": 0, "low": 0}),
                }
            )
            total_tech += 1
            total_files += tfiles
            total_dirs += tdirs

        if tech_rows:
            sections.append(
                {
                    "category": category,
                    "tech_rows": sorted(tech_rows, key=lambda x: x["total_files"], reverse=True),
                }
            )

    template_path = state.htmltemplates_dir / "recon.html"
    try:
        template_html = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.error("Failed to load recon HTML template %s: %s", template_path, exc)
        return

    rendered_html = Template(template_html).render(
        reportTitle=report_title,
        reportSubTitle=report_subtitle,
        reportDate=datetime.now().strftime("%b %d, %Y"),
        generated_at=datetime.now().strftime("%b %d, %Y %H:%M"),
        recon_target=meta.get("recon_target_directory", ""),
        recon_strict_mode=meta.get("recon_strict_mode", "false"),
        logoImagePath=logo_image_path,
        sections=sections,
        total_categories=len(sections),
        total_technologies=total_tech,
        total_files=total_files,
        total_directories=total_dirs,
    )

    output_file_path = Path(output_file_path)
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    output_file_path.write_text(rendered_html, encoding="utf-8")
    print("     [-] Reconnaissance HTML report: " + str(futils.get_reports_root_path(output_file_path)))


# Backward-compatible aliases for legacy callers.
detectFramework = detect_framework
extractParentDirectory = extract_parent_directory
summariseRecon = summarize_recon
reconSummaryHtmlReport = recon_summary_html_report
