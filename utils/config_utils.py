# Standard libraries
import os
import sys
import threading
from pathlib import Path

# Third-party libraries
import ruamel.yaml
from ruamel.yaml import YAML

# Local application imports
import state.runtime_state as runtime


def _safe_config_text(value):
    if value is None:
        return ""
    return str(value).strip()


def update_project_config(project_name, project_subtitle):
    """
    Update the project title and subtitle in the YAML config file (`config/project.yaml`).

    Parameters:
        project_name (str): New project title.
        project_subtitle (str): New project subtitle.

    Returns:
        None
    """
    if os.path.exists(runtime.projectConfig):
        yaml = YAML()
        with open(runtime.projectConfig, "r") as file:
            config_data = yaml.load(file) or {}

        # Update or set the values
        config_data["title"] = _safe_config_text(project_name)
        config_data["subtitle"] = _safe_config_text(project_subtitle)

        with open(runtime.projectConfig, "w") as file:
            yaml.dump(config_data, file)



def get_tool_version():
    """
    Retrieve the tool version from the YAML config file (`config/tool.yaml`).

    Returns:
        str: The version string (e.g., "0.26") if found, else "Unknown".
    """
    yaml = YAML()
    try:
        if not os.path.exists(runtime.toolConfig):
            return "Unknown"
        
        with open(runtime.toolConfig, 'r') as file:
            config_data = yaml.load(file)
            return str(config_data.get("release", "Unknown"))
    except Exception as e:
        print(f"[!] Error reading version info from config: {e}")
        return "Unknown"


def get_tool_config():
    """
    Load the full tool configuration from `config/tool.yaml`.

    Returns:
        dict: Parsed YAML data or an empty dict on failure.
    """
    yaml = YAML()
    try:
        if not os.path.exists(runtime.toolConfig):
            return {}
        with open(runtime.toolConfig, "r") as file:
            data = yaml.load(file) or {}
            return data if isinstance(data, dict) else {}
    except Exception as exc:
        print(f"[!] Error reading tool config: {exc}")
        return {}


def get_state_management_config():
    """
    Get scan state-management settings with sane defaults.
    """
    tool_cfg = get_tool_config()
    state_cfg = tool_cfg.get("state_management", {}) if isinstance(tool_cfg, dict) else {}
    if not isinstance(state_cfg, dict):
        state_cfg = {}

    default_path = str(Path(runtime.root_dir) / "runtime" / "scan_state.json")
    configured_path = str(state_cfg.get("default_state_file", default_path)).strip() or default_path
    if not Path(configured_path).is_absolute():
        configured_path = str(Path(runtime.root_dir) / configured_path)

    return {
        "enabled": bool(state_cfg.get("enabled", True)),
        "resume_mode": str(state_cfg.get("resume_mode", "manual")).strip().lower() or "manual",
        "persist_after_seconds": int(state_cfg.get("persist_after_seconds", 300)),
        "persist_interval_seconds": int(state_cfg.get("persist_interval_seconds", 30)),
        "default_state_file": configured_path,
        "cleanup_on_success": bool(state_cfg.get("cleanup_on_success", False)),
    }


def get_display_config():
    """
    Get display settings (timezone) with sane defaults.
    """
    tool_cfg = get_tool_config()
    display_cfg = tool_cfg.get("display", {}) if isinstance(tool_cfg, dict) else {}
    if not isinstance(display_cfg, dict):
        display_cfg = {}
    return {
        "timezone": str(display_cfg.get("timezone", "")).strip(),
    }


def get_now():
    """
    Return the current datetime in the configured timezone.
    Falls back to server local time if no timezone is set or the value is invalid.
    """
    from datetime import datetime
    tz_name = get_display_config().get("timezone", "").strip()
    if not tz_name:
        return datetime.now()
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(tz_name))
    except Exception:
        return datetime.now()


def get_analysis_config():
    """
    Get analyzer settings with sane defaults.
    """
    tool_cfg = get_tool_config()
    analysis_cfg = tool_cfg.get("analysis", {}) if isinstance(tool_cfg, dict) else {}
    if not isinstance(analysis_cfg, dict):
        analysis_cfg = {}

    report_theme = str(analysis_cfg.get("report_theme", "hacker_mode")).strip().lower() or "hacker_mode"
    if report_theme not in {"hacker_mode", "professional_mode", "both"}:
        report_theme = "hacker_mode"

    def _pos_int(val, default):
        try:
            v = int(val)
            return v if v > 0 else default
        except (TypeError, ValueError):
            return default

    return {
        "run_by_default": bool(analysis_cfg.get("run_by_default", True)),
        "include_frameworks": bool(analysis_cfg.get("include_frameworks", True)),
        "report_theme": report_theme,
        "max_files_per_platform": _pos_int(analysis_cfg.get("max_files_per_platform"), 300),
        "max_functions_per_platform": _pos_int(analysis_cfg.get("max_functions_per_platform"), 1500),
    }


def init_or_prompt_project_config():
    import utils.cli_utils as cli

    """
    Initialize or prompt for project title/subtitle from project.yaml.

    - If title and subtitle are set: show them, allow 6s to override.
    - If not set or override chosen: prompt for input and update config.
    """

    config_path = runtime.projectConfig
    yaml = YAML()

    if not os.path.exists(config_path):
        print(" [!] Project configuration file not found.")
        return

    with open(config_path, 'r') as f:
        config = yaml.load(f) or {}

    current_title = _safe_config_text(config.get('title', ''))
    current_subtitle = _safe_config_text(config.get('subtitle', ''))
    non_interactive = os.environ.get("DAKSH_NON_INTERACTIVE", "").strip() == "1" or (not sys.stdin.isatty())

    if non_interactive:
        if not current_title:
            current_title = "DakshSCRA Scan"
        if not current_subtitle:
            current_subtitle = "Automated Run"
        update_project_config(current_title, current_subtitle)
        cli.section_print(f"[*] Using Project Configuration (non-interactive mode):")
        print(f"     ├── Project Name     : {current_title}")
        print(f"     └── Project Subtitle : {current_subtitle}")
        return

    if current_title and current_subtitle:
        cli.section_print(f"[*] Using Existing Project Configuration:")
        print(f"     ├── Project Name     : {current_title}")
        print(f"     └── Project Subtitle : {current_subtitle}")
        print("\n     [!] Press ENTER within 6 seconds to modify project details...")

        user_input = []

        def timed_input():
            try:
                user_input.append(input("     [-] Waiting for input: "))
            except EOFError:
                user_input.append("")

        input_thread = threading.Thread(target=timed_input, daemon=True)
        input_thread.start()
        input_thread.join(timeout=6)

        if not user_input:
            print("     [*] No input received. Continuing with existing project configuration...\n")
            return
        # If user pressed ENTER (empty string), we treat as intent to update
        if user_input[0].strip() != "":
            print("     [*] Unexpected input received. Ignoring and continuing...\n")
            return

    # Prompt if not set or override chosen
    cli.section_print(f"[!] Project details not set or user opted to modify. Provide the following:")
    title = input("     [-] Enter Project Name (e.g., XYZ Portal): ")
    subtitle = input("     [-] Enter Project Subtitle (e.g., v1.0.1 / XYZ Corp): ")
    update_project_config(title, subtitle)
    print("     [-] Project configuration updated.\n")


# Backward-compatible alias for legacy callers.
updateProjectConfig = update_project_config
