# Standard libraries
import os
import sys
import threading

# Third-party libraries
import ruamel.yaml
from ruamel.yaml import YAML

# Local application imports
import state.runtime_state as runtime
import utils.cli_utils as cli


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



def init_or_prompt_project_config():
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

        input_thread = threading.Thread(target=timed_input)
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
