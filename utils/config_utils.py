# Standard libraries
import os

# Third-party libraries
import ruamel.yaml
from ruamel.yaml import YAML

# Local application imports
import state.runtime_state as runtime



def updateProjectConfig(project_name, project_subtitle):
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
            config_data = yaml.load(file)

        # Update or set the values
        config_data["title"] = project_name
        config_data["subtitle"] = project_subtitle

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

