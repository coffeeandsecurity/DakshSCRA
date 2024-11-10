import os
import ruamel.yaml
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
        yaml = ruamel.yaml.YAML()
        
        with open(runtime.projectConfig, "r") as file:
            config_data = yaml.load(file)

        # Update the entries in the YAML data
        if "title" in config_data and "subtitle" in config_data:
            config_data["title"] = project_name
            config_data["subtitle"] = project_subtitle

        # Save the updated YAML file while preserving order and formatting
        with open(runtime.projectConfig, "w") as file:
            yaml.dump(config_data, file)
