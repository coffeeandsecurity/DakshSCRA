import json
import yaml
from jinja2 import Template
import modules.runtime as runtime
import modules.utils as ut

# Global variable for the HTML report path
estimation_Fpath = runtime.estimation_Fpath

# Assumed number of hours to review one file
# hours_per_file = 0.25



def effortEstimator(json_file_path):
    """
    Estimates the effort in days for frontend and backend codebases 
    based on file counts and outputs an HTML report.

    This function reads a JSON file containing file count data for different 
    frontend and backend languages, calculates the estimated minimum and maximum 
    effort in days required for each language based on predefined effort metrics, 
    and generates a summarized HTML report.

    Parameters:
        json_file_path (str): Path to the JSON file containing frontend and backend 
                              file count data.

    Returns:
        None: The function writes an HTML report summarizing the effort estimation.
    """

    global estimation_Fpath

    # Load data from JSON file
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)

    # Extract information for Backend and Frontend
    backend_data = data.get("Backend", {})
    frontend_data = data.get("Frontend", {})

    # Calculate total frontend and backend files count
    total_frontend_min = 0
    total_frontend_max = 0
    total_backend_min = 0
    total_backend_max = 0

    frontend_info = []  # List to store frontend language information
    backend_info = []  # List to store backend language information

    for language, language_data in frontend_data.items():
        total_files = language_data.get("totalFiles", 0)
        # Calculate estimated efforts in days for frontend files based on the file count
        frontend_effort_days = get_effort_days(total_files, 'frontend')

        total_frontend_min += frontend_effort_days[0]  # minimum days
        total_frontend_max += frontend_effort_days[1]  # maximum days

        frontend_info.append({
            'language': language,
            'total_files': total_files,
            'effort_days_min': frontend_effort_days[0],
            'effort_days_max': frontend_effort_days[1]
        })


    for language, language_data in backend_data.items():
        total_files = language_data.get("totalFiles", 0)
        # Calculate estimated efforts in days for backend files based on the file count
        backend_effort_days = get_effort_days(total_files, 'backend')

        total_backend_min += backend_effort_days[0]  # minimum days
        total_backend_max += backend_effort_days[1]  # maximum days

        backend_info.append({
            'language': language,
            'total_files': total_files,
            'effort_days_min': backend_effort_days[0],
            'effort_days_max': backend_effort_days[1]
        })

    '''
    # Print the stored language information
    for info in backend_language_info:
        print(f"Backend Language: {info['language']}")
        print(f"Backend Total Files: {info['total_files']}")
        print(f"    - Total Efforts (min): {info['effort_days_min']} days")
        print(f"    - Total Efforts (max): {info['effort_days_max']} days")
        
    print(f"Total Backend Efforts (min): {total_backend_min} days")
    print(f"Total Backend Efforts (max): {total_backend_max} days")
    '''

    total_days_min = total_frontend_min + total_backend_min
    total_days_max = total_frontend_max + total_backend_max

    # A dictionary to encapsulate the report data
    report_data = {
        'backend_data': backend_info,
        'frontend_data': frontend_info,
        'total_days_min': total_days_min,
        'total_days_max': total_days_max
    }

    # Generate HTML report
    generate_report(report_data)



def generate_report(report_data):
    """
    Generates an HTML report for effort estimation by populating a Jinja2 template.

    Parameters:
        report_data (dict): Contains effort data for frontend, backend, 
                            and total days estimate (min and max).

    Returns:
        None: Writes the rendered HTML report to a predefined file path.
    """    

    # Load the template HTML content from the file
    with open(runtime.estimation_template, 'r') as template_file:
        template_html = template_file.read()

    # Render the Jinja2 template with the data
    template = Template(template_html)
    rendered_html = template.render(**report_data)

    # Save the rendered HTML report to the global path
    with open(estimation_Fpath, 'w') as report_file:
        report_file.write(rendered_html)

    print("     [-] Effort estimation report: " + str(ut.getRelativePath(estimation_Fpath)))



def get_effort_days(file_count, tech):
    """
    Estimates effort days based on the file count and technology type.

    Parameters:
        file_count (int): Number of files to estimate effort for.
        tech (str): Technology type ('backend' or 'frontend').

    Returns:
        tuple: Effort range (min, max days) for the given file count.

    Raises:
        ValueError: If 'file_count' is not an integer or 'tech' is invalid.
    """

    try:
        file_count = int(file_count)
    except ValueError:
        raise ValueError("Invalid value for 'file_count'. It must be an integer.")

    if not isinstance(tech, str) or tech.lower() not in ['backend', 'frontend']:
        raise ValueError("Invalid value for 'tech'. It must be either 'backend' or 'frontend'.")

    # Load data from the config file
    with open(runtime.estimateConfig, 'r') as config_file:
        config_data = yaml.safe_load(config_file)

    # Determine the corresponding data for the specified tech (backend or frontend)
    tech_data = config_data['estimation_days_ranges'][f'{tech}_data']

    for data in tech_data:
        lower_bound, upper_bound = data['files_range']
        
        if lower_bound <= file_count <= (upper_bound if upper_bound != 999999 else 999999):
            if upper_bound == 999999:
                print("Maximum range exceeded!")
            return data['effort_range']
        
    raise ValueError(f"No effort range found for file count {file_count} and tech {tech}.")


