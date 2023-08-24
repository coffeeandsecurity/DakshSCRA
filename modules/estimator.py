import json
import yaml
from jinja2 import Template
import modules.runtime as runtime
import modules.misclib as mlib

# Global variable for the HTML report path
estimation_Fpath = runtime.estimation_Fpath

# Assumed number of hours to review one file
# hours_per_file = 0.25



def effortEstimator(json_file_path):
    global estimation_Fpath

    # Load data from JSON file
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)

    # Extract information for Backend and Frontend
    backend_data = data.get("Backend", {})
    frontend_data = data.get("Frontend", {})

    # Calculate total frontend and backend files count
    total_frontend_files = sum(language_data.get("totalFiles", 0) for language_data in frontend_data.values())
    total_backend_files = sum(language_data.get("totalFiles", 0) for language_data in backend_data.values())

    # Calculate estimated efforts in days for backend files based on the provided file count ranges
    backend_effort_days = get_effort_days(total_backend_files, 'backend')

    # Calculate estimated efforts in days for frontend files based on the provided file count ranges
    frontend_effort_days = get_effort_days(total_frontend_files, 'frontend')

    total_days = [0, 0]  # initialize
    total_days[0] = backend_effort_days[0] + frontend_effort_days[0]    # minimum days
    total_days[1] = backend_effort_days[1] + frontend_effort_days[1]    # maximum days

    # A dictionary to encapsulate the report data
    report_data = {
        'backend_data': backend_data,
        'frontend_data': frontend_data,
        'backend_days_min': backend_effort_days[0],
        'backend_days_max': backend_effort_days[1],
        'frontend_days_min': frontend_effort_days[0],
        'frontend_days_max': frontend_effort_days[1],
        'total_days_min': total_days[0],
        'total_days_max': total_days[1]
    }

    # Generate HTML report
    generate_report(report_data)



def generate_report(report_data):

    # Prepare data for rendering the Jinja2 template
    template_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Code Review Effort Estimation Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                }
                h1 {
                    color: #0066cc;
                    text-align: center;
                }
                h2 {
                    color: #000000;
                    margin: 5px 0;
                    text-align: left;
                }
                h3 {
                    color: #2F4F4F;
                    margin: 5px 0;
                    text-align: left;
                }
                p {
                    margin: 5px 0;
                }
                .notes {
                    background-color: #f5f5f5; /* Light gray background */
                    padding: 10px; /* Add padding around the Notes section */
                }
                .language-section {
                    margin-left: 20px;
                }
                .center-text {
                    text-align: center;
                }
                li {
                margin-left: 20px; /* Adjust the indentation as needed */
                padding: 3px 0; /* Add padding before and after the text */
                }
            </style>
        </head>
        <body>
            <h1>Code Review Effort Estimation Report</h1>
            <h2 class="center-text">Generated using Daksh SCRA</h2>
            <div class="notes">
                <p>Note: This report offers approximate effort estimation figures for conducting source code reviews. 
                These figures should be considered as guidance to formulate an estimate that satisfies all stakeholders.</p> 
                <p>For organizations seeking code review services, this report offers benchmark figures that can be utilized to verify estimates provided by third-party companies. 
                Similarly, for security consulting firms, these estimated figures serve as supporting evidence for code review proposals put forth to clients.</p> 
                <p>It's important to note that the current version of this tool focuses solely on estimating efforts for web applications. 
                Nevertheless, as the estimation module undergoes multiple updates in the forthcoming months, support for all other types of applications will also be incorporated.</p>
            </div>
            <br>
            <h2>Backend</h2>
            {% for language, language_data in backend_data.items() %}
            <div class="language-section">
                <h3>{{ language }}</h3>
                    <li>Total files identified: {{ language_data.totalFiles }}</li>
                    <li>Estimated efforts (days): {{ backend_days_min }} (minimum) - {{ backend_days_max }} (maximum) days</li>
            </div>
            {% endfor %}

            <h2>Frontend</h2>
            {% for language, language_data in frontend_data.items() %}
            <div class="language-section">
                <h3>{{ language }}</h3>
                    <li>Total files identified: {{ language_data.totalFiles }}</li>
                    <li>Estimated efforts (days): {{ frontend_days_min }} (minimum) - {{ frontend_days_max }} (maximum) days</li>
            </div>
            {% endfor %}

            <h2>Total Efforts (for the entire code review)</h2>
            <p>Total estimated effort (days): {{ total_days_min }} (minimum) - {{ total_days_max }} (maximum) days</p>
        </body>
        </html>
    '''

    # Render the Jinja2 template with the data
    template = Template(template_html)
    rendered_html = template.render(**report_data)

    # Save the rendered HTML report to the global path
    with open(estimation_Fpath, 'w') as report_file:
        report_file.write(rendered_html)

    print("     [-] Effort estimation report: " + str(mlib.getRelativePath(estimation_Fpath)))



def get_effort_days(file_count, tech):
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
        if data['files_range'][0] <= file_count <= data['files_range'][1]:
            return data['effort_range']

    raise ValueError(f"No effort range found for file count {file_count} and tech {tech}.")



'''
def get_effort_days(file_count, tech):
    try:
        file_count = int(file_count)
    except ValueError:
        raise ValueError("Invalid value for 'file_count'. It must be an integer.")

    if not isinstance(tech, str) or tech.lower() not in ['backend', 'frontend']:
        raise ValueError("Invalid value for 'tech'. It must be either 'backend' or 'frontend'.")

    if tech.lower() == 'backend':
        # Calculate estimated efforts in days for backend files based on the provided file count ranges
        if file_count <= 10:
            return [0.5, 1]
        elif file_count <= 20:
            return [1, 2]
        elif file_count <= 40:
            return [2, 4]
        elif file_count <= 100:
            return [5, 10]
        elif file_count <= 300:
            return [11, 20]
        elif file_count <= 1000:
            return [21, 40]
        else:
            return [41, 60]
    
    elif tech.lower() == 'frontend':
        # Calculate estimated efforts in days for frontend files based on the provided file count ranges
        if file_count <= 40:
            return [0.5, 1]
        elif file_count <= 100:
            return [1, 2]
        elif 100 < file_count < 500:
            return [2, 4]
        elif file_count <= 1000:
            return [3, 4]
        else:
            return [4, 5]

    else:
        raise ValueError("Unexpected error occurred while calculating effort days.")
'''




'''
Title : World's first Scientific approach to automated effort estimation for code review

This report offers approximate effort estimation figures for conducting source code reviews. 
These figures should be considered as guidance to formulate an estimate that satisfies all stakeholders. 
For companies in search of code reviews, this report provides reference numbers that can be used to validate 
estimates offered by third-party firms. Similarly, for security consulting firms, these estimated figures serve as 
supporting evidence for code review proposals put forth to clients. 

Consider following for estimation: 
* Resources
* Automated Tools: 
* Total Files and Corresponding lines of codes
* Functionalities (Total Functions)
* Data Flow
* Routes
* Workflow and UseCases
* Framework
* Technology

# Estimation must include the following: 
    * Targeted
    * Thorough and Comprehensive
    * Manual Only 
    * Hybrid Scan
    - Ball Park - High and Low
    
# Reports:
    * Manually Prepared
    * Automated Report Generated 

    Note: Reporting efforts can vary based on 

# Config File
    * Companies can provide details such as:
        - Total Functions/Methods (Add User, Delete User)
        - Total Workflows (User Registration, Password Reset)
        - Technologies (C#,Java etc)
        - Framework
'''