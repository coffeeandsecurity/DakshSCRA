import json
from jinja2 import Template

import modules.runtime as runtime
import modules.misclib as mlib


# Global variable for the HTML report path
estimation_Fpath = runtime.estimation_Fpath

# Assumed number of hours to review one file
hours_per_file = 0.25

def get_effort_days(file_count, min_days, max_days):
    # Effort estimation formula based on file count ranges
    return (min(max_days, max(min_days, (file_count * hours_per_file))), max(max_days, min(min_days, (file_count * hours_per_file))))

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

    # Assign weights for frontend and backend files
    frontend_weight = 0.08      # Approx 5 mins per file (i.e 5/60 hr)
    backend_weight = 0.25          # 15 mins per file (i.e. 15/60 hr)

    # Calculate estimated efforts based on the formula: Estimated Effort = (F * frontend_weight) + (B * backend_weight)
    estimated_frontend_effort_hours = total_frontend_files * frontend_weight * hours_per_file
    estimated_backend_effort_hours = total_backend_files * backend_weight * hours_per_file
    total_estimated_effort_hours = estimated_frontend_effort_hours + estimated_backend_effort_hours

    # Calculate estimated efforts in days for backend files based on the provided file count ranges
    estimated_backend_effort_days = get_effort_days(total_backend_files, 0.5, 1) if total_backend_files <= 10 else \
                                    get_effort_days(total_backend_files, 1, 2) if total_backend_files <= 20 else \
                                    get_effort_days(total_backend_files, 2, 4) if total_backend_files <= 40 else \
                                    get_effort_days(total_backend_files, 5, 10) if total_backend_files <= 100 else \
                                    get_effort_days(total_backend_files, 11, 20) if total_backend_files <= 300 else \
                                    get_effort_days(total_backend_files, 21, 40) if total_backend_files <= 1000 else \
                                    get_effort_days(total_backend_files, 41, 60)

    # Calculate estimated efforts in days for frontend files based on the provided file count ranges
    estimated_frontend_effort_days = get_effort_days(total_frontend_files, 0.5, 1) if total_frontend_files <= 40 else \
                                     get_effort_days(total_frontend_files, 1, 2) if total_frontend_files <= 100 else \
                                     get_effort_days(total_frontend_files, 2, 4) if 100 < total_frontend_files < 500 else \
                                     get_effort_days(total_frontend_files, 3, 4) if total_frontend_files <= 1000 else \
                                     get_effort_days(total_frontend_files, 4, 5)

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
                .language-section {
                    margin-left: 20px;
                }
                .center-text {
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <h1>Code Review Effort Estimation Report</h1>
            <h2 class="center-text">Generated using Daksh SCRA</h2>

            <h2>Backend</h2>
            {% for language, language_data in backend_data.items() %}
            <div class="language-section">
                <h3>{{ language }}</h3>
                <p>Total files identified: {{ language_data.totalFiles }}</p>
                <p>Estimated efforts (hours): {{ backend_hours_min }} (minimum) - {{ backend_hours_max }} (maximum) hours</p>
                <p>Estimated efforts (days): {{ backend_days_min }} (minimum) - {{ backend_days_max }} (maximum) days</p>
            </div>
            {% endfor %}

            <h2>Frontend</h2>
            {% for language, language_data in frontend_data.items() %}
            <div class="language-section">
                <h3>{{ language }}</h3>
                <p>Total files identified: {{ language_data.totalFiles }}</p>
                <p>Estimated efforts (hours): {{ frontend_hours_min }} (minimum) - {{ frontend_hours_max }} (maximum) hours</p>
                <p>Estimated efforts (days): {{ frontend_days_min }} (minimum) - {{ frontend_days_max }} (maximum) days</p>
            </div>
            {% endfor %}

            <h2>Total Efforts (for the entire code review)</h2>
            <p>Total estimated effort (hours): {{ total_hours_min }} (minimum) - {{ total_hours_max }} (maximum) hours</p>
            <p>Total estimated effort (days): {{ total_days_min }} (minimum) - {{ total_days_max }} (maximum) days</p>
        </body>
        </html>
    '''

    # Render the Jinja2 template with the data
    template = Template(template_html)
    rendered_html = template.render(
        backend_data=backend_data,
        frontend_data=frontend_data,
        backend_hours_min=estimated_backend_effort_days[0],
        backend_hours_max=estimated_backend_effort_days[1],
        backend_days_min=estimated_backend_effort_days[0],
        backend_days_max=estimated_backend_effort_days[1],
        frontend_hours_min=estimated_frontend_effort_days[0],
        frontend_hours_max=estimated_frontend_effort_days[1],
        frontend_days_min=estimated_frontend_effort_days[0],
        frontend_days_max=estimated_frontend_effort_days[1],
        total_hours_min=total_estimated_effort_hours,
        total_hours_max=total_estimated_effort_hours,
        total_days_min=total_estimated_effort_hours / 8,
        total_days_max=total_estimated_effort_hours / 8
    )

    # Save the rendered HTML report to the global path
    with open(estimation_Fpath, 'w') as report_file:
        report_file.write(rendered_html)

    print("     [-] Effort estimation report: " + str(mlib.getRelativePath(estimation_Fpath)))












'''
Title : World's first Scientific approach to automated effort estimation for code review

This report is support to be a guidance to come up with an estimate that works for all stake holders.
If you are a company seeking for code review then this report gets you some number to validate
If you are a consulting firm then you have some mechanism to substantiate

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