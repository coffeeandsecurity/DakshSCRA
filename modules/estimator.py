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
                    margin-top: 5px; 
                    margin-bottom: 5px; 
                }
                h2 {
                    color: #0066cc;
                    text-align: left;
                    margin-top: 5px; 
                    margin-bottom: 5px;
                }
                h3 {
                    color: #000000;
                    margin: 5px 0;
                    text-align: left;
                }
                .section-title {
                    color: #000000;
                    font-size: 1.5em;
                    margin-top: 10px;
                    margin-bottom: 5px;
                }
                .subsection-title {
                    color: #2F4F4F;
                    font-size: 1.2em;
                    margin-top: 5px;
                    margin-bottom: 5px;
                }
                p {
                    margin: 5px 0;
                }
                .notes {
                    font-size: 14px;
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
            <h2 class="center-text">Generated Using Daksh SCRA</h2>
            <h3 class="center-text">World's First Scientific Approach To Automated Code Review Effort Estimation</h3>
            <br>
            <div class="notes">
                <p>Note: This report offers approximate effort estimation figures for conducting source code reviews. 
                These figures should be considered as guidance to formulate an estimate that satisfies all stakeholders. 
                For organizations seeking code review services, this report offers benchmark figures that can be utilized to verify estimates provided by third-party companies. 
                Similarly, for security consulting firms, these estimated figures serve as supporting evidence for code review proposals put forth to clients.</p> 
                <p>It's important to note that the current version of this tool focuses solely on estimating efforts for web applications. 
                Nevertheless, as the estimation module undergoes multiple updates in the forthcoming months, support for all other types of applications will also be incorporated.</p>
            </div>
            <br>
            <div class="section-title">Backend</div>
            {% for info in backend_data %}
            <div class="language-section">
                <div class="subsection-title">{{ info['language'] }}</div>
                    <li>Total files identified: {{ info['total_files'] }}</li>
                    <li>Estimated efforts (days): {{ info['effort_days_min'] }} (minimum) - {{ info['effort_days_max'] }} (maximum) days</li>
            </div>
            {% endfor %}

            <div class="section-title">Frontend</div>
            {% for info in frontend_data %}
            <div class="language-section">
                <div class="subsection-title">{{ info['language'] }}</div>
                    <li>Total files identified: {{ info['total_files'] }}</li>
                    <li>Estimated efforts (days): {{ info['effort_days_min'] }} (minimum) - {{ info['effort_days_max'] }} (maximum) days</li>
            </div>
            {% endfor %}
            <br>
            <div class="section-title"><b>Total Efforts</b> (for the entire code review)</div>
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
        lower_bound, upper_bound = data['files_range']
        
        if lower_bound <= file_count <= (upper_bound if upper_bound != 999999 else 999999):
            if upper_bound == 999999:
                print("Maximum range exceeded!")
            return data['effort_range']
        
    raise ValueError(f"No effort range found for file count {file_count} and tech {tech}.")






'''
Title : World's first Scientific approach to automated effort estimation for code review


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