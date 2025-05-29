import os
import sys
import json
import re
import chardet
from pathlib import Path
from collections import Counter

import utils.file_utils as futils
import state.runtime_state as state
import utils.cli_utils as cli
#import modules.estimator as estimate

# Exclusion list for file extensions
exclusion_list = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.tiff', '.zip',
                  '.svg', '.ttf', '.woff', '.woff2']



def detectFramework(language, file_path):
    """
    Detects the framework used in a specified file based on its language.

    Loads framework definitions from a JSON file, checks if the specified language
    exists, and analyzes the file at `file_path` to identify any matching frameworks
    using file extensions and regex patterns.

    Parameters:
        language (str): The programming language (e.g., 'Python').
        file_path (str): The path to the file for analysis.

    Returns:
        str or None: The name of the detected framework or None if not found.

    Raises:
        FileNotFoundError: If the framework JSON file is missing.
        json.JSONDecodeError: If the JSON cannot be decoded.
    """

    # Load the JSON data from a file
    with open(state.framework_Fpath) as json_file:
        data = json.load(json_file)

    # Check if the language exists in the JSON data
    if language in data:
        frameworks = data[language]
        for framework in frameworks:
            regex_pattern = framework['regex']
            file_extensions = framework['fileExtensions']

            # Check if the file extension matches
            if file_path.endswith(tuple(file_extensions)):
                # Read the file content and detect the encoding
                with open(file_path, 'rb') as file_handle:
                    content = file_handle.read()
                    result = chardet.detect(content)
                    encoding = result['encoding'] if result['encoding'] is not None else 'ISO-8859-1'   # ISO-8859-1 encoding type works on most occasions including those where utf8 cause errors

                # Decode the file content using the detected encoding
                content = content.decode(encoding, errors='ignore')

                # Match the regex pattern
                match = re.search(regex_pattern, content, re.IGNORECASE)
                if match:
                    return framework['name']

    return None




def recon(targetdir, flag=False):
    """
    Performs software composition analysis on a specified directory to identify technologies and frameworks 
    used within the project files.

    This function scans the given target directory for project files, checks their extensions or matches them 
    against regex patterns defined for various technologies, and generates a summary of findings. The results 
    are saved to a JSON output file. Optionally, the function can operate in a mode suited for source code scanning.

    Parameters:
        targetdir (str): The directory path to be scanned for project files.
        flag (bool): A flag indicating whether to enable special behavior. If False, prints a header message for reconnaissance. 
                     If True, indicates the function is used in conjunction with source code scanning.

    Returns:
        tuple: A tuple containing:
            - log_filepaths (list): A list of file paths enumerated during the reconnaissance.
            - recSummary (dict): A summary of the reconnaissance results, typically containing identified technologies and frameworks.

    Raises:
        FileNotFoundError: If the technology details JSON file is not found.
        json.JSONDecodeError: If the JSON file cannot be decoded.
        IOError: If there is an error writing the output JSON file.
    """

    if flag == False:       # True is used when recon option is used along with source code scanning
        cli.section_print("[*] Reconnaissance (a.k.a Software Composition Analysis)")   
    
    if Path(state.inventory_Fpathext).is_file():
        os.remove(state.inventory_Fpathext)
    log_filepaths = []
    print("     [-] Enumerating project files and directories")
    for root, _, files in os.walk(targetdir):
        for file in files:
            file_path = os.path.join(root, file)
            _, extension = os.path.splitext(file_path)
            if extension.lower() not in exclusion_list:
                log_filepaths.append(file_path)

    # Load technology details from JSON file
    try:
        with open(state.technologies_Fpath, 'r') as json_file:
            technologies = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print("Error loading technology details:", str(e))
        return []

    # Output file path
    output_file_path = state.reconOutput_Fpath

    # Check if the output file already exists
    if Path(output_file_path).is_file():
        # Load the existing output from the JSON file
        try:
            with open(output_file_path, 'r') as existing_output_file:
                existing_output = json.load(existing_output_file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print("Error loading existing output:", str(e))
            existing_output = {}
    else:
        existing_output = {}

    # Perform reconnaissance on each file path within log_filepaths
    print("     [-] Performing reconnaissance...")
    recon_output = {}  # Initialize the recon_output dictionary
    for file_path in log_filepaths:
        #sys.stdout.write("\033[K")
        #print("         [-] Checking file:", file_path, end='\r')  # Print the file path being checked

        # Check the file extension against the identified technologies
        _, extension = os.path.splitext(file_path)
        for category, tech_list in technologies.items():
            for tech in tech_list:
                if isinstance(tech, dict):
                    regex_flag = tech.get('regexFlag', '1')
                    if regex_flag == '0':
                        # Check file extension if regexFlag is 0
                        file_extensions = tech.get('fileExtensions', [])
                        if extension.lower() in file_extensions:
                            # Match found based on file extension, confirm the technology
                            sys.stdout.write("\033[K") #clear line to prevent overlap of texts
                            print("     [-] Match found:", tech['name'], "in", category, end='\r')  # Print the matched technology name and category
                            #print(f"Framework: {detectFramework(tech['name'], file_path)}")

                            recon_output.setdefault(category, {}).setdefault(tech['name'], []).append(file_path)
                            if detectFramework(tech['name'], file_path) is not None:
                                recon_output.setdefault("Framework", {}).setdefault(detectFramework(tech['name'], file_path), []).append(file_path)
                            break  # No need to continue checking other technologies
                    else:
                        # Perform regex matching if regexFlag is 1
                        regex = tech.get('regex', '')
                        if regex and re.search(regex, file_path, re.IGNORECASE):
                            # Match found based on regex, confirm the technology
                            sys.stdout.write("\033[K") #clear line to prevent overlap of texts
                            print("     [-] Match found:", tech['name'], "in", category, end='\r')  # Print the matched technology name and category
                            recon_output.setdefault(category, {}).setdefault(tech['name'], []).append(file_path)
                            # print(f"Framework: {detectFramework(tech['name'], file_path)}")
                            if detectFramework(tech['name'], file_path) is not None:
                                recon_output.setdefault("Framework", {}).setdefault(detectFramework(tech['name'], file_path), []).append(file_path)

                            break  # No need to continue checking other technologies
                else:
                    print("Invalid technology entry in", category)

    # Save the reconnaissance output in a JSON file, overwriting the existing output
    try:
        with open(output_file_path, 'w') as output_file:
            json.dump(recon_output, output_file, indent=4, sort_keys=True)
    except IOError as e:
        print("     [-] Error saving reconnaissance output:", str(e))
    
    sys.stdout.write("\033[K") #clear line to prevent overlap of texts
    print("     [-] Reconnaissance completed.")     # The output has been saved in 'recon.json'

    # Summarise recon info
    recSummary = summariseRecon(output_file_path)
    
    # log_filepaths - is a list comprising of all the enumerated file paths. To be used later
    return log_filepaths, recSummary




def extractParentDirectory(file_paths):
    """
    Extracts the unique parent directories of the most common project folder from a list of file paths.

    This function identifies the project folder names from the given file paths, determines the most frequently occurring
    project folder name, and then collects the parent directories of those paths that match this most common project folder.


    Parameters:
        file_paths (list): A list of file paths.

    Returns:
        list: A list of unique parent directories that match the most common project folder name.
    """

    #print("filepaths: "+str(file_paths))
    # Extract project folder names from file paths
    project_folder_names = [os.path.basename(os.path.dirname(file_path)) for file_path in file_paths]

    # Find the most common project folder name
    common_project_folder = Counter(project_folder_names).most_common(1)

    if common_project_folder:
        # Get the most common project folder name
        most_common_folder = common_project_folder[0][0]

        # Extract parent directories using the most common project folder name
        parent_directories = set()
        for file_path in file_paths:
            directory_path = os.path.dirname(file_path)
            parent_directory = os.path.dirname(directory_path)
            if os.path.basename(parent_directory) == most_common_folder:
                parent_directories.add(parent_directory)

        return list(parent_directories)

    return []



def summariseRecon(json_file_path):
    """
    Generates a summary report from a given JSON recon file and saves it as recon_summary.json.

    This function reads a JSON file containing categorized file paths, counts the occurrences of files 
    in their respective directories, and summarizes this data into a structured format. The summary includes 
    total files and directories for each file type within the categories.

    Parameters:
        json_file_path (str): The path to the input JSON file containing recon data.

    Returns:
        str: The path to the generated summary JSON file (recon_summary.json).
    """

    with open(json_file_path, 'r') as file:
        data = json.load(file)

    summary = {}

    for category, files in data.items():
        category_summary = {}
        for file_type, file_paths in files.items():
            directory_counts = {}

            for file_path in file_paths:
                directory_path = '/'.join(file_path.split('/')[:-1])
                directory_counts[directory_path] = directory_counts.get(directory_path, 0) + 1

            file_type_summary = []
            for directory, count in directory_counts.items():
                file_type_summary.append({"directory": directory, "fileCount": count})

            category_summary[file_type] = {
                "directories": file_type_summary,
                "totalFiles": len(file_paths),
                "totalDirectories": len(directory_counts)
            }

        # Check if the category is "Framework"
        '''
        if category == "Framework":
            parent_directories = extractParentDirectory(file_paths)
            category_summary["ParentDirectory"] = parent_directories
        '''
        summary[category] = category_summary

    # Write the output to a JSON file "recon_summary.json" in the same folder as the input JSON file
    output_file_path = os.path.join(os.path.dirname(json_file_path), state.reconSummary_Fpath)
    with open(output_file_path, 'w') as output_file:
        json.dump(summary, output_file, indent=4, sort_keys=True)

    #print("     [-] Recon summary has been written to 'recon_summary.json'.")
    reconSummaryTextReport(state.reconSummary_Fpath, state.outputRecSummary)
    # estimate.effortEstimator(output_file_path)

    return output_file_path



def reconSummaryTextReport(json_file_path, output_file_path):
    """
    Parses a recon summary JSON file and generates a text-based reconnaissance summary report.

    This function reads data from a JSON file that contains the results of a software composition analysis 
    and creates a formatted text report. The report includes sections for different technology stacks and 
    provides a detailed overview of discovered platforms, frameworks, directories, and file counts.

    Parameters:
        json_file_path (str): The path to the input JSON file containing the recon summary data.
        output_file_path (str): The path where the generated text report will be saved.

    Returns:
        None: This function writes the summary report to the specified output file.
    """

    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)

    with open(output_file_path, 'w') as text_file:
        # Summarised Software Composition Analysis Output
        text_file.write("Software Composition Analysis Summary:\n")
        text_file.write("--------------------------------------\n")
        text_file.write("Below is a concise overview of the technologies, platforms, and frameworks identified in the overall solution.\n\n")

        sections = {
            "Backend": data.get("Backend", {}),
            "Frontend": data.get("Frontend", {}),
            "Mobile Platforms": data.get("Mobile Platforms", {}),
            "Database": data.get("Database", {}),
            "Shell Scripts": data.get("Shell Scripts", {}),
            "System Programs": data.get("System Programs", {}),
            "Framework": data.get("Framework", {}),
            "Design Patterns": data.get("Design Patterns", {}),
            "Libraries": data.get("Libraries", {}),
            "Cloud Services": data.get("Cloud Services", {})
        }

        for section_title, section_content in sections.items():
            if section_content:
                text_file.write(f"[*] {section_title}:\n")
                for sub_title in section_content:
                    text_file.write(f"    [-] {sub_title}\n")


        # Detailed Software Composition Analysis Output
        text_file.write("\nDetailed Software Composition Analysis:\n")
        text_file.write("---------------------------------------\n")
        #text_file.write("Below is a detailed overview of the technologies, platforms, and frameworks identified in the overall solution.\n\n")
        text_file.write("Below is a detailed overview of the technologies, platforms, and frameworks "
                "discovered within the overall solution, along with the associated directories and "
                "file counts related to the identified platforms.\n\n")


        for root_title, root_content in data.items():
            text_file.write(f"{root_title}:\n")
            for sub_title, sub_content in root_content.items():
                if isinstance(sub_content, dict):
                    text_file.write(f"  {sub_title}:\n")
                    common_root = os.path.commonpath([directory_info['directory'] for directory_info in sub_content['directories']])
                    text_file.write(f"    Common Root Directory: {common_root}{os.path.sep}\n")
                    for directory_info in sub_content['directories']:
                        relative_path = os.path.relpath(directory_info['directory'], common_root)
                        if relative_path == '.':
                            relative_path = ''
                        text_file.write(f"      {relative_path}{os.path.sep} - file(s) count: {directory_info['fileCount']}\n")
            text_file.write("\n")

    print("     [-] Reconnaissance summary report: " + str(futils.getReportsRootPath(output_file_path)))



