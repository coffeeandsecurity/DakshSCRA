import os
import sys
import json
import re
import chardet
from pathlib import Path
from collections import Counter

import modules.misclib as mlib
import modules.runtime as runtime
import modules.estimator as estimate

# Exclusion list for file extensions
exclusion_list = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.tiff', '.zip',
                  '.svg', '.ttf', '.woff', '.woff2']


def detectFramework(language, file_path):
    # Load the JSON data from a file
    with open(runtime.framework_Fpath) as json_file:
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



# Software composition analysis
def recon(targetdir, flag=False):
    if flag == False:       # True is used when recon option is used along with source code scanning
        print("\n[*] Reconnaissance (a.k.a Software Composition Analysis)")
    
    if Path(runtime.inventory_Fpathext).is_file():
        os.remove(runtime.inventory_Fpathext)
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
        with open(runtime.technologies_Fpath, 'r') as json_file:
            technologies = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print("Error loading technology details:", str(e))
        return []

    # Output file path
    output_file_path = runtime.reconOutput_Fpath

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




'''
This function takes a list of file_paths as input. It extracts the project folder names from the file paths and 
finds the most common project folder name using the Counter class. Then, it iterates over the file paths, extracts 
the parent directories, and checks if the parent directory's name matches the most common project folder name. 
If it matches, the parent directory is added to the parent_directories set. 
Finally, the function returns a list of all the extracted parent directories.
'''
def extractParentDirectory(file_paths):
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


'''
This function generates the recon_summary.json
'''
def summariseRecon(json_file_path):
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
    output_file_path = os.path.join(os.path.dirname(json_file_path), runtime.reconSummary_Fpath)
    with open(output_file_path, 'w') as output_file:
        json.dump(summary, output_file, indent=4, sort_keys=True)

    #print("     [-] Recon summary has been written to 'recon_summary.json'.")
    reconSummaryTextReport(runtime.reconSummary_Fpath, runtime.outputRecSummary)
    # estimate.effortEstimator(output_file_path)

    return output_file_path


'''
Parse the generated recon summary JSON file and generate the text based recon summary report. 
'''
def reconSummaryTextReport(json_file_path, output_file_path):
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

    print("     [-] Reconnaissance summary report: " + str(mlib.getRelativePath(output_file_path)))



