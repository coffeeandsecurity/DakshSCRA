import os
import sys
import json
import re
import chardet
from pathlib import Path

import modules.misclib as mlib
import modules.runtime as runtime


# Exclusion list for file extensions
exclusion_list = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.tiff', '.zip',
                  '.svg', '.ttf', '.woff', '.woff2']


# Identify CMS function
def identify_cms(technology, programming_language, file_path):
    with open(runtime.technologies_Fpath) as file:
        cms_data = json.load(file)

    cms_types = cms_data.get('Framework', {}).get(programming_language, [])
    print("CMS Types: " + str(cms_types))

    for cms_type in cms_types:
        print("CMS Type: " + str(cms_type))
        regex = cms_type['regex']
        regex_flag = cms_type['regexFlag']
        file_extensions = cms_type['fileExtensions']

        if any(file_path.endswith(extension) for extension in file_extensions):
            if regex_flag == '0':
                if re.search(regex, technology, re.IGNORECASE):
                    return cms_type['name']
            else:
                if re.search(regex, technology):
                    return cms_type['name']

    return None



# Software composition analysis
def recon(targetdir):
    print("\n--- Project reconnaissance ---")
    print("\n[*] Software Composition Analysis!!")
    if Path(runtime.inventory_Fpathext).is_file():
        os.remove(runtime.inventory_Fpathext)
    log_filepaths = []
    for root, _, files in os.walk(targetdir):
        for file in files:
            file_path = os.path.join(root, file)
            _, extension = os.path.splitext(file_path)
            if extension.lower() not in exclusion_list:
                log_filepaths.append(file_path)

    # Load technology details from JSON file
    print("Loading technology details...")
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
    print("Performing reconnaissance...")
    recon_output = {}  # Initialize the recon_output dictionary
    for file_path in log_filepaths:
        print("Checking file:", file_path)  # Print the file path being checked
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
                            print("Match found:", tech['name'], "in", category)  # Print the matched technology name and category
                            '''
                            cms = identify_cms(tech['name'], category, file_path)  # Identify the CMS for the technology
                            if cms:
                                print("Identified CMS:", cms)  # Print the identified CMS
                                existing_output.setdefault(category, {}).setdefault(tech['name'], {}).setdefault(file_path, cms)
                            '''
                            recon_output.setdefault(category, {}).setdefault(tech['name'], []).append(file_path)
                            break  # No need to continue checking other technologies
                    else:
                        # Perform regex matching if regexFlag is 1
                        regex = tech.get('regex', '')
                        if regex and re.search(regex, file_path, re.IGNORECASE):
                            # Match found based on regex, confirm the technology
                            print("Match found:", tech['name'], "in", category)  # Print the matched technology name and category
                            '''
                            cms = identify_cms(tech['name'], category, file_path)  # Identify the CMS for the technology
                            if cms:
                                print("Identified CMS:", cms)  # Print the identified CMS
                                existing_output.setdefault(category, {}).setdefault(tech['name'], {}).setdefault(file_path, cms)
                            '''
                            recon_output.setdefault(category, {}).setdefault(tech['name'], []).append(file_path)
                            break  # No need to continue checking other technologies
                else:
                    print("Invalid technology entry in", category)

    # Save the reconnaissance output in a JSON file, overwriting the existing output
    print("Saving reconnaissance output...")
    try:
        with open(output_file_path, 'w') as output_file:
            json.dump(recon_output, output_file, indent=4)
    except IOError as e:
        print("Error saving reconnaissance output:", str(e))

    print("Reconnaissance completed. The output has been saved in 'recon_output.json'")

    summariseRecon(output_file_path)
    
    return log_filepaths


'''
Function to list directories grouped by file extensions or technology type, 
along with the count of each file type within each directory. 
It takes the path to the initial recon JSON output file, reads and analyses the details, 
and dumps the output in a JSON format within the same directory as the input JSON file.
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

        summary[category] = category_summary

    # Write the output to a JSON file "recon_summary.json" in the same folder as the input JSON file
    output_file_path = os.path.join(os.path.dirname(json_file_path), "recon_summary.json")
    with open(output_file_path, 'w') as output_file:
        json.dump(summary, output_file, indent=4)

    print("Summary data has been written to 'recon_summary.json'.")





