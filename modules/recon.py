import os
import json
import re
import chardet
from pathlib import Path

import modules.misclib as mlib
import modules.runtime as runtime

# Exclusion list for file extensions
exclusion_list = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.tiff', '.zip',
                  '.svg', '.ttf', '.woff', '.woff2']


# Function to analyze the source code and perform reconnaissance
def perform_reconnaissance(source_code_path, technologies, existing_output):
    # Read the source code file with auto-detected encoding or fallback to a default encoding
    with open(source_code_path, 'rb') as file:
        raw_data = file.read()
        detection_result = chardet.detect(raw_data)
        encoding = detection_result['encoding'] if detection_result['encoding'] else 'utf-8'
        source_code = raw_data.decode(encoding, errors='replace')

    # Perform reconnaissance for each technology category
    recon_output = {category: set() for category in technologies.keys()}
    for category, tech_list in technologies.items():
        for tech in tech_list:
            # Check if the technology is already recorded in the existing output
            if tech['name'] in existing_output.get(category, set()):
                continue

            matches = re.findall(tech['regex'], source_code, re.IGNORECASE)
            if matches:
                recon_output[category].add(tech['name'])
                # Update the existing output
                existing_output.setdefault(category, set()).add(tech['name'])

    # Print the match found message if recon_output[category] is not empty
    for category in recon_output.keys():
        if recon_output[category]:
            print("Match Found: " + ", ".join(recon_output[category]))

    # Return the reconnaissance output
    return recon_output


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
    with open(runtime.technologies_Fpath, 'r') as json_file:
        technologies = json.load(json_file)

    # Output file path
    output_file_path = runtime.reconOutput_Fpath

    # Check if the output file already exists
    if Path(output_file_path).is_file():
        # Load the existing output from the JSON file
        with open(output_file_path, 'r') as existing_output_file:
            existing_output = json.load(existing_output_file)
    else:
        existing_output = {}

    # Perform reconnaissance on each file path within log_filepaths
    recon_output = {category: set() for category in technologies.keys()}
    for file_path in log_filepaths:
        file_recon_output = perform_reconnaissance(file_path, technologies, existing_output)
        for category, tech_set in file_recon_output.items():
            recon_output[category].update(tech_set)

    # Convert sets to lists
    recon_output = {category: list(tech_list) for category, tech_list in recon_output.items()}

    # Save the reconnaissance output in a JSON file, overwriting the existing output
    with open(output_file_path, 'w') as output_file:
        json.dump(recon_output, output_file, indent=4)

    print("Reconnaissance completed. The output has been saved in 'recon_output.json'")

    return log_filepaths


# WORK IN PROGRESS
wip = """
    Note: This feature is still work in progress. 
    The purpose of this feature is to perform a software/application level reconnaisance 
    to identify various useful details related to the target project. The reconnaisance would 
    include multiple sub-features and one such feature is automated software composition analysis. 

    Steps:
        *  Enum all file paths
        *  Enum each file types and total identified number
        *  Identify Design Pattern
        *  Identify application type (Misc, COTS, Unknown, CMS, Mobile, APIs)
        *  Conditional Check to identify application type (Use XML/Dict to specify conditions)
        *  Identify Standard Libs and total number
        *  Intelligent Enum - ON / OFF
        *  Enum TLOC

    Options:
        *  Ignore paths based on path or keyword
        *  Ignore files based on extentions
    """

#print(wip)