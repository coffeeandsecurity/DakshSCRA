import fnmatch
import os, sys, re
import pandas as pd
import chardet
import string

import json
from json.decoder import JSONDecodeError

import ruamel.yaml
from ruamel.yaml import YAML

from tabulate import tabulate
from pathlib import Path    # Resolve the windows / mac / linux path issue
import xml.etree.ElementTree as ET
from colorama import Fore, Style

import modules.runtime as runtime
import modules.rulesops as rulesops


# Current directory of the python file
parentPath = os.path.dirname(os.path.realpath(__file__))


def saveYaml(file_path, data):
    with open(file_path, "w") as file:
        ruamel.yaml.safe_dump(data, file)


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
            # ruamel.yaml.round_trip_dump(config_data, file)        <-- To be removed - deprecated
            yaml.dump(config_data, file)



def validate_input(input_string, input_type):
    """
    Validate the input string based on type, length, and allowed characters.

    Parameters:
        input_string (str): The string to validate.
        input_type (str): The type of input, either 'name' or 'path'.

    Returns:
        bool: True if input is valid, False if it exceeds length limits or contains invalid characters.
    """

    allowed_chars = string.ascii_letters + string.digits + '-_()'
    max_length = 50
    
    if input_type == 'name':
        allowed_chars = string.ascii_letters + string.digits + '-_() '
        max_length = 50
    elif input_type == 'path':
        allowed_chars = string.ascii_letters + string.digits + '-_/\\'
        max_length = 100
    
    if len(input_string) > max_length:
        print(f"Input exceeds maximum length of {max_length} characters.")
        return False
    elif any(char not in allowed_chars for char in input_string):
        print(f"Input contains invalid characters. Only the following characters are allowed: {allowed_chars}")
        return False
    else:
        return True

# Detect file encoding type
def detectEncodingType(targetfile):
    # Open the file in binary mode and read the first 1000 bytes to detect the encoding type
    with open(targetfile, 'rb') as f:
        result = chardet.detect(f.read(1000))
        
    return result['encoding']



def discoverFiles(codebase, sourcepath, mode):
    """
    Discovers files for specified platforms and logs paths to platform-specific and master log files.

    Parameters:
        codebase (str): Comma-separated list of platforms to discover files for.
        sourcepath (str): Directory path to search for files.
        mode (int): Determines file type retrieval method (1 for specific types, 2 for all types).

    Returns:
        str: Path to the master log file containing discovered file paths.
    """

    platforms = list(dict.fromkeys(re.sub(r"\s+", "", codebase).split(",")))
    #print(f"     [DEBUG] Platforms: {platforms}")
    print(f"{Fore.CYAN}     [-] Selected Platforms and Respective Filetypes: {Style.RESET_ALL}")
    #print(f"{Fore.CYAN}     [-] Platforms: {Style.RESET_ALL}")

    platform_filetypes = {}  # Store platform-specific filetypes
    platform_extensions = {}  # Store identified extensions per platform
    matches, total_files_count = [], 0
    identified_files_count = 0

    # Create or return the /runtime/platform directory and clear existing logs
    platform_dir = runtime.runtime_dirpath / "platform"
    platform_dir.mkdir(parents=True, exist_ok=True)

    # Clear all existing platform-specific log files
    for log_file in platform_dir.glob("filepaths_*.log"):
        log_file.unlink()

    # Initialize platform-specific filetypes if mode is 1
    if mode == 1:
        for platform in platforms:
            ft = rulesops.getRulesPath_OR_FileTypes(platform, "filetypes")
            platform_filetypes[platform] = list(dict.fromkeys(ft.split(",")))
            platform_extensions[platform] = []  # Initialize empty list for each platform

            print(f"         [-] {platform.capitalize()} Filetypes: {platform_filetypes[platform]}")
            #print(f"{Fore.YELLOW}     [-] {platform.capitalize()} Filetypes: {platform_filetypes[platform]}{Style.RESET_ALL}")

    elif mode == 2:  # Default to *.* if mode 2 is used
        platform_filetypes = {platform: ['*.*'] for platform in platforms}
        platform_extensions = {platform: [] for platform in platforms}

    master_log_path = runtime.runtime_dirpath / "filepaths.log"
    with open(master_log_path, "w+") as master_log:

        # Traverse the source path to discover and log files
        for root, _, filenames in os.walk(sourcepath):
            total_files_count += len(filenames)

            for platform, extensions in platform_filetypes.items():
                platform_log_path = platform_dir / f"filepaths_{platform}.log"

                with open(platform_log_path, "a") as platform_log:
                    for ext in extensions:
                        ext = ext.strip()  # Remove spaces
                        matched_files = fnmatch.filter(filenames, ext)

                        for filename in matched_files:
                            full_path = os.path.join(root, filename)

                            platform_log.write(full_path + "\n")
                            master_log.write(full_path + "\n")

                            matches.append(full_path)
                            identified_files_count += 1

                            ext_value = getFileExtention(full_path)
                            if ext_value and ext_value not in platform_extensions[platform]:
                                platform_extensions[platform].append(ext_value)

    # Print identified file extensions per platform
    #print("     [-] Identified File Types:")
    print(f"{Fore.CYAN}     [-] Discovered/Identified File Types:{Style.RESET_ALL}")
    for platform, exts in platform_extensions.items():
        print(f"         [-] {platform.capitalize()}: {exts}")

    # Print and update scan summary
    print(f"     [-] Total project files in the directory: {total_files_count}")
    print(f"     [-] Total files to be scanned: {identified_files_count}")

    updateScanSummary("detection_summary.total_project_files_identified", str(total_files_count))
    updateScanSummary("detection_summary.total_files_identified", str(identified_files_count))
    updateScanSummary("detection_summary.file_extensions_identified", platform_extensions)

    runtime.totalFilesIdentified = identified_files_count

    return master_log_path  # Return master log path




# This is a test function and will be merged with the above function
def reconDiscoverFiles(codebase, sourcepath, mode):
    if mode == 1:
        ft = re.sub(r"\s+", "", rulesops.getRulesPath_OR_FileTypes(codebase, "filetypes"))
        filetypes = list(ft.split(","))
        print("     [-] Filetypes Selected: " + str(filetypes))
        updateScanSummary("inputs_received.file_extensions_selected", str(filetypes))
    elif mode == 2:
        filetypes = ['*.*']
        updateScanSummary("inputs_received.file_extensions_selected", str(filetypes))

    matches = []
    fext = []

    # print("     [-] DakshSCRA Directory Path: " + runtime.root_dir)
    
    identified_files = []  # List to store discovered file paths

    for root, dirnames, filenames in os.walk(sourcepath):
        for extensions in filetypes:
            for filename in fnmatch.filter(filenames, extensions):
                file_path = os.path.join(root, filename)
                matches.append(file_path)
                identified_files.append(file_path)
                fext.append(getFileExtention(filename))

    print("     [-] Total files to be scanned: " + str(len(identified_files)))
    updateScanSummary("detection_summary.total_files_identified", str(len(identified_files)))
    updateScanSummary("detection_summary.file_extensions_identified", str(fext))

    runtime.totalFilesIdentified = str(len(identified_files))

    fext = list(dict.fromkeys(filter(None, fext)))

    print("     [-] File Extensions Identified: " + str(fext))
    updateScanSummary("detection_summary.file_extensions_identified", str(fext))

    return identified_files



# Return relative paths related to reports - Temp option. Will be removed later
def getRelativePath(fpath):
    # Convert PosixPath object to string
    fpath = str(fpath)

    # Check if the path is relative
    if not os.path.isabs(fpath):
        return fpath  # Return full path if it is relative

    # Get the index of the '/reports' directory in the full file path
    reports_index = fpath.find('/reports')

    # Check if '/reports' directory exists in the path
    if reports_index == -1:
        return None  # Return None if '/reports' directory is not found

    # Extract the relative path from the '/reports' directory onwards
    relative_path = fpath[reports_index:]

    return relative_path


# Retrieve files extention from file path
def getFileExtention(fpath):
    extention = Path(str(fpath)).suffix

    return extention


# Discovered files extentions and count of each type
def fileExtentionInventory(fpath):
    extention = Path(str(fpath)).suffix

    inventory = {}
    inventory["file"] = fpath 
    inventory["extension"] = extention

    inventory = json.dumps(inventory)           # Convert dictionary to string object
    inventory = json.loads(inventory)           # Take a string as input and returns a dictionary as output.


    with open(runtime.inventory_Fpathext, "a+") as outfile:
        try:
            data = json.loads(outfile)
            data = data.append(inventory)
            #outfile.seek(0,2)
            json.dump(data, outfile, indent=2)
            outfile.close
            print("Try block: ")
        
        except TypeError as e:
            with open(runtime.inventory_Fpathext, "a+") as outfile:
                json.dump(str(inventory), outfile, indent=2)
                outfile.close
                print("TypeError block: ")

    return inventory


# Remove all files in the temp dir
def dirCleanup(dirname):
    dir = Path(parentPath + "/../" + dirname)
    if os.path.exists(dir):
        for the_file in os.listdir(dir):
            file_path = os.path.join(dir, the_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)
    else:  # Force create output directory if it doesn't exist
        os.makedirs(dir)
    return



def getSourceFilePath(project_dir, source_file):
    pattern = re.compile(project_dir + '.+')

    source_filepath = ''
    try:
        source_filepath = pattern.search(source_file)[0]
    except TypeError as e:      # The "'NoneType' object is not subscriptable" error occurs on windows. 
        source_filepath = source_file

    return source_filepath


def getShortPath(file_path):

    short_file_path = getSourceFilePath(runtime.sourcedir, file_path)

    directory, filename = os.path.split(file_path)
    shortened = '..[SHORTENED]..'
    return f"{os.sep}{directory.split(os.sep)[1]}{os.sep}{shortened}{os.sep}{filename}"



def cleanFilePaths(filepaths_source):
    """
    Cleans file paths by replacing absolute paths with relative project paths.

    Parameters:
        filepaths_source (str): The source file path for which to clean paths.

    Returns:
        None: The function writes cleaned paths to a text file.
    """

    target_dir = os.path.dirname(filepaths_source)
    source_file = os.path.join(target_dir, "filepaths.log")
    dest_file = os.path.join(target_dir, "filepaths.txt")

    with open(source_file, "r") as h_sf, open(dest_file, "w") as h_df:
        for eachfilepath in h_sf:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
            h_df.write(getSourceFilePath(runtime.sourcedir, filepath) + "\n")

    runtime.discovered_clean_Fpaths = dest_file
    #os.unlink(source_file)



def updateScanSummary(key, value):
    """
    Updates a specified entry in the scan summary JSON file.

    If the JSON file is missing, it creates one with default data.

    Parameters:
        key (str): The key path to the entry in the JSON structure to update.
        value (any): The new value to assign to the specified key.

    Returns:
        None: The function modifies the JSON file in place.
    """

    json_filename = runtime.scanSummary_Fpath

    # Create the JSON file with default data if the file is missing.
    if not os.path.isfile(json_filename):
        default_data = {
            "inputs_received": {
                "rule_selected": "",
                "total_rules_loaded": 0,
                "platform_specific_rules": 0,
                "common_rules": 0,
                "target_directory": "",
                "filetypes_selected": "",
                "file_extensions_selected": []
            },
            "detection_summary": {
                "total_project_files_identified": 0,
                "total_files_identified": 0,
                "total_files_scanned": 0,
                "file_extensions_identified": {},
                "areas_of_interest_identified": 0,
                "file_paths_areas_of_interest_identified": 0
            },
            "scanning_timeline": {
                "scan_start_time": "",
                "scan_end_time": "",
                "scan_duration": ""
            },
            "source_files_scanning_summary": {
                "matched_rules": [],
                "unmatched_rules": []
            },
            "paths_scanning_summary": {
                "matched_rules": [],
                "unmatched_rules": []
            }
        }

        with open(json_filename, "w") as file:
            json.dump(default_data, file, indent=4)

    try:
        with open(json_filename, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        data = {}

    # Split the key into nested levels
    levels = key.split(".")
    current = data

    try:
        # Traverse the levels to access the innermost dictionary
        for level in levels[:-1]:
            current = current[level]

        # If updating file extensions, ensure it's grouped by platform
        if key == "detection_summary.file_extensions_identified":
            # Merge new platform-specific extensions with existing ones
            if not isinstance(current[levels[-1]], dict):
                current[levels[-1]] = {}  # Initialize as a dictionary if not already

            for platform, extensions in value.items():
                current[levels[-1]].setdefault(platform, []).extend(extensions)
                # Remove duplicates
                current[levels[-1]][platform] = list(set(current[levels[-1]][platform]))

        else:
            # Update the specific entry in the dictionary
            current[levels[-1]] = value

        with open(json_filename, "w") as file:
            json.dump(data, file, indent=4)

    except (KeyError, TypeError) as e:
        print(f"An error occurred while updating entry '{key}': {str(e)}")
        print(f"Entry '{key}' does not exist or is not accessible.")
    except Exception as e:
        print(f"An error occurred while updating entry '{key}': {str(e)}")




# Display tool's usage details in the console
def toolUsage(option):
    if option == 'invalid_dir':
        print("\nExample: python dakshsca.py -r php -t /path_to_source_dir")
        print("Example: python dakshsca.py -r php -f php -t /path_to_source_dir\n")

    else:
        print("\nExamples:")
        
        print(" # '-f' is optional. If not specified, it will default to the corresponding filetypes of the selected rule.")
        print("   dakshsca.py -r php -t /source_dir_path\n")
        
        print(" # To override default settings, other filetypes can be specified with '-f' option.")
        print("   dakshsca.py -r php -f dotnet -t /path_to_source_dir")
        print("   dakshsca.py -r php -f custom -t /path_to_source_dir\n")
        
        print(" # Perform reconnaissance and rule based scanning if '-recon' used with '-r' option.")
        print("   dakshsca.py  -recon -r php -t /path_to_source_dir\n")

        print(" # Perform only reconnaissance if '-recon' used without the '-r' option.")
        print("   dakshsca.py  -recon -t /path_to_source_dir\n")

        print(" # Verbosity: '-v' is default, '-vvv' will display all rules check within each rule category.")
        print("   dakshsca.py -r php -vv -t /path_to_source_dir\n")
    
        print("Note: You must run the tool using appropriate python environment.")
        print("For Example: python3 dakshsca.py -r php -t /source_dir_path\n")
    
    return


# Removes duplicates from a comma-separated string and preserves order.
def remove_duplicates(value):
    if value:
        unique_values = list(dict.fromkeys(value.split(',')))  # Remove duplicates while preserving order
        return ','.join(unique_values)
    return value
