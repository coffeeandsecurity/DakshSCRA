import fnmatch
import os, sys, re
import pandas as pd
import chardet

import json
from json.decoder import JSONDecodeError

from tabulate import tabulate
from pathlib import Path    # Resolve the windows / mac / linux path issue
import xml.etree.ElementTree as ET

import modules.runtime as runtime


# Current directory of the python file
parentPath = os.path.dirname(os.path.realpath(__file__))

# Detect file encoding type
def detectEncodingType(targetfile):
    # Open the file in binary mode and read the first 1000 bytes to detect the encoding type
    with open(targetfile, 'rb') as f:
        result = chardet.detect(f.read(1000))
        
    return result['encoding']


def discoverFiles(codebase, sourcepath, mode):

    # mode '1' is for standard files discovery based on the filetypes/platform specified
    if mode == 1:
        ft = re.sub(r"\s+", "", GetRulesPathORFileTypes(codebase, "filetypes"))         # Get file types and use regex to remove any whitespaces in the string
        filetypes = list(ft.split(","))         # Convert the comman separated string to a list
        print("     [-] Filetypes Selected: " + str(filetypes))
        update_scanSummary("inputs_received.file_extensions_selected", str(filetypes))
    elif mode == 2:
        filetypes = '*.*'
        update_scanSummary("inputs_received.file_extensions_selected", str(filetypes))

    matches = []
    fext = []

    parentPath = runtime.root_dir                               # Daksh root directory 
    print("     [-] DakshSCRA Directory Path: " + runtime.root_dir)      
    
    f_filepaths = open(runtime.discovered_Fpaths, "w+")         # File ('discovered_Fpaths') for logging all discovered file paths

    print("     [-] Identifying total files to be scanned!")
    linescount = 0
    filename = None     # To be removed. Temporarily added to fix - "local variable referenced before assignment" error
    fCnt = 0

    # Reccursive Traversal of Directories and Files
    for root, dirnames, filenames in os.walk(sourcepath):           # os.walk - Returns root dir, dirnames, filenames
        for extensions in filetypes:
            for filename in fnmatch.filter(filenames, extensions):
                matches.append(os.path.join(root, filename))
                filename = os.path.join(root, filename)
                f_filepaths.write(filename + "\n")  # Log discovered file paths
                linescount += 1
            
                fCnt += 1
                # print("[*] Counter = " + str(fCnt) + " File Extension: " + GetFileExtention(filename))
                # print("[*] Counter = " + str(fCnt) + " Filename: " + filename)
                # print("[*] Counter = " + str(fCnt) + " Dictionary: " + str(FileExtentionInventory(filename)))

            fext.append(GetFileExtention(filename))
            
    # print("[*] Counter - Outer Loop = " + str(fCnt))
    fCnt = 0
    f_filepaths.close()
    

    print("     [-] Total files to be scanned: " + str(linescount))
    fext = list(dict.fromkeys(filter(None, fext)))      # filter is used to remove empty item that gets added due to 'filename = None' above
    print("     [-] File Extentions Identified: " + str(fext))

    #cleanfilepaths(settings.discovered_Fpaths)

    return runtime.discovered_Fpaths

# Retrieve files extention from file path
def GetFileExtention(fpath):
    extention = Path(str(fpath)).suffix

    return extention


# Discovered files extentions and count of each type
def FileExtentionInventory(fpath):
    extention = Path(str(fpath)).suffix

    inventory = {}
    inventory["file"] = fpath 
    inventory["extension"] = extention

    inventory = json.dumps(inventory)           # Convert dictionary to string object
    inventory = json.loads(inventory)      # Take a string as input and returns a dictionary as output.
    # print("Inventory: " + str(load_inventory))
    # print("Inventory: " + str(inventory))


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
                #outfile.seek(0,2)
                json.dump(str(inventory), outfile, indent=2)
                outfile.close
                print("TypeError block: ")

    '''
        if not data:
            with open(settings.inventory_Fpathext, "w") as outfile:
                json.dump(data, outfile)
                outfile.close
        else:
            outfile.close
            with open(settings.inventory_Fpathext, "w") as outfile:
                data.append(inventory)
                json.dump(data, outfile)
                outfile.close   

    with open(settings.inventory_Fpathext, "w") as outfile:
            json.dump(inventory, outfile)
            outfile.close   
    '''
    return inventory


# Remove all files in the temp dir
def DirCleanup(dirname):
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



def GetSourceFilePath(project_dir, source_file):
    pattern = re.compile(project_dir + '.+')

    source_filepath = ''
    try:
        source_filepath = pattern.search(source_file)[0]
    except TypeError as e:      # The "'NoneType' object is not subscriptable" error occurs on windows. 
        # print(e)              # This error handling is meant to getaround the error caused on windows os
        source_filepath = source_file

    return source_filepath


# Function to replace absolute file paths with project file paths 
# by stripping out the path before the project directory
def clean_filepaths(filepaths_source):
    target_dir = os.path.dirname(filepaths_source)
    source_file = os.path.join(target_dir, "filepaths.log")
    dest_file = os.path.join(target_dir, "filepaths.txt")

    with open(source_file, "r") as h_sf, open(dest_file, "w") as h_df:
        for eachfilepath in h_sf:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
            h_df.write(GetSourceFilePath(runtime.sourcedir, filepath) + "\n")


    #os.unlink(source_file)

# Function to obtain rules file path of a particular platform or the supported filetypes 
def GetRulesPathORFileTypes(platform, option):

    while option not in ["filetypes", "rules"]:
        print("Error (GetRulesPathORFileTypes): Invalid option supplied. Allowed options are [rules or filetypes]!")
        sys.exit()

    retValue = ''

    # Load filetypes XML config file
    xmltree = ET.parse(runtime.rulesConfig)
    rule = xmltree.getroot()

    if option == "filetypes":
        for r in rule:
            if r.find("platform").text == platform:
                retValue = r.find("ftypes").text        # Return file types
                break
    elif option == "rules":
        for r in rule:
            if r.find("platform").text == platform:
                retValue = r.find("path").text          # Return rule file path
                break

    else:
        print("Error: Invalid value of rulesORfiletypes!")

    return retValue



def rules_count(rules_file):
    try:
        tree = ET.parse(rules_file)
        root = tree.getroot()

        total_rules_count = 0  # Initialise the count

        # Iterate over the rule elements
        for rule in root.findall('rule'):
            total_rules_count += 1

        return total_rules_count

    except ET.ParseError as e:
        print(f"Error parsing XML file: {str(e)}")
        return 0


# List/Show rules or supported filetypes or both
def ListRulesFiletypes(option):
    retValue = 0
    dict = {}

    # Load filetypes XML config file
    xmltree = ET.parse(runtime.rulesConfig)
    rule = xmltree.getroot()


    if option == 'R':
        print("\nList of all available rules")
        for r in rule:
            print("\t" + r.find("platform").text)        # Return supported platforms
            retValue = 1

    elif option == 'RF':
        print("\nList both available rules and filetypes")
        for r in rule:
            #print(tabulate([["Platform","File Types"],[r.find("platform").text, r.find("ftypes").text]], headers="firstrow", tablefmt="psql"))
            dict[r.find("platform").text] = r.find("ftypes").text
            retValue = 1
    
        df = pd.DataFrame.from_dict(dict, orient='index')
        print("\n" + tabulate(df, headers=["Platform", "File Types"], tablefmt="grid", maxcolwidths=[None, 40]) + "\n")

    else:
        print("Invalid option")
        retValue = 0


    return retValue


# Function to update a specific entry in the scan summary JSON file
def update_scanSummary(key, value):
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
                "total_files_identified": 0,
                "total_files_scanned": 0,
                "file_extensions_identified": [],
                "areas_of_interest_identified": 0,
                "file_paths_areas_of_interest_identified": 0
            },
            "scanning_timeline": {
                "scan_start_time": "",
                "scan_end_time": "",
                "scan_duration": ""
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

        # Update the specific entry in the dictionary
        current[levels[-1]] = value

        with open(json_filename, "w") as file:
            json.dump(data, file, indent=4)

        #print(f"Updated entry '{key}' with value '{value}'.")
    except (KeyError, TypeError) as e:
        print(f"An error occurred while updating entry '{key}': {str(e)}")
        print(f"Entry '{key}' does not exist or is not accessible.")
    except Exception as e:
        print(f"An error occurred while updating entry '{key}': {str(e)}")

