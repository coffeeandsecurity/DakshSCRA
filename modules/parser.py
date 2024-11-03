import re
import sys
import json
import ast
import xml.etree.ElementTree as ET
from pathlib import Path 
from timeit import default_timer as timer

import modules.runtime as runtime
import modules.utils as ut



def sourceParser(rule_input, targetfile, outputfile):
    """
    Parses rules from XML files and applies them to target files.
    Supports both individual Path and dictionary of Paths as input.

    Parameters:
        rule_input (dict or Path): Rule file paths or a single Path to an XML file.
        targetfile (str): File containing paths of target source files.
        outputfile (str): File to write scan results.

    Returns:
        tuple: (matched_rules, unmatched_rules) - Lists of rule titles for matched and unmatched patterns.
    """

    # Determine if input is a dict or a single Path
    if isinstance(rule_input, dict):
        rule_paths = rule_input.values()
    elif isinstance(rule_input, Path):
        rule_paths = [rule_input]
    else:
        raise TypeError(f"Expected a dict or Path, but got {type(rule_input)}")

    f_scanout = outputfile
    f_targetfiles = targetfile

    iCnt = 0
    rule_no = runtime.rCnt
    error_count = 0
    unmatched_rules = []     # Store unmatched patterns
    matched_rules = []       # Store matched patterns

    # Process each rule path
    for rule_path in rule_paths:
        xmltree = ET.parse(rule_path)
        root = xmltree.getroot()

        #print(f"     [-] Parsing rules from: {rule_path}")

        for category in root:
            category_name = category.get('name')
            if category_name:
                print(f"     [-] Category: {category_name}")

            for rule in category:
                rule_title = rule.find("name").text
                pattern = rule.find("regex").text            
                rule_desc = rule.find("rule_desc").text
                vuln_desc = rule.find("vuln_desc").text
                dev_note = rule.find("developer").text
                rev_note = rule.find("reviewer").text

                exclude = rule.find("exclude").text if rule.find("exclude") is not None else ""
                flag_title_desc = False

                #print(f"         [-] Applying Rule: {rule_title}")
                
                # stdout based on verbosity level set
                if str(runtime.verbosity) == '1' or str(runtime.verbosity) == '2':
                    #sys.stdout.write("\033[F")      # move the cursor up one line 
                    #sys.stdout.write("\033[K")     # clear line to prevent overlap of texts
                    print(f"         [-] Applying Rule: {rule_title}", end='\r')
                else:
                    sys.stdout.write("\033[K")
                    print(f"         [-] Applying Rule: {rule_title}")

                # Process each target file
                for eachfilepath in f_targetfiles:
                    filepath = eachfilepath.rstrip()
                    iCnt += 1

                    if str(runtime.verbosity) == '1':
                        if len(filepath) > 60:
                            print('\t Parsing file: ' + "["+str(iCnt)+"] "+ ut.getShortPath(filepath), end='\r')
                        else:
                            print('\t Parsing file: ' + "["+str(iCnt)+"] "+ filepath, end='\r')
                    else:
                        print('\t Parsing file: ' + "["+str(iCnt)+"] "+ ut.getSourceFilePath(runtime.sourcedir, filepath), end='\r')
                    
                    sys.stdout.write("\033[K")     # clear line to prevent overlap of texts
                    #sys.stdout.write("\033[F\033[K")  # move the cursor up one line and clear line to prevent overlap of texts

                    try:
                        with open(filepath, 'r', encoding='ISO-8859-1') as fo_target:
                            linecount = 0
                            flag_fpath = False

                            for line in fo_target:
                                linecount += 1
                                if len(line) > 500:
                                    continue  # Skip overly long lines

                                # Apply regex matching
                                if re.findall(pattern, line):
                                    if exclude and re.search(exclude, line, re.IGNORECASE):
                                        continue  # Skip if exclude rule matches

                                    line = (line[:75] + '..') if len(line) > 300 else line

                                    if not flag_title_desc:
                                        if rule_no > 0:
                                            f_scanout.write("\n\n")  # Add newlines before first entry
                                        flag_title_desc = True
                                        rule_no += 1
                                        runtime.rulesMatchCnt += 1
                                        matched_rules.append(rule_title)

                                        f_scanout.write(
                                            f"{rule_no}. Rule Title: {rule_title}\n"
                                            f"\n\t Rule Description  : {rule_desc}"
                                            f"\n\t Issue Description : {vuln_desc}"
                                            f"\n\t Developer Note    : {dev_note}"
                                            f"\n\t Reviewer Note     : {rev_note} \n"
                                        )

                                    if not flag_fpath:
                                        flag_fpath = True
                                        f_scanout.write(
                                            f"\n\t -> Source File: {ut.getSourceFilePath(runtime.sourcedir, filepath)}\n"
                                            f"\t\t [{linecount}] {line}"
                                        )
                                    else:
                                        f_scanout.write(f"\t\t [{linecount}] {line}")

                        if rule_title not in matched_rules:
                            unmatched_rules.append(rule_title)

                    except (FileNotFoundError, PermissionError, UnicodeError) as e:
                        print(f"Error processing {filepath}: {e}")
                        error_count += 1

                f_targetfiles.seek(0)  # Reset the target files pointer
                runtime.rCnt = rule_no  # Update runtime rule counter
                iCnt = 0  # Reset file counter
                #sys.stdout.write("\033[K")  # Clear line to prevent overlap of texts

        # Remove duplicates from the matched and unmatched rules lists
        matched_rules = list(set(matched_rules))
        unmatched_rules = list(set(unmatched_rules))

    runtime.parseErrorCnt += error_count
    return matched_rules, unmatched_rules




def pathsParser(rule_path, targetfile, outputfile, rule_no):
    """
    Parses file paths and matches them against specified patterns from an XML rule file.

    This routine reads the XML rules, checks each file path from the target file against 
    the defined regex patterns, and categorizes them into matched and unmatched rules.

    Parameters:
        rule_path (str): Path to the XML file containing matching rules.
        targetfile (file-like object): File object containing paths to be scanned.
        outputfile (file-like object): File object for writing matched results.
        rule_no (int): The initial rule number for matched output.

    Returns:
        tuple: A list of matched rules and a list of unmatched rules.
    """

    # Load rules from XML file
    xmltree = ET.parse(rule_path)
    rule = xmltree.getroot()

    f_scanout = outputfile
    f_targetfilepaths = targetfile
    pFlag = False

    rule_no = 0
    unmatched_rules = []     # List to store unmatched patterns
    matched_rules = []       # List to store matched patterns

    for r in rule:
        #rule_no += 1
        #f_scanout.write(f"{rule_no}. Rule Title: {r.find('name').text}\n")

        pattern = r.find("regex").text
        pattern_name = r.find("name").text

        for eachfilepath in f_targetfilepaths:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()    # strip out '\r' or '\n' from the file paths
            filepath = ut.getSourceFilePath(runtime.sourcedir, filepath)

            if re.findall(pattern, filepath, flags=re.IGNORECASE):   # If there is a match
                if pFlag == False:
                    rule_no += 1
                    runtime.rulesPathsMatchCnt += 1
                    matched_rules.append(pattern_name)  # Add matched patterns to the list
                    f_scanout.write(f"{rule_no}. Rule Title: {r.find('name').text}\n")
                    f_scanout.write(("\tFile Path: " + filepath) + "\n")
                    print("     [-] File Path Rule:" + pattern_name)

                    sys.stdout.write("\033[F") #back to previous line
                    sys.stdout.write("\033[K") #clear line to prevent overlap of texts
                    
                    pFlag = True
                else: 
                    f_scanout.write(("\tFile Path: " + filepath) + "\n")             
                
            else:
                unmatched_rules.append(pattern_name)  # Add unmatched items to the list

        pFlag = False
        f_targetfilepaths.seek(0, 0)

    # Remove duplicates from unmatched items list
    unmatched_rules = list(set(unmatched_rules))
    '''
    # Print unmatched patterns
    if unmatched_patterns:
        print("Unmatched Patterns:")
        for item in unmatched_patterns:
            print("     [-]" + item)
    '''

    return matched_rules, unmatched_rules




def genScanSummaryText(file_path):
    """
    Generates a summary report from JSON scan data and writes it to a text file.

    This routine reads the specified JSON file, extracts relevant input and detection 
    summary information, and formats it for output to a summary text file.

    Parameters:
        file_path (str): Path to the JSON file containing scan data.

    Returns:
        None: The function writes the summary directly to a specified output file.
    """

    def format_file_extensions(file_extensions_dict):
        formatted_file_extensions = ""
        for language, extensions in file_extensions_dict.items():
            formatted_file_extensions += f"{language}: {', '.join(extensions)}\n"
        return formatted_file_extensions

    def format_key_value(key, value, indent_level=0, is_sub_key=False):
        indent = "    " * indent_level
        prefix = "[-] " if is_sub_key else "[+] "
        return f"{indent}{prefix}{key}: {value}\n"

    with open(file_path, 'r') as file:
        json_data = json.load(file)

    output = ""

    # Inputs Received
    inputs_received = json_data.get('inputs_received', {})
    output += "[+] Inputs Selected:\n"
    output += format_key_value("Target Directory", inputs_received.get('target_directory'), indent_level=1, is_sub_key=True)
    output += format_key_value("Rule Selected", inputs_received.get('rule_selected'), indent_level=1, is_sub_key=True)
    output += format_key_value("Total Rules Loaded", inputs_received.get('total_rules_loaded'), indent_level=1, is_sub_key=True)
    output += format_key_value("Platform Specific Rules", inputs_received.get('platform_specific_rules'), indent_level=2, is_sub_key=True)
    output += format_key_value("Common Rules", inputs_received.get('common_rules'), indent_level=2, is_sub_key=True)
    output += format_key_value("File Types Selected", inputs_received.get('filetypes_selected'), indent_level=1, is_sub_key=True)

    # Detection Summary
    detection_summary = json_data.get('detection_summary', {})
    output += "[+] Detection Summary:\n"
    output += format_key_value("Total Project Files Identified", detection_summary.get('total_project_files_identified'), indent_level=1, is_sub_key=True)
    output += format_key_value("Total Files Identified (Based on Selected Rule)", detection_summary.get('total_files_identified'), indent_level=1, is_sub_key=True)
    output += format_key_value("Total Files Scanned (Based on Selected Rule)", detection_summary.get('total_files_scanned'), indent_level=1, is_sub_key=True)

    # Format File Extensions Identified
    file_extensions_identified = detection_summary.get('file_extensions_identified')
    if file_extensions_identified:
        output += "    [-] File Extensions Identified (Based on Selected Rule):\n"
        for platform, extensions in file_extensions_identified.items():
            formatted_extensions = ', '.join(extensions)
            output += f"        {platform}: [{formatted_extensions}]\n"
    
    output += format_key_value("Code Files - Areas-of-Interests (Rules Matched)", detection_summary.get('areas_of_interest_identified'), indent_level=1, is_sub_key=True)
    output += format_key_value("File Paths - Areas-of-Interests (Rules Matched)", detection_summary.get('file_paths_areas_of_interest_identified'), indent_level=1, is_sub_key=True)
    output += "\n"

    # Scanning Timeline
    scanning_timeline = json_data.get('scanning_timeline', {})
    output += "[+] Scanning Timeline:\n"
    output += format_key_value("Scan start time", scanning_timeline.get('scan_start_time'), indent_level=1, is_sub_key=True)
    output += format_key_value("Scan end time", scanning_timeline.get('scan_end_time'), indent_level=1, is_sub_key=True)
    output += format_key_value("Scan completed in", scanning_timeline.get('scan_duration'), indent_level=1, is_sub_key=True)

    with open(runtime.outputSummary, 'w') as file:
        file.write(output)

