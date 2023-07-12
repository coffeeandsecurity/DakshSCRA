import re
import sys
import json
import ast
import xml.etree.ElementTree as ET
from timeit import default_timer as timer

import modules.runtime as runtime
import modules.misclib as mlib


'''
This routine will search patterns loaded from the XML file and parse through all source files.

The following parameters are expected: 
    rule_path   - Path to rule file (or rule file name)
    targetfile  - Target file containing enumerated filepaths withing the target source directory
    outputfile  - File for writing scan output
'''
def sourceParser(rule_path, targetfile, outputfile, rule_no):
    # Load rules from XML file
    xmltree = ET.parse(rule_path)
    root = xmltree.getroot()

    f_scanout = outputfile
    f_targetfiles = targetfile

    iCnt = 0
    rule_no = runtime.rCnt
    error_count = 0  # Counter for error occurrences
    unmatched_rules = []     # List to store unmatched patterns
    matched_rules = []       # List to store matched patterns


    for category in root:
        category_name = category.get('name')
        if category_name:
            print("     [-] Category: " + category_name)

            for rule in category:
                r = rule
                flag_title_desc = False
                
                # f_scanout.write(str(rule_no)+". Rule Title: " + r.find("name").text + "\n")
                rule_title = r.find("name").text
                pattern = r.find("regex").text

                rule_desc = r.find("rule_desc").text
                vuln_desc = r.find("vuln_desc").text
                dev_note = r.find("developer").text
                rev_note = r.find("reviewer").text

                if r.find('mitigation/regex'):
                    pattern = r.get('mitigation/regex')

                exclude = r.find("exclude").text if r.find("exclude") is not None else ""

                # stdout based on verbosity level set
                if str(runtime.verbosity) == '1' or str(runtime.verbosity) == '2':
                    #sys.stdout.write("\033[F")      # move the cursor up one line 
                    #sys.stdout.write("\033[K")     # clear line to prevent overlap of texts
                    print("         [-] Applying Rule: " + r.find("name").text, end='\r')
                else:
                    sys.stdout.write("\033[K")
                    print("         [-] Applying Rule: " + r.find("name").text)

                for eachfilepath in f_targetfiles:  # Read each line (file path) in the file
                    filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
                    
                    iCnt += 1

                    if str(runtime.verbosity) == '1':
                        if len(filepath) > 60:
                            print('\t Parsing file: ' + "["+str(iCnt)+"] "+ mlib.getShortPath(filepath), end='\r')
                        else:
                            print('\t Parsing file: ' + "["+str(iCnt)+"] "+ filepath, end='\r')
                    else:
                        print('\t Parsing file: ' + "["+str(iCnt)+"] "+ mlib.getSourceFilePath(runtime.sourcedir, filepath), end='\r')
                    
                    sys.stdout.write("\033[K")     # clear line to prevent overlap of texts
                    #sys.stdout.write("\033[F\033[K")  # move the cursor up one line and clear line to prevent overlap of texts

                    try:
                        # with open(filepath, 'r', encoding='utf8') as fo_target:
                        with open(filepath, 'r', encoding='ISO-8859-1') as fo_target:       # ISO-8859-1 encoding type works on most occasions including those where utf8 cause errors
                            linecount = 0
                            flag_fpath = False
                            for line in fo_target:
                                linecount += 1

                                if len(line) > 500:     # Setting maximum input length of the string read from the file
                                    continue  # Skip long lines
                                
                                if re.findall(pattern, line):
                                    if exclude and re.search(exclude, line, re.IGNORECASE):
                                        continue        # Skip current iteration if exclude rule matches
                            
                                    line = (line[:75] + '..') if len(line) > 300 else line
                                    
                                    if not flag_title_desc:
                                        if rule_no > 0:                 # This check ensures there is no new line before the first entry in the txt report
                                            f_scanout.write("\n\n")     # Insert new lines before the entry of each matched rule title 
                                        
                                        flag_title_desc = True
                                        rule_no += 1
                                        runtime.rulesMatchCnt += 1
                                        matched_rules.append(rule_title)  # Add matched rules to the list
                                        f_scanout.write(str(rule_no)+". Rule Title: " + rule_title + "\n")
                                        f_scanout.write(f"\n\t Rule Description  : {rule_desc}"
                                                                f"\n\t Issue Description : {vuln_desc}"
                                                                f"\n\t Developer Note    : {dev_note}"
                                                                f"\n\t Reviewer Note     : {rev_note} \n")

                                    if not flag_fpath:
                                        flag_fpath = True
                                        f_scanout.write("\n\t -> Source File: " + mlib.getSourceFilePath(runtime.sourcedir, filepath) + "\n")
                                        f_scanout.write("\t\t [" + str(linecount) + "]" + line)
                                    else:
                                        f_scanout.write("\t\t [" + str(linecount) + "]" + line)
                                
                        if rule_title not in matched_rules:
                            unmatched_rules.append(rule_title)

                    except OSError:
                        print("OS Error occurred!")
                        error_count += 1
                    except UnicodeError as err:
                        print("Error Occurred: ", err)
                        print(filepath)
                        error_count += 1
                
                #f_scanout.write("\n")
                f_targetfiles.seek(0)  # Reset the file pointer to the beginning

                runtime.rCnt = rule_no     
                iCnt = 0
                sys.stdout.write("\033[K")  # Clear line to prevent overlap of texts
        
            runtime.parseErrorCnt += error_count
            # Remove duplicates from matched_rules and unmatched_rules lists
            matched_rules = list(set(matched_rules))
            unmatched_rules = list(set(unmatched_rules))
    
    return matched_rules, unmatched_rules


'''
This routine will parse all enumerated file paths and match patterns to group them under matched category
'''
def pathsParser(rule_path, targetfile, outputfile, rule_no):
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
            filepath = mlib.getSourceFilePath(runtime.sourcedir, filepath)

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


# Generate scan summary output in text file
def genScanSummaryText(file_path):
    # Format file extensions in a well aligned colums when there are multiple file extensions
    def format_file_extensions(file_extensions_list):
        max_extensions_per_row = 4
        formatted_file_extensions = ""

        for i, ext in enumerate(file_extensions_list):
            formatted_file_extensions += ext
            if i < len(file_extensions_list) - 1:
                formatted_file_extensions += ", "
            if (i + 1) % max_extensions_per_row == 0:
                formatted_file_extensions += "\n" + " " * 32

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
    
    # Format File Extensions Selected
    file_extensions_selected = inputs_received.get('file_extensions_selected')
    if file_extensions_selected:
        file_extensions_selected_list = ast.literal_eval(file_extensions_selected)
        formatted_file_extensions_selected = format_file_extensions(file_extensions_selected_list)
        output += format_key_value("File Extensions Selected", formatted_file_extensions_selected, indent_level=1, is_sub_key=True)
    #output += format_key_value("File Extensions Selected", inputs_received.get('file_extensions_selected'), indent_level=1, is_sub_key=True)
    '''
    # Resolves the issue of two '\n' before the target directory
    output = output.rstrip()    # Remove trailing whitespace
    output += "\n"
    output += format_key_value("Target Directory", inputs_received.get('target_directory'), indent_level=1, is_sub_key=True)
    output += "\n"
    '''
    # Detection Summary
    detection_summary = json_data.get('detection_summary', {})
    output += "[+] Detection Summary:\n"
    output += format_key_value("Total Project Files Identified", detection_summary.get('total_project_files_identified'), indent_level=1, is_sub_key=True)
    output += format_key_value("Total Files Identified (Based on Selected Rule)", detection_summary.get('total_files_identified'), indent_level=1, is_sub_key=True)
    output += format_key_value("Total Files Scanned (Based on Selected Rule)", detection_summary.get('total_files_scanned'), indent_level=1, is_sub_key=True)
    
    # Format File Extensions Identified
    file_extensions_identified = detection_summary.get('file_extensions_identified')
    if file_extensions_identified:
        file_extensions_identified_list = ast.literal_eval(file_extensions_identified)
        formatted_file_extensions_identified = format_file_extensions(file_extensions_identified_list)
        output += format_key_value("File Extensions Identified (Based on Selected Rule)", formatted_file_extensions_identified, indent_level=1, is_sub_key=True)
    
    #output += format_key_value("File Extensions Identified (Based on Selected Rule)", detection_summary.get('file_extensions_identified'), indent_level=1, is_sub_key=True)
    
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


