# Standard libraries
import argparse
import os
import re
import sys
import time
from datetime import datetime
from os import path  # This lowercase path to be used only to validate whether a directory exists
from pathlib import Path  # Resolve the Windows / macOS / Linux path issue

# Local application imports
import core.discovery as discover
import core.estimator as estimate
import core.parser as parser
import core.recon as rec
import core.reports as report

import state.constants as constants
import state.runtime_state as state

import utils.cli_utils as cli
import utils.config_utils as cutils
import utils.file_utils as futils
import utils.result_utils as result
import utils.rules_utils as rutils
import utils.string_utils as strutils
from utils.cli_utils import spinner
from utils.config_utils import get_tool_version


version = get_tool_version()

# ---- Initilisation ----- 
# Current directory of the python file
root_dir = os.path.dirname(os.path.realpath(__file__))
state.root_dir = root_dir         # initialise global root directory which is referenced at multiple locations

futils.dirCleanup("runtime")
futils.dirCleanup("runtime/platform")
futils.dirCleanup("reports/html")
futils.dirCleanup("reports/text")
futils.dirCleanup("reports/pdf")
# ------------------------- #

args = argparse.ArgumentParser()

args.add_argument('-r', type=str, action='store', dest='rule_file', required=False,
                  help='Specify platform-specific rule name')

args.add_argument('-f', type=str, action='store', dest='file_types', required=False,
                  help='Specify file types to scan')

args.add_argument('-v', action='count', dest='verbosity', default=0,
                  help="Specify verbosity level {'-v', '-vv', '-vvv'}")

args.add_argument('-t', type=str, action='store', dest='target_dir', required=False,
                  help='Specify target directory path')

args.add_argument('-l', '--list', type=str, action='store', dest='rules_filetypes',
                  required=False, choices=['R', 'RF'],
                  help='List rules [R] OR rules and filetypes [RF]')

args.add_argument('-recon', action='store_true', dest='recon',
                  help="Detect platform, framework, and programming language used")

args.add_argument('-estimate', action='store_true', dest='estimate',
                  help="Estimate efforts required for code review")

args.add_argument('-rpt', '--report', type=str, action='store', dest='report_format',
                  default='html,pdf',
                  help="Report types to generate: html, pdf, or html,pdf (default: html,pdf)")



# Parse arguments with error handling

try:
    results = args.parse_args()
except argparse.ArgumentError as e:
    print("\nError: Invalid option provided.")
    #args.print_help()
    cli.toolUsage('invalid_option')
    sys.exit(1)


# Display help if no arguments are passed
if not results or len(sys.argv) < 2:
    #args.print_help()
    cli.toolUsage('invalid_option')
    sys.exit(1)

# Preserve original rule argument for display/logging purposes
original_rule_file = results.rule_file

'''
# If '-r auto' is passed, resolve it into supported rule types
if original_rule_file and original_rule_file.lower() == "auto":
    #resolved_rule_list = rutils.getAvailableRules(exclude=["common"])
    detected = discover.autoDetectRuleTypes(results.target_dir)
    results.rule_file = detected
    results.file_types = detected
    #print(f"    [DEBUG] Target Dir: {str(results.target_dir)}")
    #print(f"    [DEBUG] Detected File Types: {str(detected)}")
'''

# Remove duplicates in rule_file and file_types
results.rule_file = strutils.remove_duplicates(results.rule_file)
results.file_types = strutils.remove_duplicates(results.file_types)

# If rule_file is present but file_types is empty, inherit rule_file value
if results.rule_file and not results.file_types:
    results.file_types = results.rule_file.lower()


elif results.recon:

    if not results.target_dir:
        print("You must specify the target directory using -t option.\n")
        sys.exit(1)

elif results.rules_filetypes != None:       
    rutils.listRulesFiletypes(results.rules_filetypes)    # List available rules and/or supported filetypes
    sys.exit(1)


# Priority #1 - If '-recon' option used but no rule file is specified then only recon must be performed
if (results.recon or results.estimate) and results.target_dir and not results.rule_file:
    #print(constants.author)
    print(constants.AUTHOR_BANNER.format(version=version))

    # Check if the directory path is valid
    if path.isdir(results.target_dir) == False: 
        print("\nInvalid target directory :" + results.target_dir + "\n")
        #args.print_usage()
        cli.toolUsage("invalid_dir")
        sys.exit(1)
    else:
        targetdir = results.target_dir
        
        # Perform recon and/or estimate based on the options used
        if results.recon and not results.estimate:
            log_filepaths, _ = rec.recon(targetdir, False)
            sys.exit(1)
        elif results.estimate and not results.recon:
            log_filepaths, recSummary = rec.recon(targetdir, False)
            estimate.effortEstimator(recSummary)
            sys.exit(1)
        else:  # If both '-recon' and '-estimate' options are used
            log_filepaths, recSummary = rec.recon(targetdir, False)
            estimate.effortEstimator(recSummary) 
            sys.exit(1)

# Priority #2 - Check if '-r' (rule type) is set
elif results.rule_file:

    if not results.file_types:        # If filetypes is not specified then default to platform specific filetypes
        results.file_types = results.rule_file.lower()              # Set filetypes as the rules option specified
    
    if not results.target_dir:
        print("You must specify the target directory using -t option")
        sys.exit(1)

    # Determine what to display for inputs
    display_rule_file = "auto" if original_rule_file and original_rule_file.lower() == "auto" else results.rule_file.lower()
    display_file_types = "auto" if original_rule_file and original_rule_file.lower() == "auto" else results.file_types.lower()

    if results.file_types and results.rule_file and results.target_dir:
        print(constants.AUTHOR_BANNER.format(version=version))

        cli.section_print(f"[*] Inputs & Rule Selection")
        print(f"     [-] Rule Selected        : {display_rule_file!r}")
        print(f"     [-] File Types Selected  : {display_file_types!r}")
        print(f"     [-] Target Directory     : {results.target_dir}")

        '''
        result.updateScanSummary("inputs_received.rule_selected", results.rule_file.lower())
        result.updateScanSummary("inputs_received.filetypes_selected", results.file_types.lower())
        '''
        result.updateScanSummary("inputs_received.rule_selected", display_rule_file)
        result.updateScanSummary("inputs_received.filetypes_selected", display_file_types)
        result.updateScanSummary("inputs_received.target_directory", results.target_dir)

        # Prompt the user to enter project name and subtitle
        project_name = input("     [-] Enter Project Name (e.g., XYZ Portal): ")
        project_subtitle = input("     [-] Enter Project Subtitle (e.g., v1.0.1 / XYZ Corp): ")
        cutils.updateProjectConfig(project_name,project_subtitle)     # Update project details

    if str(results.verbosity) in ('1', '2', '3'):
        state.verbosity = results.verbosity
        print(f"     [-] Verbosity Level      : {results.verbosity}")
    else:
        print(f"     [-] Verbosity Level      : Default [1]")


# Check if the directory path is valid
if path.isdir(results.target_dir) == False: 
    print("\nInvalid target directory :" + results.target_dir + "\n")
    #args.print_usage()
    cli.toolUsage("invalid_dir")
    sys.exit(1)

# Add the trailing slash ('/' or '\') to the path if missing. This is required to treat it as a directory.
project_dir = os.path.join(results.target_dir, '')

# The regex matches the last trailing slash ('/' or '\') and then reverse search until the next trailing slash is found
state.sourcedir = re.search(r'((?!\/|\\).)*(\/|\\)$', project_dir)[0]        # Target Source Code Directory

# utils.dirCleanup("runtime")    

# Current directory of the python file
root_dir = os.path.dirname(os.path.realpath(__file__))
state.root_dir = root_dir

# If '-r auto' is passed, resolve it into supported rule types
if original_rule_file and original_rule_file.lower() == "auto":
    #cli.section_print(f"[*] Auto-detecting applicable platform types...")
    print("     [-] Auto-detecting applicable platform types... ", end="", flush=True)
    spinner("start")

    detected = discover.autoDetectRuleTypes(results.target_dir)
    results.rule_file = detected
    results.file_types = detected
    spinner("stop")

    print(f"     [-] Detected Platform(s) : {detected}")

# List of file types to enumerate before scanning using rules
codebase = results.file_types

# Store rule name and corresponding full path in a dictionary

# Verify if the rule name(s) are valid
rule_files = {}
for rule_name in results.rule_file.split(','):
    rule_paths = rutils.getRulesPath_OR_FileTypes(rule_name.strip(), "rules")
    
    if not rule_paths:
        print("\nError: Invalid rule name or no path found:", rule_name.strip())
        sys.exit()
    else:
        # Construct full path and store it in the dictionary under the rule name
        full_path = Path(str(state.rulesRootDir) + rule_paths)  # Use the entire string
        rule_files[rule_name.strip()] = full_path

rules_main = rule_files     # Assign the rule files dictionary to rules main which will be later used in the program

# Initialize lists for storing rule paths and counts with platform names
rule_paths_str = []     # Collect rule paths as strings (for logging/debugging)
rule_counts = []        # Collect rule counts (for JSON update)
platform_rules_list = []  # List to store formatted platform specific rules with counts

# Iterate through the rules and collect paths + counts
for rule_name, rule_path in rules_main.items():
    #print(f"    [DEBUG] Rule Name: {rule_name}")
    #print(f"    [DEBUG] Path: {Path(str(rule_path))}")
    
    # Add rule path to the list for logging purposes
    rule_paths_str.append(str(rule_path))
    
    # Get the count of rules for this path
    count = rutils.rulesCount(Path(str(rule_path)))
    rule_counts.append(str(count))  # Store as string for easy joining

    # Format each platform with its rule count and add to the list
    platform_rules_list.append(f"{rule_name}[{count}]")

# Join all rule paths and counts as comma-separated strings
platform_rules_paths = ", ".join(rule_paths_str)  # Optional for logging if needed
#platform_rules_total = ", ".join(rule_counts)
platform_rules_total = ", ".join(platform_rules_list)  # Now in the format "php [32], cpp [25], java [26]"

# Handle common rules and their count
rules_common = Path(str(state.rulesRootDir) + rutils.getRulesPath_OR_FileTypes("common", "rules"))
common_rules_total = rutils.rulesCount(rules_common)

# Total loaded rules (platform + common)
total_rules_loaded = sum(map(int, rule_counts)) + common_rules_total

cli.section_print(f"[*] Rules Loaded")
print(f"     [-] Platform Rules       : {platform_rules_total}")
print(f"     [-] Common Rules         : {common_rules_total}")
print(f"     [-] Total Rules Loaded   : {total_rules_loaded}")

# Update Scan Summary JSON file - Loaded rules count
result.updateScanSummary("inputs_received.platform_specific_rules", platform_rules_total)
result.updateScanSummary("inputs_received.common_rules", str(common_rules_total))
result.updateScanSummary("inputs_received.total_rules_loaded", str(total_rules_loaded))

# Source Code Dirctory Path
sourcepath = Path(results.target_dir)

state.start_time = time.time()  # This time will be used to calculate total time taken for the scan
state.start_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

sCnt = 0    # Stage counter
cli.section_print("[*] Scanner Initiated")

###### [Stage #] File Path Discovery ######
sCnt+=1
if results.recon:
        cli.section_print(f"[*] [Stage {sCnt}] Reconnaissance (a.k.a Software Composition Analysis)")         # Stage 1
        targetdir = results.target_dir
        rec.recon(targetdir, True)

        sCnt+=1
        cli.section_print(f"[*] [Stage {sCnt}] File Path Discovery")    # Stage 2
        master_file_paths, platform_file_paths = discover.discoverFiles(codebase, sourcepath, 1)
else: 
    cli.section_print(f"[*] [Stage {sCnt}] File Path Discovery")        # Stage 1
    master_file_paths, platform_file_paths = discover.discoverFiles(codebase, sourcepath, 1)


###### [Stage 2 or 3] Rules, or Pattern Matching & Analysis - Parse Source Code ######
sCnt+=1
cli.section_print(f"[*] [Stage {sCnt}] Pattern Matching & Analysis")

# Ensure the directory structure exists. If it doesn't then create necessary directory structure.
output_directory = os.path.dirname(state.outputAoI)
os.makedirs(output_directory, exist_ok=True)

source_matched_rules = []
source_unmatched_rules = []

with open(state.outputAoI, "w") as f_scanout:
    
    # Only run platform-specific rules if the rule file is NOT 'common'
    if results.rule_file.lower() not in ['common']:
        # Iterate through each platform in the rules_main dictionary
        for index, (platform, rules_main_path) in enumerate(rules_main.items()):
            # Ensure the index matches the file path list
            if index < len(platform_file_paths):
                platform_file_path = platform_file_paths[index]

                print(f"\033[92m     --> Applying rules for {platform} \033[0m")
                
                # Debug print statement to check what is passed to sourceParser
                # print(f"[DEBUG] Platform: {platform}, Rules Path: {rules_main_path}, File Path: {platform_file_path}")

                with open(platform_file_path, 'r', encoding=futils.detectEncodingType(platform_file_path)) as f_targetfiles:
                    # Call sourceParser for each platform's rules
                    matched, unmatched = parser.sourceParser(rules_main_path, f_targetfiles, f_scanout)

                    # Store individual platform results
                    source_matched_rules.extend(matched)
                    source_unmatched_rules.extend(unmatched)

                    # Reset target file pointer after each pass to allow re-reading
                    f_targetfiles.seek(0)

    # Apply common (platform-independent) rules
    print("\033[92m     --> Applying common (platform-independent) rules \033[0m")
    with open(master_file_paths, 'r', encoding=futils.detectEncodingType(master_file_paths)) as f_targetfiles:
        common_matched_rules, common_unmatched_rules = parser.sourceParser(rules_common, f_targetfiles, f_scanout)

    # Aggregate common rule results with platform-specific results (if any)
    source_matched_rules.extend(common_matched_rules)
    source_unmatched_rules.extend(common_unmatched_rules)

    print("\033[92m     --- Pattern Matching Summary ---\033[0m")

# Update the scan summary JSON file with the aggregated matched and unmatched patterns
result.updateScanSummary("source_files_scanning_summary.matched_rules", source_matched_rules)
result.updateScanSummary("source_files_scanning_summary.unmatched_rules", source_unmatched_rules)


print("     [-] Total Files Scanned:", str(state.totalFilesIdentified - state.parseErrorCnt))
result.updateScanSummary("detection_summary.total_files_scanned", str(state.totalFilesIdentified - state.parseErrorCnt))
result.updateScanSummary("detection_summary.areas_of_interest_identified", str(state.rulesMatchCnt))

print("     [-] Total matched rules:", len(source_matched_rules))
print("     [-] Total unmatched rules:", len(source_unmatched_rules))

###### [Stage 3 or 4] Parse File Paths for areas of interest ######
sCnt+=1
cli.section_print(f"[*] [Stage {sCnt}] Identifying Areas of Interest")

with open(state.outputAoI_Fpaths, "w") as f_scanout:
    with open(master_file_paths, 'r', encoding=futils.detectEncodingType(master_file_paths)) as f_targetfiles:
        rule_no = 1
        matched_rules, unmatched_rules = parser.pathsParser(state.rulesFpaths, f_targetfiles, f_scanout, rule_no)
    
    print("     [-] Total matched rules:", len(matched_rules))
    print("     [-] Total unmatched rules:", len(unmatched_rules))

    # Update the scan summary JSON file with the matched and unmatched patterns
    result.updateScanSummary("paths_scanning_summary.matched_rules", matched_rules)
    result.updateScanSummary("paths_scanning_summary.unmatched_rules", unmatched_rules)


result.updateScanSummary("detection_summary.file_paths_areas_of_interest_identified", str(state.rulesPathsMatchCnt))

futils.cleanFilePaths(master_file_paths)
os.unlink(master_file_paths)        # Delete the temp file paths log after the path cleanup in the above step

cli.section_print(f"[*] Scanning Timeline")
print("    [-] Scan start time     : " + str(state.start_timestamp))
end_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print("    [-] Scan end time       : " + str(end_timestamp))

hours, rem = divmod(time.time() - state.start_time, 3600)
minutes, seconds = divmod(rem, 60)
seconds, milliseconds = str(seconds).split('.')
scan_duration = "{:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), seconds, milliseconds[:3])
print(f"    [-] Scan completed in   : {scan_duration}")

# Update Scan Summary JSON file - Timeline
result.updateScanSummary("scanning_timeline.scan_start_time", state.start_timestamp)
result.updateScanSummary("scanning_timeline.scan_end_time",  end_timestamp)
result.updateScanSummary("scanning_timeline.scan_duration", scan_duration)

# Parse the JSON Summary file and write output to a text file
parser.genScanSummaryText(state.scanSummary_Fpath)



###### [Stage 4] Generate Reports ######
#report.genReport()
valid_formats = {"html", "pdf"}
requested_formats = results.report_format.lower().replace(" ", "").split(",")
selected_formats = [fmt for fmt in requested_formats if fmt in valid_formats]

if selected_formats:
    report.genReport(formats=",".join(selected_formats))
else:
    print("[!] No valid report format selected. Defaulting to 'html,pdf'.")
    report.genReport(formats="html,pdf")

cutils.updateProjectConfig("","")     # Clean up project details in the config file

