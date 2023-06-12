import os
import re
import sys
import argparse
import time
from datetime import datetime
from pathlib import Path        # Resolve the windows / mac / linux path issue
from os import path             # This lowercase path to be used only to validate whether a directory exist

import modules.misclib as mlib
import modules.reports as report
import modules.parser as parser
import modules.recon as rec
import modules.runtime as runtime
import modules.rulesops as rops

# ---- Initilisation ----- 
# Current directory of the python file
root_dir = os.path.dirname(os.path.realpath(__file__))
runtime.root_dir = root_dir         # initialise global root directory which is referenced at multiple locations

mlib.dirCleanup("runtime")
mlib.dirCleanup("reports/html")
#mlib.dirCleanup("reports/text")
mlib.dirCleanup("reports/pdf")
# ------------------------- #

args = argparse.ArgumentParser()

args.add_argument('-r', type=str, action='store', dest='rule_file', required=False, help='Specify platform specific rule name')
args.add_argument('-f', type=str, action='store', dest='file_types', required=False, help='Specify file types to scan')
args.add_argument('-v', action='count', dest='verbosity', default=0, help="specify verbosity level {'-v', '-vv'}")
args.add_argument('-t', type=str, action='store', dest='target_dir', required=False, help='Specify target directory path')
args.add_argument('-l', '--list', type=str, action='store', dest='rules_filetypes', required=False, choices=['R','RF'], help='List rules [R] OR rules and filetypes [RF]')
args.add_argument('-recon', action='store_true', dest='recon', help="platform and technology reconnaissance")


results = args.parse_args(args=None if sys.argv[1:] else ['--help'])    # Display help if no argument is passed


if len(sys.argv) < 2:
    args.print_help()
    #args.print_usage(description="Required arguments")
    print("\nExample: python dakshsca.py -r dotnet -t /path_to_source_dir")
    print("Example: python dakshsca.py -r dotnet -f dotnet -t /path_to_source_dir\n")
    print("To specify the verbosity level, set -v [1,2]\n")
    print("Example: python dakshsca.py -r dotnet -f dotnet -v 2 -t /path_to_source_dir\n")
    
    sys.exit(1)

elif results.recon:

    if not results.target_dir:
        print("You must specify the target directory using -t option.\n")
        sys.exit(1)

elif results.rules_filetypes != None:       
    rops.listRulesFiletypes(results.rules_filetypes)    # List available rules and/or supported filetypes
    sys.exit(1)

# Priority #1 - If '-recon' option used then only recon must be performed
if results.recon and results.target_dir:
    print(runtime.author)
    # Check if the directory path is valid
    if path.isdir(results.target_dir) == False: 
        print("\nInvalid target directory :" + results.target_dir + "\n")
        args.print_usage()
        print("\nExample: python dakshsca.py -r dotnet -t /path_to_source_dir")
        print("Example: python dakshsca.py -r dotnet -f dotnet -t /path_to_source_dir\n")
        sys.exit(1)
    else:
        targetdir = results.target_dir
        # log_filepaths = mlib.discoverFiles('*.*', targetdir, 2)     # mode = 2 - Software Recon
        #log_filepaths = parser.recon(targetdir)
        log_filepaths = rec.recon(targetdir)
        sys.exit(1)

# Priority #2 - Check if '-r' (rule type) is set
elif results.rule_file:

    if not results.file_types:        # If filetypes is not specified then default to platform specific filetypes
        results.file_types = results.rule_file.lower()              # Set filetypes as the rules option specified
    
    if not results.target_dir:
        print("You must specify the target directory using -t option")
        sys.exit(1)

    if results.file_types and results.rule_file and results.target_dir:
        print(runtime.author)
        print("\nThe following inputs were received:")
        print(f'[*] Rule Selected        = {results.rule_file.lower()!r}')
        print(f'[*] File Types Selected  = {results.file_types.lower()!r}')
        print(f'[*] Target Directory     = {results.target_dir}')

        mlib.updateScanSummary("inputs_received.rule_selected", results.rule_file.lower())
        mlib.updateScanSummary("inputs_received.filetypes_selected", results.file_types.lower())
        mlib.updateScanSummary("inputs_received.target_directory", results.target_dir)

    if str(results.verbosity) in ('1', '2'):
        runtime.verbosity = results.verbosity
        print(f'[*] Verbosity Level    = {results.verbosity}')
    else:
        print('[*] Default Verbosity Level [1] Set')


# Check if the directory path is valid
if path.isdir(results.target_dir) == False: 
    print("\nInvalid target directory :" + results.target_dir + "\n")
    args.print_usage()
    print("\nExample: python dakshsca.py -r dotnet -t /path_to_source_dir")
    print("Example: python dakshsca.py -r dotnet -f dotnet -t /path_to_source_dir\n")
    sys.exit(1)

# Add the trailing slash ('/' or '\') to the path if missing. This is required to treat it as a directory.
project_dir = os.path.join(results.target_dir, '')

# The regex matches the last trailing slash ('/' or '\') and then reverse search until the next trailing slash is found
runtime.sourcedir = re.search(r'((?!\/|\\).)*(\/|\\)$', project_dir)[0]        # Target Source Code Directory

# mlib.dirCleanup("runtime")    

# Current directory of the python file
root_dir = os.path.dirname(os.path.realpath(__file__))
runtime.root_dir = root_dir

# codebase = 'allfiles'  # This is the list of file types to enumerate before scanning using rules
codebase = results.file_types

# Verify if the rule name is valid
if not (rules_main := rops.getRulesPath_OR_FileTypes(results.rule_file, "rules")):
    print("\nError: Invalid rule name!")
    sys.exit()
else:
    rules_main = Path(str(runtime.rulesRootDir) + rules_main)


rules_common = Path(str(runtime.rulesRootDir) + rops.getRulesPath_OR_FileTypes("common", "rules"))

platform_rules_total = rops.rulesCount(rules_main)
common_rules_total = rops.rulesCount(rules_common)
total_rules_loaded = rops.rulesCount(rules_main) + rops.rulesCount(rules_common) 

print(f"[*] Total {results.rule_file.lower()} rules loaded: {platform_rules_total}")
print(f"[*] Total common rules loaded: {common_rules_total}")

# Update Scan Summary JSON file - Loaded rules count
mlib.updateScanSummary("inputs_received.platform_specific_rules", str(platform_rules_total))
mlib.updateScanSummary("inputs_received.common_rules", str(common_rules_total))
mlib.updateScanSummary("inputs_received.total_rules_loaded", str(total_rules_loaded))


# Source Code Dirctory Path
sourcepath = Path(results.target_dir)

runtime.start_time = time.time()  # This time will be used to calculate total time taken for the scan
runtime.start_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

print("[*] Scanner initiated!!")

###### [Stage 1] Discover file paths    ######
print("[+] [Stage 1] Discover file paths")
log_filepaths = mlib.discoverFiles(codebase, sourcepath, 1)

###### [Stage 2] Rules/Pattern Matching - Parse Source Code ######
print("[+] [Stage 2] Rules/Pattern Matching - Parsing identified project files")

with open(runtime.outputAoI, "w") as f_scanout:
    with open(log_filepaths, 'r', encoding=mlib.detectEncodingType(log_filepaths)) as f_targetfiles:
        rule_no = 1
        parser.sourceParser(rules_main, f_targetfiles, f_scanout, rule_no)   # Pattern matching for specific platform type
        parser.sourceParser(rules_common, f_targetfiles, f_scanout, rule_no)  # Pattern matching for common rules


###### [Stage 3] Parse File Paths for areas of interest ######
print("[+] [Stage 3] Parsing file paths for areas of interest")

with open(runtime.outputAoI_Fpaths, "w") as f_scanout:
    with open(log_filepaths, 'r', encoding=mlib.detectEncodingType(log_filepaths)) as f_targetfiles:
        rule_no = 1
        parser.pathsParser(runtime.rulesFpaths, f_targetfiles, f_scanout, rule_no)


mlib.cleanFilePaths(log_filepaths)
os.unlink(log_filepaths)        # Delete the temp file paths log after the path cleanup in the above step

print("\n[*] Scanning Timeline")
print("    [-] Scan start time     : " + str(runtime.start_timestamp))
end_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print("    [-] Scan end time       : " + str(end_timestamp))
# print("Scan completed in " + str(format((time.time() - settings.start_time), '.2f')) + " seconds.")

hours, rem = divmod(time.time() - runtime.start_time, 3600)
minutes, seconds = divmod(rem, 60)
seconds, milliseconds = str(seconds).split('.')
print("    [-] Scan completed in   : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours),int(minutes),seconds, milliseconds[:3]))
scan_duration = "{:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), seconds, milliseconds[:3])
# print("    [-] Scan completed in   : " + time.strftime("%HHr:%MMin:%Ss", time.gmtime(time.time() - settings.start_time)))

# Update Scan Summary JSON file - Timeline
mlib.updateScanSummary("scanning_timeline.scan_start_time", runtime.start_timestamp)
mlib.updateScanSummary("scanning_timeline.scan_end_time",  end_timestamp)
mlib.updateScanSummary("scanning_timeline.scan_duration", scan_duration)

###### [Stage 4] Generate Reports ######
report.genReport()
