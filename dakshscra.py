import os, re
# import shutil
import sys
import time
import argparse

from datetime import datetime
from os import path         # This lowercase path to be used only to validate whether a directory exist
from pathlib import Path    # Resolve the windows / mac / linux path issue

# User Defined Libraries / Functions
import modules.misclib as mlib
import modules.reports as report
import modules.parser as parser
import modules.recon as rec
import modules.settings as settings


# ---- Initilisation ----- 
# Current directory of the python file
rootDir = os.path.dirname(os.path.realpath(__file__))
settings.root_dir = rootDir         # initialise global root directory which is referenced at multiple locations

mlib.DirCleanup("runtime")
mlib.DirCleanup("report/html")
#mlib.DirCleanup("report/text")
mlib.DirCleanup("report/pdf")
# shutil.rmtree("report/text", ignore_errors=False, onerror=None)
# shutil.rmtree("report/text", ignore_errors=False, onerror=None)
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
    mlib.ListRulesFiletypes(results.rules_filetypes)    # List available rules and/or supported filetypes
    sys.exit(1)

# Priority #1 - If '-recon' option used then only recon must be performed
if results.recon and results.target_dir:
    print(settings.author)
    # Check if the directory path is valid
    if path.isdir(results.target_dir) == False: 
        print("\nInvalid target directory :" + results.target_dir + "\n")
        args.print_usage()
        print("\nExample: python dakshsca.py -r dotnet -t /path_to_source_dir")
        print("Example: python dakshsca.py -r dotnet -f dotnet -t /path_to_source_dir\n")
        sys.exit(1)
    else:
        targetdir = results.target_dir
        # log_filepaths = mlib.DiscoverFiles('*.*', targetdir, 2)     # mode = 2 - Software Recon
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
        print(settings.author)
        print("\nThe following inputs received:")
        print('[*] Rule Selected        = {!r}'.format(results.rule_file.lower()))
        print('[*] File Types Selected  = {!r}'.format(results.file_types.lower()))
        print('[*] Target Directory     = {!r}'.format(results.target_dir))

    if (str(results.verbosity) == '1') or (str(results.verbosity) == '2'):
        settings.verbosity = results.verbosity
        print('[*] Verbosity Level    = {!r}'.format(results.verbosity))
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
settings.sourcedir = re.search(r'((?!\/|\\).)*(\/|\\)$', project_dir)[0]        # Target Source Code Directory

# mlib.DirCleanup("runtime")    

# Current directory of the python file
rootDir = os.path.dirname(os.path.realpath(__file__))
settings.root_dir = rootDir

# codebase = 'allfiles'  # This is the list of file types to enumerate before scanning using rules
codebase = results.file_types

if (mlib.GetRulesPathORFileTypes(results.rule_file, "rules") == ''):
    print("\nError: Invalid rule name!")
    sys.exit()
else:
    rulefile = mlib.GetRulesPathORFileTypes(results.rule_file, "rules")
    rules_main = Path(str(settings.rulesRootDir) + rulefile)


rules_common = Path(str(settings.rulesRootDir) + mlib.GetRulesPathORFileTypes("common", "rules"))

# Source Code Dirctory Path
sourcepath = Path(results.target_dir)

settings.start_time = time.time()  # This time will be used to calculate total time taken for the scan
settings.start_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print("\n[*] Scan Start Time: " + str(settings.start_timestamp))

###### [Stage 1] Discover file paths    ######
log_filepaths = mlib.DiscoverFiles(codebase, sourcepath, 1)

###### [Stage 2] Rules/Pattern Matching - Parse Source Code ######
f_scanout = open(settings.outputAoI, "w")           # settings.outputAoI -> File path for areas of interest scan output
f_targetfiles = open(log_filepaths, encoding="utf8")

parser.SourceParser(rules_main, f_targetfiles, f_scanout)       # Pattern matching for specific platform type
parser.SourceParser(rules_common, f_targetfiles, f_scanout)     # Pattern matching for common rules

f_targetfiles.close()
f_scanout.close()

###### [Stage 3] Parse File Paths for areas of interest ######
f_scanout = open(settings.outputAoI_Fpaths, "w")        # settings.outputAoI_Fpaths -> Output file for areas of interest file paths scan output
f_targetfiles = open(log_filepaths, encoding="utf8")
parser.PathsParser(settings.rulesFpaths, f_targetfiles, f_scanout)
f_targetfiles.close()
f_scanout.close()

# Generate report
report.GenReport()

mlib.CleanFilePaths(log_filepaths)
os.unlink(log_filepaths)        # Delete the temp file paths log after the path cleanup in the above step

end_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print("\n[*] Scan End Time: " + str(end_timestamp))
# print("Scan completed in " + str(format((time.time() - settings.start_time), '.2f')) + " seconds.")
print("[*] Scan completed in " + time.strftime("%HHr:%MMin:%Ss", time.gmtime(time.time() - settings.start_time)))

