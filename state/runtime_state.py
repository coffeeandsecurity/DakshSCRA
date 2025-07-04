# Standard libraries
import os
import time
from datetime import datetime
from pathlib import Path  # Resolve the Windows / macOS / Linux path issue


start_time = time.time()  # This time will be used to calculate total time taken for the scan
start_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Program root directory -> Set the directory path to where 'dakshscra.py' is located
root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + '/../')      # Current file directory + relative path to 'dakshscra.py' directory

sourcedir = ''       # To be used for storing project directory name

verbosity = '1'

rCnt = 0    # Counter to keep track of matched rules

## ----------- Initialize - File Paths ----------- ##
# Directory path to platform specific rules
# rulesRootDir = Path(os.path.abspath('') + "/rules/scanning/platform")
rulesRootDir = Path(str(root_dir) + "/rules/scanning/platform")

# Rules config path
rulesConfig = Path(str(rulesRootDir) + "/../rulesconfig.xml")

# Tool details/version config file
toolConfig = Path(str(root_dir) + "/config/tool.yaml")

# Project config path
projectConfig = Path(str(root_dir) + "/config/project.yaml")

# Estimation config path
estimateConfig = Path(str(root_dir) + "/config/estimate.yaml")

# Files path scanning rules
rulesFpaths = Path(str(rulesRootDir) + "/filepaths.xml")

# Static paths
staticPdfCssFpath = Path(str(root_dir) + "/resources/static/pdf.css")

# Logo
staticLogo = Path(str(root_dir) + "/resources/static/logo_for_report.jpg")

## ------------- <Counters> ------------- ##
totalFilesIdentified = 0
parseErrorCnt = 0           # Keep track of file parsing errors
rulesMatchCnt = 0
rulesPathsMatchCnt = 0
## ------------- </Counters> ------------- ##


## ------------- <Temp Files> ------------- ##
# Log File paths
runtime_dirpath = Path(str(root_dir) + "/runtime/")
discovered_Fpaths = Path(str(root_dir) + "/runtime/filepaths.log")
discovered_clean_Fpaths = Path(str(root_dir) + "/runtime/filepaths.txt")

# Logs File paths
inventory_Fpathext = Path(str(root_dir) + "/runtime/inventory.json")

# Specify the filename of the JSON file
scanSummary_Fpath = Path(str(root_dir) + "/runtime/scan_summary.json")
## ------------- </Temp Files> ------------- ##


## ------------- <Recon> ------------- ##
technologies_Fpath = Path(str(root_dir) + "/rules/recon/technology.json")
framework_Fpath = Path(str(root_dir) + "/rules/recon/frameworks.json")

reconOutput_Fpath = Path(str(root_dir) + "/runtime/recon.json")
reconSummary_Fpath = Path(str(root_dir) + "/runtime/recon_summary.json")
## ------------- </Recon> ------------- ##


## ------------- <Reports> ------------- ##

# Output file - areas of interest
outputAoI = Path(str(root_dir) + "/reports/text/areas_of_interest.txt")

# Filepaths - Areas of Interests
outputAoI_Fpaths = Path(str(root_dir) + "/reports/text/filepaths_aoi.txt")       

# FilePaths - Runtime
output_Fpaths = Path(str(root_dir) + "/runtime/filepaths.txt")   

# Output file - summary
outputSummary = Path(str(root_dir) + "/reports/text/summary.txt")

# Output file - Recon summary
outputRecSummary = Path(str(root_dir) + "/reports/text/recon.txt")

# PDF Report file path
pdfreport_Fpath = Path(str(root_dir) + "/reports/pdf/report.pdf")

# HTML Report file path
htmlreport_Fpath = Path(str(root_dir) + "/reports/html/report.html")

# HTML Report template path
htmltemplates_dir  = Path(str(root_dir) + "/resources/templates/")

# Effort estimation - Report template
estimation_template = Path(str(root_dir) + "/resources/templates/estimate.html")

# Effort estimation - HTML Report file path
estimation_Fpath = Path(str(root_dir) + "/reports/html/estimation.html")

## ------------- </Reports> ------------- ##



