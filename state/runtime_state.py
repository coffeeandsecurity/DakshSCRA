# Standard libraries
import os
import time
from datetime import datetime
from pathlib import Path  # Resolve the Windows / macOS / Linux path issue


start_time = time.time()  # This time will be used to calculate total time taken for the scan
start_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Program root directory -> Set the directory path to where 'dakshscra.py' is located
root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + '/../')      # Current file directory + relative path to 'dakshscra.py' directory


def _resolve_output_root(env_name, default_relative_dir):
    configured = os.environ.get(env_name, "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(str(root_dir) + f"/{default_relative_dir}")

sourcedir = ''       # To be used for storing project directory name

verbosity = '1'

rCnt = 0    # Counter to keep track of matched rules

## ----------- Initialize - File Paths ----------- ##
# Directory path to platform specific rules
# rulesRootDir = Path(os.path.abspath('') + "/rules/scanning/platform")
rulesRootDir = Path(str(root_dir) + "/rules/scanning/platform")

# Rules config path
rulesConfig = Path(str(rulesRootDir) + "/../rulesconfig.xml")
# Framework registry config path
frameworkConfig = Path(str(rulesRootDir) + "/../frameworkconfig.xml")

# Tool details/version config file
toolConfig = Path(str(root_dir) + "/config/tool.yaml")

# Project config path
projectConfig = Path(str(root_dir) + "/config/project.yaml")

# Suppression baseline config
suppressionBaseline = Path(str(root_dir) + "/config/suppressions.json")

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
suppressedFindingsCnt = 0
## ------------- </Counters> ------------- ##

# Runtime suppression entries loaded from baseline file
suppressions = []


## ------------- <Temp Files> ------------- ##
# Runtime/report roots can be overridden for isolated runs (for example web UI jobs).
runtime_base_dir = _resolve_output_root("DAKSH_RUNTIME_DIR", "runtime")
reports_base_dir = _resolve_output_root("DAKSH_REPORTS_DIR", "reports")

# Log File paths
runtime_dirpath = runtime_base_dir
reports_dirpath = reports_base_dir
discovered_Fpaths = runtime_dirpath / "filepaths.log"
discovered_clean_Fpaths = runtime_dirpath / "filepaths.txt"

# Logs File paths
inventory_Fpathext = runtime_dirpath / "inventory.json"

# Specify the filename of the JSON file
scanSummary_Fpath = runtime_dirpath / "scan_summary.json"
## ------------- </Temp Files> ------------- ##


## ------------- <Recon> ------------- ##
technologies_Fpath = Path(str(root_dir) + "/rules/recon/technology.json")
framework_Fpath = Path(str(root_dir) + "/rules/recon/frameworks.json")

reconOutput_Fpath = runtime_dirpath / "recon.json"
reconSummary_Fpath = runtime_dirpath / "recon_summary.json"
## ------------- </Recon> ------------- ##


## ------------- <Reports> ------------- ##

# Output file - areas of interest (JSON)
outputAoI_JSON = reports_dirpath / "data" / "areas_of_interest.json"

# Filepaths - Areas of Interests
outputAoI_Fpaths_JSON = reports_dirpath / "data" / "filepaths_aoi.json"

# FilePaths - Runtime
output_Fpaths_JSON = runtime_dirpath / "filepaths.json"

# Output file - summary
outputSummary_JSON = reports_dirpath / "data" / "summary.json"

# Output file - Recon summary
outputRecSummary_JSON = reports_dirpath / "data" / "recon.json"

# Backward-compatible alias used by legacy recon code paths
outputRecSummary = outputRecSummary_JSON

# Output file - Analyzer summary
outputAnalysis_JSON = reports_dirpath / "data" / "analysis.json"

# PDF Report file path
pdfreport_Fpath = reports_dirpath / "scan" / "pdf" / "report.pdf"

# HTML Report file path
htmlreport_Fpath = reports_dirpath / "scan" / "html" / "report.html"

# HTML Report template path
htmltemplates_dir  = Path(str(root_dir) + "/resources/templates/")

# Effort estimation - Report template
estimation_template = Path(str(root_dir) + "/resources/templates/estimate.html")

# Effort estimation - HTML Report file path
estimation_Fpath = reports_dirpath / "scan" / "estimate" / "estimation.html"

# Reconnaissance - HTML Report file path
reconreport_Fpath = reports_dirpath / "scan" / "recon" / "reconnaissance.html"

## ------------- </Reports> ------------- ##
