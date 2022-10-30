from datetime import datetime
import time, os
from pathlib import Path    # Resolve the windows / mac / linux path issue

start_time = time.time()  # This time will be used to calculate total time taken for the scan
start_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Program root directory -> Set the directory path to where 'dakshscra.py' is located
root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + '/../../')      # Current file directory + relative path to 'dakshscra.py' directory

sourcedir = ''       # To be used for storing project directory name

verbosity = '1'

## ----------- Initialize - File Paths ----------- ##
# Directory path to platform specific rules
# rulesRootDir = Path(os.path.abspath('') + "/rules/scanning/platform")
rulesRootDir = Path(str(root_dir) + "/rules/scanning/platform")

# Rules config path
rulesConfig = Path(str(rulesRootDir) + "/../rulesconfig.xml")

# Files path scanning rules
rulesFpaths = Path(str(rulesRootDir) + "/filepaths.xml")


## ------------- <Runtime Temp Files> ------------- ##
# Log File paths
discovered_Fpaths = Path(str(root_dir) + "/runtime/filepaths.log")

# Logs File paths
inventory_Fpathext = Path(str(root_dir) + "/runtime/inventory.json")
## ------------- </Runtime Temp Files> ------------- ##


## ------------- <Reports> ------------- ##
# Output file - areas of interest
outputAoI = Path(str(root_dir) + "/report/text/areas_of_interest.txt")
outputAoI_Fpaths = Path(str(root_dir) + "/report/text/filepaths_aoi.txt")       # Filepaths - Areas of Interests

# HTML Report file path
htmlreport_Fpath = Path(str(root_dir) + "/report/html/report.html")

# HTML Report template path
htmltemplates_dir  = Path(str(root_dir) + "/resources/templates/")
## ------------- </Reports> ------------- ##





## ----------- Banners | Credits | Console Output Decoration ----------- ##

author = '''
=============================================================
Daksh SCRA (Source Code Review Assist) - Beta Release v0.2

Author:     Debasis Mohanty 
            www.coffeeandsecurity.com
            Twitter: @coffensecurity
            Email: d3basis.m0hanty@gmail.com
============================================================='''

