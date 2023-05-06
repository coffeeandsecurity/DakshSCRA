import os

from pathlib import Path

import modules.misclib as mlib
import modules.settings as settings

# Software composition analysis
def recon(targetdir):
    # WORK IN PROGRESS
    wip = """
    Note: This feature is still work in progress. 
    The purpose of this feature is to perform a software/application level reconnaisance 
    to identify various useful details related to the target project. The reconnaisance would 
    include multiple sub-features and one such feature is automated software composition analysis. 

    Steps:
        *  Enum all file paths
        *  Enum each file types and total identified number
        *  Identify Design Pattern
        *  Identify application type (Misc, COTS, Unknown, CMS, Mobile, APIs)
        *  Conditional Check to identify application type (Use XML/Dict to specify conditions)
        *  Identify Standard Libs and total number
        *  Intelligent Enum - ON / OFF
        *  Enum TLOC

    Options:
        *  Ignore paths based on path or keyword
        *  Ignore files based on extentions
        *  Effort estimation
    """
    #print(wip)

    print("\n--- Project reconnaissance ---")
    print("\n[*] Software Composition Analysis!!")
    if Path(settings.inventory_Fpathext).is_file():
        os.remove(settings.inventory_Fpathext)
    log_filepaths = mlib.DiscoverFiles('*.*', targetdir, 2)     # mode = 2 - Software Recon

    return log_filepaths