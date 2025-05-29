import sys, re
import html
import os
from re import search

try :
	from jinja2 import Environment, PackageLoader, FileSystemLoader, Template
except ImportError :
	sys.exit("[!] The Jinja2 module is not installed, please install it and try again")

from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter

from pygments_better_html import BetterHtmlFormatter
import traceback

from datetime import datetime, timedelta
from weasyprint import HTML, CSS
import time

import state.runtime_state as state
import yaml
import base64

from collections import defaultdict
import html
import re

import utils.cli_utils as cli


def genPdfReport(html_path, pdf_path):
    try:
        started_at = time.time()
        cli.section_print(f"[*] PDF Report Generation")

        print(f"    [-] Started at       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"    [-] Be patient! PDF report generation takes time.")
        

        HTML(html_path).write_pdf(pdf_path, stylesheets=[CSS(state.staticPdfCssFpath)])

        sys.stdout.write("\033[F") #back to previous line        
        sys.stdout.write("\033[K") #clear line to prevent overlap of texts
        print(f"    [-] Completed at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        hours, rem = divmod(time.time() - started_at, 3600)
        minutes, seconds = divmod(rem, 60)
        seconds, milliseconds = str(seconds).split('.')
        print("    [-] Total time taken : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours),int(minutes),seconds, milliseconds[:3]))

        return pdf_path
    except Exception as e:
        print(e)
        traceback.print_exc()

    return pdf_path



def genHtmlReport(summary, snippets, filepaths, filepaths_aoi, report_output_path):
    # Config
    with open(state.projectConfig, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            return None

    # Logo image
    try:
        # Convert the image to base64 format
        with open(state.staticLogo, "rb") as f:
            encoded_logo_image = base64.b64encode(f.read())
    
    except Exception as exc:
        print(exc)
        return None

    env = Environment( loader = FileSystemLoader(state.htmltemplates_dir))
    template_file = "report.html"
    template = env.get_template(template_file)
    output_text = template.render(
        reportTitle=config["title"],
        reportSubTitle=config["subtitle"] if config["subtitle"].lower() != 'none' and config["subtitle"] != "" else None,
        reportDate=datetime.now().strftime("%b %d, %Y"),
        summary=summary,
        snippets=snippets,
        filepaths_aoi=filepaths_aoi,
        filepaths=filepaths,
        logoImagePath=f"data:image/jpg;base64,{encoded_logo_image.decode('utf-8')}"
    )

    html_path = report_output_path
    html_file = open(html_path, 'w')
    html_file.write(output_text)
    html_file.close()
    return html_path,output_text



def _highLightCode(statements):
    code = "".join(statements)
    # Make the style 'default' to show the code snippet in grey background
    code = highlight(code, PythonLexer(), BetterHtmlFormatter(linenos="table", noclasses=True, style='github-dark'))
    return code



def getAreasOfInterest(input_file):
    # Open the input file
    f = open(input_file)

    snippet = None
    snippets = defaultdict(list)  # Use defaultdict to automatically initialize lists for each platform
    prev_snippets = None
    platform = None  # Initialize a variable to store the current platform

    # Read the file line by line
    for line in f.readlines():
        platform_match = re.match(r"--- (\w+) Findings ---", line)     # For extracting platform name
        # Look for a platform line, e.g., "--- JAVA Findings ---"
        # platform_match = re.match(r"--- (\w+ Findings) ---", line)  # For extracting platform name between '---'
        if platform_match:
            platform = platform_match.group(1)  # Store the full platform name (e.g., 'JAVA Findings')
            continue  # Skip to the next line after capturing the platform

        # Process Rule Title after capturing the platform
        if platform and "Rule Title" in line:
            # Extract the platform-specific rule count (e.g., JAVA-1, PHP-1, etc.)
            rulecount_match = re.match(r"(\w+-\d+)\.\s+Rule Title:", line)
            if rulecount_match:
                rulecount = rulecount_match.group(1)  # Extract the platform rule count (e.g., 'JAVA-1')
            else:
                rulecount = "GENERAL"  # Fallback to 'GENERAL' if no match is found

            # Extract the rule title (everything after "Rule Title:")
            keyword = re.sub("^.+Rule Title:", "", line).strip()

            # Escape the keyword for safe HTML rendering
            keyword = html.escape(keyword)

            # Save the snippet data with platform name and rule count
            if prev_snippets:
                prev_snippets["code"] = _highLightCode(prev_snippets["statements"])
                snippet["sources"].append(prev_snippets)

            # Initialize the snippet
            snippet = {
                "platform": platform,   # Store the platform name (e.g., JAVA, PHP, etc.)
                "rulecount": rulecount, # Store the platform rule count (e.g., JAVA-1)
                "keyword": keyword,     # Store the rule title
                "rule_desc": "",
                "issue_desc": "",
                "dev_note": "",
                "rev_note": "",
                "sources": [],
            }

            prev_snippets = None
            snippets[platform].append(snippet)  # Group the snippet by platform


        # Process Source File
        elif "Source File" in line:
            if prev_snippets:
                prev_snippets["code"] = _highLightCode(prev_snippets["statements"])
                snippet["sources"].append(prev_snippets)

            source = line.replace("-> Source File:", "").strip()
            source = html.escape(source)

            prev_snippets = {
                "source": source,
                "statements": []
            }

        # Process Rule Description
        elif line.lstrip().startswith('Rule Description'):
            if snippet:
                snippet["rule_desc"] = line.split(":", 1)[1].strip()

        # Process Issue Description
        elif line.lstrip().startswith('Issue Description'):
            if snippet:
                snippet["issue_desc"] = line.split(":", 1)[1].strip()

        # Process Developer Note
        elif line.lstrip().startswith('Developer Note'):
            if snippet:
                snippet["dev_note"] = line.split(":", 1)[1].strip()

        # Process Reviewer Note
        elif line.lstrip().startswith('Reviewer Note'):
            if snippet:
                snippet["rev_note"] = line.split(":", 1)[1].strip()

        # Process code snippets and other lines
        else:
            if prev_snippets and len(line.strip()) != 0:
                code = line.lstrip()
                prev_snippets["statements"].append(code)

    return snippets





def getFilePathsOfAOI(input_file):
    # Read text file
    f = open(input_file)
    paths_of_aoi = []
    path_obj = None

    for line in f.readlines():
        if search("Rule Title", line):
            keyword = re.sub("^.+Rule Title:", "", line)
            line = html.escape(keyword)

            path_obj = {
                "keyword": keyword,
                "paths": [],
            }

            paths_of_aoi.append(path_obj)

        elif search("File Path", line):
            path = line.replace("File Path:", "")
            line = html.escape(path)
            if path_obj:
                path_obj["paths"].append(path)
            
            
    return paths_of_aoi



def getFilePaths(input_file):
    # Read text file
    f = open(input_file)
    return f.readlines()



def getSummary(input_file):
    # Read text file
    f = open(input_file)
    content = f.read()
    content = html.escape(content)
    f.close()
  
    return content



def genReport():
    started_at = time.time()
    cli.section_print("[*] HTML Report Generation")
    print(f"    [-] Started at       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    snippets = getAreasOfInterest(state.outputAoI)
    filepaths_aoi = getFilePathsOfAOI(state.outputAoI_Fpaths)
    filepaths = getFilePaths(state.output_Fpaths)
    summary = getSummary(state.outputSummary)

    html_report_output_path =  state.htmlreport_Fpath
    pdf_report_path = state.pdfreport_Fpath

    htmlfile, output_html = genHtmlReport(summary, snippets, filepaths, filepaths_aoi, html_report_output_path)
    
    print(f"    [-] Completed at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    hours, rem = divmod(time.time() - started_at, 3600)
    minutes, seconds = divmod(rem, 60)
    seconds, milliseconds = str(seconds).split('.')
    print("    [-] Total time taken : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours),int(minutes),seconds, milliseconds[:3]))

    if not htmlfile:
        return None

    genPdfReport(htmlfile, pdf_report_path)

    # Display reports path but strip out the path to root directory
    cli.section_print("[*] HTML Report:")
    print("     [-] HTML Report Path : "+ re.sub(str(state.root_dir), "", str(state.htmlreport_Fpath)))
    cli.section_print("[*] PDF Report:")
    print("     [-] PDF Report Path : "+ re.sub(str(state.root_dir), "", str(state.pdfreport_Fpath)))
    cli.section_print("[*] Raw Text Reports:")    

    aoi_path = re.sub(str(state.root_dir), "", str(state.outputAoI))
    aoi_fpaths_path = re.sub(str(state.root_dir), "", str(state.outputAoI_Fpaths))
    discovered_files_path = re.sub(str(state.root_dir), "", str(state.discovered_clean_Fpaths))
    recon_path = re.sub(str(state.root_dir), "", str(state.outputRecSummary))

    if os.path.isfile(state.outputRecSummary):
        print("     [-] Reconnaissance Summary:", recon_path)
    if os.path.isfile(state.outputAoI):
        print("     [-] Areas of Interest (AoI):", aoi_path)
    if os.path.isfile(state.outputAoI_Fpaths):
        print("     [-] Filepaths (AoI):", aoi_fpaths_path)
    if os.path.isfile(state.discovered_clean_Fpaths):
        print("     [-] All Discovered Files:", discovered_files_path)

    
    print("\nNote: The tool generates reports in three formats: HTML, PDF, and TEXT. " 
    "While the HTML and PDF reports are currently in a reasonably good state, " 
    "they will undergo continuous refinement and improvement with each subsequent iteration.")
    
