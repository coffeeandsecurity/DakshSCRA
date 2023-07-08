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

import modules.runtime as runtime
import yaml
import base64

def genPdfReport(html_path, pdf_path):
    try:
        started_at = time.time()
        print(f"[*] PDF report generation")
        print(f"    [-] Started at       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("    [-] Be patient! PDF report generation takes time.")
        

        HTML(html_path).write_pdf(pdf_path, stylesheets=[CSS(runtime.staticPdfCssFpath)])

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
    with open(runtime.projectConfig, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            return None

    # Logo image
    try:
        # Convert the image to base64 format
        with open(runtime.staticLogo, "rb") as f:
            encoded_logo_image = base64.b64encode(f.read())
    
    except Exception as exc:
        print(exc)
        return None

    env = Environment( loader = FileSystemLoader(runtime.htmltemplates_dir))
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
    # Read text file
    f = open(input_file)

    snippet = None
    snippets = []
    prev_snippets = None
    for line in f.readlines():
        if search("Rule Title", line):
            keyword = re.sub("^.+Rule Title:", "", line)
            
            keyword = html.escape(keyword)

            if prev_snippets:                
                prev_snippets["code"] = _highLightCode(prev_snippets["statements"])
                snippet["sources"].append(prev_snippets)

            snippet = {
                "keyword": keyword,
                "rule_desc": "",
                "issue_dec": "",
                "dev_note": "",
                "rev_note": "",
                "sources": [],
            }

            prev_snippets = None
            snippets.append(snippet)

        elif search("Source File", line):
            if prev_snippets:
                prev_snippets["code"] = _highLightCode(prev_snippets["statements"])
                snippet["sources"].append(prev_snippets)

            source = line.replace("-> Source File:", "")
            source = html.escape(source)

            prev_snippets = {
                "source": source,
                "statements": []
            }

        elif line.lstrip().startswith('Rule Description'):
            if snippet:
                snippet["rule_desc"] = line.split(":", 1)[1]
        elif line.lstrip().startswith('Issue Description'):
             if snippet:
                snippet["issue_desc"] = line.split(":", 1)[1]
        elif line.lstrip().startswith('Developer Note'):
             if snippet:
                snippet["dev_note"] = line.split(":", 1)[1]
        elif line.lstrip().startswith('Reviewer Note '): 
             if snippet:
                snippet["rev_note"] = line.split(":", 1)[1]       
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
    print(f"[*] HTML report generation")
    print(f"    [-] Started at       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    snippets = getAreasOfInterest(runtime.outputAoI)
    filepaths_aoi = getFilePathsOfAOI(runtime.outputAoI_Fpaths)
    filepaths = getFilePaths(runtime.output_Fpaths)
    summary = getSummary(runtime.outputSummary)

    html_report_output_path =  runtime.htmlreport_Fpath
    pdf_report_path = runtime.pdfreport_Fpath

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
    print("\n[*] HTML Report:")
    print("     [-] HTML Report Path : "+ re.sub(str(runtime.root_dir), "", str(runtime.htmlreport_Fpath)))
    print("\n[*] PDF Report:")
    print("     [-] PDF Report Path : "+ re.sub(str(runtime.root_dir), "", str(runtime.pdfreport_Fpath)))
    print("\n[*] Raw Text Reports:")

    aoi_path = re.sub(str(runtime.root_dir), "", str(runtime.outputAoI))
    aoi_fpaths_path = re.sub(str(runtime.root_dir), "", str(runtime.outputAoI_Fpaths))
    discovered_files_path = re.sub(str(runtime.root_dir), "", str(runtime.discovered_clean_Fpaths))
    recon_path = re.sub(str(runtime.root_dir), "", str(runtime.outputRecSummary))

    if os.path.isfile(runtime.outputRecSummary):
        print("     [-] Reconnaissance Summary:", recon_path)
    if os.path.isfile(runtime.outputAoI):
        print("     [-] Areas of Interest:", aoi_path)
    if os.path.isfile(runtime.outputAoI_Fpaths):
        print("     [-] Project Files - Areas of Interest:", aoi_fpaths_path)
    if os.path.isfile(runtime.discovered_clean_Fpaths):
        print("     [-] Discovered Files Path:", discovered_files_path)

    
    print("\nNote: The tool generates reports in three formats: HTML, PDF, and TEXT. " 
    "While the HTML and PDF reports are currently in a reasonably good state, " 
    "they will undergo continuous refinement and improvement with each subsequent iteration.")
    
