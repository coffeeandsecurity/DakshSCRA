import sys, re
import html
from re import search

try :
	from jinja2 import Environment, PackageLoader, FileSystemLoader, Template
except ImportError :
	sys.exit("[!] The Jinja2 module is not installed, please install it and try again")

from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
from datetime import datetime
from weasyprint import HTML, CSS

import modules.settings as settings



def genPdfReport(html_path, pdf_path):
    try:
        css = CSS(string='@page { size: A3; margin: 0.75in }')
        HTML(html_path).write_pdf(pdf_path, stylesheets=[css])
        return pdf_path
    except Exception as e:
        print(e)

    return pdf_path

def genHtmlReport(summary, snippets, filepaths, report_output_path):

    env = Environment( loader = FileSystemLoader(settings.htmltemplates_dir))
    template_file = "report.html"
    template = env.get_template(template_file)
    output_text = template.render(
        reportTitle="Report Title - Placeholder",
        reportSubTitle="Report Sub-Title - Placeholder",
        reportDate=datetime.now().strftime("%b %m, %Y"),
        summary=summary,
        snippets=snippets,
        filepaths=filepaths
    )

    html_path = report_output_path
    html_file = open(html_path, 'w')
    html_file.write(output_text)
    html_file.close()

    return html_path

def _highLightCode(statements):
    code = "".join(statements)
    # Make the style 'default' to show the code snippet in grey background
    code = highlight(code, PythonLexer(), HtmlFormatter(linenos=True, noclasses=True, style='github-dark'))
    return code

def getAreasOfInterest(input_file):
    # Read text file
    f = open(input_file)
    snippets = []
    prev_snippets = None
    for line in f.readlines():
        if search("Keyword Searched", line):

            keyword = line.replace("# Keyword Searched:", "")
            keyword = html.escape(keyword)

            if prev_snippets:                
                prev_snippets["code"] = _highLightCode(prev_snippets["statements"])
                snippet["sources"].append(prev_snippets)

            snippet = {
                "keyword": keyword,
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
        if search("Keyword Searched", line):
            keyword = line.replace("# Keyword Searched:", "")
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

def getSummary(input_file):
    # Read text file
    f = open(input_file)
    content = f.read()
    content = html.escape(content)
    f.close()
  
    return content

def GenReport():
    snippets = getAreasOfInterest(settings.outputAoI)
    filepaths = getFilePathsOfAOI(settings.outputAoI_Fpaths)
    summary = getSummary(settings.outputSummary)

    html_report_output_path =  settings.htmlreport_Fpath
    pdf_report_path = settings.pdfreport_Fpath

    htmlfile = genHtmlReport(summary, snippets, filepaths, html_report_output_path)

    genPdfReport(htmlfile, pdf_report_path)

    print("\n[*] HTML Report:")
    print("     [*] HTML Report Path : "+ "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.htmlreport_Fpath))[1]))
    print("\n[*] PDF Report:")
    print("     [*] PDF Report Path : "+ "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.pdfreport_Fpath))[1]))
    print("\n[*] Raw Text Reports:")
    print("     [*] Areas of Interest: " + "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.outputAoI))[1]))
    print("     [*] Project Files - Areas of Interest: " + "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.outputAoI_Fpaths))[1]))
    print("     [*] Discovered Files Path: " + "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.discovered_Fpaths))[1]))
    print("\nNote: The tool generates reports in three formats: HTML, PDF, and TEXT. " 
    "Although the HTML and PDF reports are still being improved, they are currently in a reasonably good state. " 
    "With each subsequent iteration, these reports will continue to be refined and improved even further.")
    
