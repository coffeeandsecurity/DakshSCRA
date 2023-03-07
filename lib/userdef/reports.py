import sys, re
import html
from re import search

try :
	from jinja2 import Environment, PackageLoader, FileSystemLoader, Template
except ImportError :
	sys.exit("[!] The Jinja2 module is not installed, please install it and try again")

import lib.userdef.settings as settings

def GenReport():
    GenHtmlReport()
    
    print("\n[*] Raw Text Reports:")
    print("     [*] Areas of Interest: " + "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.outputAoI))[1]))
    print("     [*] Project Files - Areas of Interest: " + "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.outputAoI_Fpaths))[1]))
    print("     [*] Discovered Files Path: " + "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.discovered_Fpaths))[1]))
    print("\n[*] HTML Report: WORK IN PROGRESS - IGNORE THIS REPORT")
    print("     [*] HTML Report Path : "+ "DakshSCRA"+ str(re.split("DakshSCRA+", str(settings.htmlreport_Fpath))[1]))



def GenHtmlReport():

    env = Environment( loader = FileSystemLoader(settings.htmltemplates_dir))
    template = env.get_template('template.html')

    with open(settings.htmlreport_Fpath, 'w') as fh:
        contents = open(settings.outputAoI, "r")        # Input file 'settings.outputAoI' for generating HTML report
        
        for lines in contents.readlines():
            encodedString = html.escape(lines) # HTML Encoding is used to avoid execution of any malicious script that are part of the code snippet
            if search("Keyword Searched", encodedString):
                fh.write(template.render(keyword=encodedString))
            elif search("Source File", encodedString):
                encodedString = encodedString.strip("S")
                fh.write(template.render(fpath=encodedString))
            else:
                fh.write(template.render(snippet="&nbsp;&nbsp;" + encodedString))

    return
