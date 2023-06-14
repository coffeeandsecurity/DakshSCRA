import re
import sys
import xml.etree.ElementTree as ET
from timeit import default_timer as timer

import modules.runtime as runtime
import modules.misclib as mlib


'''
This routine will search patterns loaded from the XML file and parse through all source files.

The following parameters are expected: 
    rule_path   - Path to rule file (or rule file name)
    targetfile  - Target file containing enumerated filepaths withing the target source directory
    outputfile  - File for writing scan output
'''
def sourceParser(rule_path, targetfile, outputfile, rule_no):
    # Load rules from XML file
    xmltree = ET.parse(rule_path)
    rule = xmltree.getroot()

    f_scanout = outputfile
    f_targetfiles = targetfile

    iCnt = 0

    for r in rule:
        rule_no += 1
        f_scanout.write(str(rule_no)+". Rule Title: " + r.find("name").text + "\n")
        pattern = r.find("regex").text

        rule_desc = r.find("rule_desc").text
        vuln_desc = r.find("vuln_desc").text
        dev_note = r.find("developer").text
        rev_note = r.find("reviewer").text

        f_scanout.write(f"\n\t Rule Description  : {rule_desc}"
                        f"\n\t Issue Description : {vuln_desc}"
                        f"\n\t Developer Note    : {dev_note}"
                        f"\n\t Reviewer Note     : {rev_note} \n")


        if r.find('mitigation/regex'):
            pattern = r.get('mitigation/regex')

        exclude = r.find("exclude").text if r.find("exclude") is not None else ""

        # stdout based on verbosity level set
        if str(runtime.verbosity) == '1':
            #sys.stdout.write("\033[F")
            sys.stdout.write("\033[K")
            print("     [-] Applying Rule: " + r.find("name").text, end='\r')
        else:
            sys.stdout.write("\033[K")
            print("     [-] Applying Rule: " + r.find("name").text)

        for eachfilepath in f_targetfiles:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
            
            iCnt += 1
            print('\t Parsing file: ' + "["+str(iCnt)+"] "+ mlib.getSourceFilePath(runtime.sourcedir, filepath))
            sys.stdout.write("\033[F\033[K")  # Clear line to prevent overlap of texts
            #sys.stdout.write("\033[K\033[F")  # Clear line to prevent overlap of texts - There is an overlap issue with this combination

            try:
                # TODO: Read the file using the detected encoding type - Giving errors at some stage. Will be fixed later
                # with open(filepath, 'r', encoding=mlib.detectEncodingType(filepath)) as fo_target:
                # with open(filepath, 'r', encoding='utf8') as fo_target:
                with open(filepath, 'r', encoding='ISO-8859-1') as fo_target:       # ISO-8859-1 encoding type works on most occasions but utf8 errors out
                    linecount = 0
                    fpath = False
                    for line in fo_target:
                        linecount += 1

                        if len(line) > 500:     # Setting maximum input length of the string read from the file
                            continue  # Skip long lines
                        
                        # Check for matches excluding excluded strings
                        # if re.findall(pattern, line) and not re.search(exclude, line, re.IGNORECASE):
                        if re.findall(pattern, line):
                            if exclude and re.search(exclude, line, re.IGNORECASE):
                                continue
                    
                            line = (line[:75] + '..') if len(line) > 300 else line

                            # TOTO - Include checks to skip strings when an exclude rule matches.
                            # Example: Exclude SQL statements from matching
                            '''
                            if re.search(r'\b(?:SELECT|UPDATE|INSERT|FROM)\b', line, re.IGNORECASE):
                                continue
                            '''
                            if not fpath:
                                f_scanout.write("\n\t -> Source File: " + mlib.getSourceFilePath(runtime.sourcedir, filepath) + "\n")
                                fpath = True
                                f_scanout.write("\t\t [" + str(linecount) + "]" + line)
                            else:
                                f_scanout.write("\t\t [" + str(linecount) + "]" + line)
        
            except OSError:
                print("OS Error occurred!")
            except UnicodeError as err:
                print("Error Occurred: ", err)
                print(filepath)
        
        f_scanout.write("\n")
        f_targetfiles.seek(0)  # Reset the file pointer to the beginning
             
        iCnt = 0
        sys.stdout.write("\033[K")  # Clear line to prevent overlap of texts
    return


'''
This routine will parse all enumerated file paths and match patterns to group them under matched category
'''
def pathsParser(rule_path, targetfile, outputfile, rule_no):
    # Load rules from XML file
    xmltree = ET.parse(rule_path)
    rule = xmltree.getroot()

    f_scanout = outputfile
    f_targetfilepaths = targetfile
    pFlag = False

    for r in rule:
        rule_no += 1        
        f_scanout.write(f"{rule_no}. Rule Title: {r.find('name').text}\n")

        pattern = r.find("regex").text
        pattern_name = r.find("name").text

        for eachfilepath in f_targetfilepaths:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
            filepath = mlib.getSourceFilePath(runtime.sourcedir, filepath)

            if re.findall(pattern, filepath):
                if pFlag == False:
                    # f_scanout.write(("Pattern Name: " + pattern_name) + "\n")
                    f_scanout.write(("\tFile Path: " + filepath) + "\n")
                    print("     [-] File path pattern match:" + pattern_name)

                    sys.stdout.write("\033[F") #back to previous line
                    sys.stdout.write("\033[K") #clear line to prevent overlap of texts
                    
                    pFlag = True
                else: 
                    f_scanout.write(("\tFile Path: " + filepath) + "\n")             
                
        pFlag = False
        f_targetfilepaths.seek(0, 0)
    
    return


