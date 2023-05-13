import re, sys
import xml.etree.ElementTree as ET
import chardet
from timeit import default_timer as timer
# import time
# from pathlib import Path    # Resolve the windows / mac / linux path issue

import modules.settings as settings
import modules.misclib as mlib


def detectEncodingType(targetfile):
    # Open the file in binary mode and read the first 1000 bytes to detect the encoding type
    with open(targetfile, 'rb') as f:
        result = chardet.detect(f.read(1000))

    print('Detected encoding type:', result['encoding'])
    return result['encoding']



'''
This routine will search patterns loaded from the XML file and parse through all source files.

The following parameters are expected: 
    rule_path   - Path to rule file (or rule file name)
    targetfile  - Target file containing enumerated filepaths withing the target source directory
    outputfile  - File for writing scan output
'''
def SourceParser(rule_path, targetfile, outputfile):
    # Load rules from XML file
    xmltree = ET.parse(rule_path)
    rule = xmltree.getroot()

    f_scanout = outputfile
    f_targetfiles = targetfile

    iCnt = 0

    for r in rule:
        start_time = timer()
        f_scanout.write("# Keyword Searched: " + r.find("name").text + "\n")
        pattern = r.find("regex").text
        if r.find('mitigation/regex'):
            pattern = r.get('mitigation/regex')

        # stdout based on verbosity level set
        if str(settings.verbosity) == '1':
            #sys.stdout.write("\033[F")
            sys.stdout.write("\033[K")
            print("\t[#] Searching for keyword: " + r.find("name").text, end='\r')
            #print("\n\tRegex Pattern: " + pattern)
            #sys.stdout.write("\033[F")
            #sys.stdout.write("\033[K")
        else:
            sys.stdout.write("\033[K")
            print("\t[#] Searching for keyword: " + r.find("name").text)
            #print("\tRegex Pattern: " + pattern)    

        for eachfilepath in f_targetfiles:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
        
            #sys.stdout.write("\033[K") #clear line to prevent overlap of texts
            print('\n\t[#] Parsing file: ' + "["+str(iCnt)+"] "+ mlib.GetSourceFilePath(settings.sourcedir, filepath), end='\r')
            sys.stdout.write("\033[K") #clear line to prevent overlap of texts
            sys.stdout.write("\033[F")
            iCnt = iCnt + 1

            # filepath = filepath[:-1]  # Slicing is another appproach to strip out '\n' from the file paths
            try:
                # Code has to be written later to handle both utf8 and ISO-8859-1 encoding type
                # fo_target = open(filepath, encoding="utf8")
                # fo_target = open(filepath, encoding="ISO-8859-1")
                # Read the file using the detected encoding type
                fo_target = open(filepath, 'r', encoding=detectEncodingType(filepath))

                linecount = 0
                fpath = False
                for line in fo_target:
                    linecount += 1
                    # if re.findall(keyword, line):
                    if re.findall(pattern, line):
                        line = (line[:75] + '..') if len(line) > 300 else line
                        if not fpath:
                            f_scanout.write("\n\t -> Source File: " + mlib.GetSourceFilePath(settings.sourcedir, filepath) + "\n")
                            fpath = True
                            f_scanout.write("\t\t [" + str(linecount) + "]" + line)
                        else:
                            f_scanout.write("\t\t [" + str(linecount) + "]" + line)
            except OSError:
                print("OS Error occured!")
                pass
            except UnicodeDecodeError as err:
                print("Error Occured: ", err)
                print(filepath)
                pass
            except UnicodeEncodeError as err:
                print("Error Occured: ", err)
                print(filepath)
                pass
            finally:
                fo_target.close()
        else:
            # sys.stdout.write("\033[F") #back to previous line 
            # sys.stdout.write("\033[K") #clear line to prevent overlap of texts
            # print("\tTime taken for the search: " + time.strftime("%HHr:%MMin:%Ss", time.gmtime(timer() - start_time)))
            f_scanout.write("\n")
            f_targetfiles.seek(0, 0)

    sys.stdout.write("\033[K") #clear line to prevent overlap of texts
    return


'''
This routine will parse all enumerated file paths and match patterns to group them under matched category
'''
def PathsParser(rule_path, targetfile, outputfile):
    # Load rules from XML file
    xmltree = ET.parse(rule_path)
    rule = xmltree.getroot()

    f_scanout = outputfile
    f_targetfilepaths = targetfile
    pFlag = False

    for r in rule:
        start_time = timer()
        f_scanout.write("# Keyword Searched: " + r.find("name").text + "\n")
        pattern = r.find("regex").text
        pattern_name = r.find("name").text

        for eachfilepath in f_targetfilepaths:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
            filepath = mlib.GetSourceFilePath(settings.sourcedir, filepath)

            if re.findall(pattern, filepath):
                if pFlag == False:
                    f_scanout.write(("Pattern Name: " + pattern_name) + "\n")
                    f_scanout.write(("\tFile Path: " + filepath) + "\n")
                    print("[*] Parsing File Paths!! FIX ME")
                    print("[*] File path pattern match:" + pattern_name)
                    # print("\t" + filepath)
                    sys.stdout.write("\033[K") #clear line to prevent overlap of texts
                    #sys.stdout.write("\033[F") #back to previous line
                    pFlag = True
                else: 
                    f_scanout.write(("\tFile Path: " + filepath) + "\n")             
                    # print("\t" + filepath)
                
        pFlag == False
        f_targetfilepaths.seek(0, 0)

    return


