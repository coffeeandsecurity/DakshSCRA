import sys
import xml.etree.ElementTree as ET
import pandas as pd
from tabulate import tabulate

import modules.runtime as runtime

# Function to obtain rules file path of a particular platform or the supported filetypes 
def getRulesPath_OR_FileTypes(platform, option):
    allowed_options = ["filetypes", "rules"]
    if option not in allowed_options:
        print(f"Error (getRulesPath_OR_FileTypes): Invalid option supplied. Allowed options are {allowed_options}!")
        sys.exit()

    ret_value = ""

    # Load filetypes XML config file
    xml_tree = ET.parse(runtime.rulesConfig)
    rules = xml_tree.getroot()

    for rule in rules:
        if rule.find("platform").text == platform:
            if option == "filetypes":
                ret_value = rule.find("ftypes").text
            elif option == "rules":
                ret_value = rule.find("path").text
            break

    return ret_value

'''
    for category in root:
        category_name = category.get('name')
        if category_name:
            print("     [-] Category: " + category_name)

            for rule in category:
                r = rule
'''



def rulesCount(rules_file):
    try:
        tree = ET.parse(rules_file)
        root = tree.getroot()

        total_rules_count = 0  # Initialize the count

        # Check if there are categories
        if root.findall('category'):
            # Iterate over the rule elements within categories
            for category in root.findall('category'):
                for rule in category.findall('rule'):
                    total_rules_count += 1
        else:
            # Iterate over the rule elements directly if no categories are present
            for rule in root.findall('rule'):
                total_rules_count += 1

        return total_rules_count

    except ET.ParseError as e:
        print(f"Error parsing XML file: {str(e)}")
        return 0


# List/Show rules or supported filetypes or both
def listRulesFiletypes(option):
    rule_dict = {}

    # Load filetypes XML config file
    xmltree = ET.parse(runtime.rulesConfig)
    rule = xmltree.getroot()


    if option == 'R':
        print("\nList of all available rules")
        for r in rule:
            print("\t" + r.find("platform").text)        # Return supported platforms

    elif option == 'RF':
        print("\nList both available rules and filetypes")
        for r in rule:
            rule_dict[r.find("platform").text] = r.find("ftypes").text

        if rule_dict:
            df = pd.DataFrame.from_dict(rule_dict, orient='index')
            print("\n" + tabulate(df, headers=["Platform", "File Types"], tablefmt="grid", maxcolwidths=[None, 40]) + "\n")
        else:
            print("No rules and filetypes found.")

    else:
        print("Invalid option")

    return 1 if rule_dict else 0