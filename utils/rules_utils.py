# Standard libraries
import sys
import xml.etree.ElementTree as ET

# Third-party libraries
import pandas as pd
from tabulate import tabulate

# Local application imports
import state.runtime_state as runtime_utils



def getRulesPath_OR_FileTypes(platform, option):
    """
    Retrieve the rules file path or supported file types for a specific platform.

    Parameters:
        platform (str): The platform for which to retrieve the rules or file types.
        option (str): 
            - 'filetypes' to get supported file types.
            - 'rules' to get the rules file path.

    Returns:
        str: The corresponding rules file path or supported file types for the specified platform.

    Raises:
        SystemExit: If an invalid option is supplied.
    """

    allowed_options = ["filetypes", "rules"]
    if option not in allowed_options:
        print(f"Error (getRulesPath_OR_FileTypes): Invalid option supplied. Allowed options are {allowed_options}!")
        sys.exit()

    ret_value = ""

    # Load filetypes XML config file
    xml_tree = ET.parse(runtime_utils.rulesConfig)
    rules = xml_tree.getroot()

    for rule in rules:
        if rule.find("platform").text == platform:
            if option == "filetypes":
                ret_value = rule.find("platform_ftypes").text
            elif option == "rules":
                ret_value = rule.find("path").text
            break

    return ret_value



def rulesCount(rules_file):
    """
    Count the total number of rules in an XML rules file.

    Parameters:
        rules_file (str): The path to the XML file containing the rules.

    Returns:
        int: The total number of rules found in the XML file, or 0 if an error occurs.
    """

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



def listRulesFiletypes(option):
    """
    List available rules, file types, or both based on the provided option.

    Parameters:
        option (str): 
            - 'R' to list all available rules.
            - 'RF' to list both available rules and supported file types.

    Returns:
        int: 1 if file types are listed, otherwise 0.
    """

    rule_dict = {}

    # Load filetypes XML config file
    xmltree = ET.parse(runtime_utils.rulesConfig)
    rule = xmltree.getroot()


    if option == 'R':
        print("\nList of all available rules")
        for r in rule:
            print("\t" + r.find("platform").text)        # Return supported platforms

    elif option == 'RF':
        print("\nList both available rules and filetypes")
        for r in rule:
            rule_dict[r.find("platform").text] = r.find("platform_ftypes").text

        if rule_dict:
            df = pd.DataFrame.from_dict(rule_dict, orient='index')
            print("\n" + tabulate(df, headers=["Platform", "File Types"], tablefmt="grid", maxcolwidths=[None, 40]) + "\n")
        else:
            print("No rules and filetypes found.")

    else:
        print("Invalid option")

    return 1 if rule_dict else 0



def getAvailableRules(exclude=None):
    """
    Get a comma-separated string of available rules with no duplicates or spaces.

    Parameters:
        exclude (list): List of rules to exclude temporarily from the return value.

    Returns:
        str: Comma-separated string of available rules.
    """
    exclude = exclude or []  # Default to an empty list if exclude is None
    available_rules = set()

    # Load filetypes XML config file
    xmltree = ET.parse(runtime_utils.rulesConfig)
    rules = xmltree.getroot()

    # Collect available rules
    for rule in rules:
        platform = rule.find("platform").text.strip()
        if platform not in exclude:
            available_rules.add(platform)

    # Return comma-separated string with no spaces
    return ",".join(sorted(available_rules))
