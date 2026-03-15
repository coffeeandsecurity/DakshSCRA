# Standard libraries
import sys
import xml.etree.ElementTree as ET

# Third-party libraries
from tabulate import tabulate

# Local application imports
import state.runtime_state as runtime_utils



def get_rules_path_or_filetypes(platform, option):
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
        print(f"Error (get_rules_path_or_filetypes): Invalid option supplied. Allowed options are {allowed_options}!")
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



def rules_count(rules_file):
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



def list_rules_filetypes(option):
    """
    List available rules, file types, or both based on the provided option.

    Parameters:
        option (str): 
            - 'R' to list all available rules.
            - 'RF' to list both available rules and supported file types.

    Returns:
        int: 1 if file types are listed, otherwise 0.
    """

    option = (option or "").strip().upper()
    rows = []
    framework_map = {}

    # Load filetypes XML config file
    xmltree = ET.parse(runtime_utils.rulesConfig)
    rule = xmltree.getroot()

    # Load framework registry config file
    try:
        fw_tree = ET.parse(runtime_utils.frameworkConfig)
        fw_root = fw_tree.getroot()
        for fw in fw_root.findall("framework"):
            fw_name = (fw.findtext("name") or "").strip()
            fw_platform = (fw.findtext("platform") or "").strip()
            if not fw_name or not fw_platform:
                continue
            framework_map.setdefault(fw_platform, set()).add(fw_name)
    except (ET.ParseError, FileNotFoundError):
        framework_map = {}

    if option == 'R':
        print("\nAvailable platform rules and framework mappings\n")
        for r in rule:
            platform = (r.findtext("platform") or "").strip()
            frameworks = sorted(framework_map.get(platform, set()))
            framework_text = ", ".join(frameworks) if frameworks else "-"
            rows.append([platform, framework_text])
        if rows:
            print(tabulate(rows, headers=["Platform Rule", "Framework Rules"], tablefmt="grid", maxcolwidths=[18, 60]))
            print()
        else:
            print("No rule entries found.\n")

    elif option == 'RF':
        print("\nAvailable platform rules, framework mappings and file types\n")
        for r in rule:
            platform = (r.findtext("platform") or "").strip()
            file_types = (r.findtext("platform_ftypes") or "").strip()
            frameworks = sorted(framework_map.get(platform, set()))
            framework_text = ", ".join(frameworks) if frameworks else "-"
            rows.append([platform, framework_text, file_types])

        if rows:
            print(tabulate(rows, headers=["Platform Rule", "Framework Rules", "File Types"], tablefmt="grid", maxcolwidths=[18, 36, 50]))
            print()
        else:
            print("No rule or file type entries found.\n")

    else:
        print("Invalid option. Use R or RF.")

    return 1 if rows else 0



def get_available_rules(exclude=None):
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


# Backward-compatible aliases for legacy callers.
getRulesPath_OR_FileTypes = get_rules_path_or_filetypes
rulesCount = rules_count
listRulesFiletypes = list_rules_filetypes
getAvailableRules = get_available_rules
