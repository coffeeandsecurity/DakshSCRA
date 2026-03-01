# Daksh SCRA (Source Code Review Assist)

```
Author: 	
- Debasis Mohanty (d3basis.m0hanty@gmail.com)
- Twitter: @coffeensecurity
- www.coffeeandsecurity.com
```

## About Daksh SCRA

Daksh SCRA (Source Code Review Assist) tool is built to enhance the efficiency of the source code review process, providing a well-structured and organized approach for code reviewers.

Rather than indiscriminately flagging everything as a potential issue, Daksh SCRA promotes thoughtful analysis, urging the investigation and confirmation of potential problems. This approach mitigates the scramble to tag every potential concern as a bug, cutting back on the confusion and wasted time spent on false positives.

What sets Daksh SCRA apart is its emphasis on avoiding unnecessary bug tagging. Unlike conventional methods, it advocates for thorough investigation and confirmation of potential issues before tagging them as bugs. This approach helps mitigate the issue of false positives, which often consume valuable time and resources, thereby fostering a more productive and efficient code review process.

## Debut

Daksh SCRA was initially introduced during a source code review training session I conducted at Black Hat USA 2022 (August 6 - 9), where it was subtly presented to a specific audience. However, this introduction was carried out with a low-profile approach, avoiding any major announcements.

While this tool was quietly published on GitHub after the 2022 training, its official public debut took place at Black Hat USA 2023 in Las Vegas.

## Features and Functionalities

### Distinctive Features (Multiple World’s First)

- **Identifies Areas of Interest in Source Code:** Encourage focused investigation and confirmation rather than indiscriminately labeling everything as a bug.

- **Identifies Areas of Interest in File Paths (World’s First):** Recognises patterns in file paths to pinpoint relevant sections for review.

- **Software-Level Reconnaissance to Identify Technologies Utilised:** Identifies project technologies, enabling code reviewers to conduct precise scans with appropriate rules.

- **Automated Scientific Effort Estimation for Code Review (World’s First):** Providing a measurable approach for estimating efforts required for a code review process.

> Although this tool has progressed beyond its early stages, it has reached a functional state that is quite usable and delivers on its promised capabilities. Nevertheless, active enhancements are currently underway, and there are multiple new features and improvements expected to be added in the upcoming months.

Additionally, the tool offers the following functionalities:

- Options to use platform-specific rules specific for finding areas of interests
- Options to extend or add new rules for any new or existing languages
- Generates report in text, HTML and PDF format for inspection

Refer to the wiki for the tool setup and usage details - [https://github.com/coffeeandsecurity/DakshSCRA/wiki](https://github.com/coffeeandsecurity/DakshSCRA/wiki)

Feel free to contribute towards updating or adding new rules and future development.

If you find any bugs, report them to [d3basis.m0hanty@gmail.com](mailto\:d3basis.m0hanty@gmail.com).

## Tool Setup

### Pre-requisites

- Python 3.8+
- All the libraries listed in `requirements.txt`



### 1. Download Daksh SCRA

Download and save the latest build from here: [https://github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) Save it to your desired folder/directory. Must make sure you have unzipped it.

Alternatively, 'cd' into your desired folder/directory and download using the 'git' command:

```
git clone https://github.com/coffeeandsecurity/DakshSCRA.git
```



### 2. Setup a Virtual Environment

> 💡 *You can create the virtual environment in any directory. It does not have to be inside the DakshSCRA folder.*

You have two options:

#### ✅ Option A: One-Step Setup (Recommended) — Use `setup_env.py`

This script automates the full environment setup, including creating a virtual environment, installing dependencies, and installing Playwright's Chromium browser.

```
python setup_env.py
```

What it does:

- Creates an isolated virtual environment
- Activates the environment
- Installs required packages from `requirements.txt`
- Installs Chromium (required by Playwright for PDF export)



#### 🔧 Option B: Manual Setup

##### Step 1: Create a Virtual Environment

**Windows:**

```
python -m venv daksh-env
.\daksh-env\Scripts\activate
```

**macOS/Linux:**

```
python3 -m venv daksh-env
source daksh-env/bin/activate
```

##### Step 2: Install Required Libraries

Navigate to your DakshSCRA directory:

```
cd path/to/DakshSCRA
pip install -r requirements.txt
```

##### Step 3: Install Playwright & Chromium

```
pip install playwright
playwright install chromium
```

> ✅ After activation, your terminal prompt should show your environment name.

You’re now ready to use DakshSCRA.



## Tool Usage
💡 Use python if you're inside a virtual environment. Otherwise, use python3 or the appropriate Python version installed on your system.

### RDL Rule Authoring (Quick Note)

Rules can now include optional `<rdl>` for conditional checks in addition to `<regex>`.

Example:

```xml
<rule>
  <name>Conditional SQLi Check</name>
  <regex><![CDATA[(?i)\b(?:mysql_query|mysqli_query|->query)\s*\(]]></regex>
  <rdl><![CDATA[[FLAG:\$_(GET|POST|REQUEST|COOKIE)][IF(MISSING:\b(?:prepare|bindParam|bindValue|PDO::prepare)\b)]]></rdl>
  <rule_desc>...</rule_desc>
  <vuln_desc>...</vuln_desc>
  <developer>...</developer>
  <reviewer>...</reviewer>
</rule>
```

Supported RDL operators:
- `FLAG:<regex>`
- `IF(...)`
- predicates: `MISSING:`, `PRESENT:`, `EXISTS:`
- boolean operators: `&&`, `||`, `!`

```
# To view tool usage along with examples
$ python dakshscra.py          # Inside virtual environment
# OR
$ python3 dakshscra.py         # If running outside the venv

# To view help and available options
$ python dakshscra.py -h       # Inside virtual environment
# OR
$ python3 dakshscra.py -h      # Outside virtual environment
```

```text
usage: dakshscra.py [-h] [-r RULES] [-f FILE_TYPES] [-v] [-t TARGET_DIR]
                    [-l {R,RF}] [-recon] [-estimate] [-rpt FORMATS]
                    [--analysis] [--loc] [--baseline-file PATH]
                    [--baseline-generate] [--no-baseline]

options:
-h, --help                 Show this help message and exit
-r RULES                   Platform rules (e.g. php,java,cpp) or "auto"
-f FILE_TYPES              Override default filetypes for scanning
-v                         Verbosity level (-v, -vv, -vvv)
-t TARGET_DIR              Target source code directory
-l {R,RF}, --list {R,RF}   List rules [R] OR rules and filetypes [RF]
-recon                     Detect platform/framework/language stack
-estimate                  Estimate review effort
-rpt, --report FORMATS     Report types: html, pdf, or html,pdf
--analysis, --analyse      Experimental data/control flow analysis
--loc                      Count effective lines of code
--baseline-file PATH       Suppression baseline file (JSON)
--baseline-generate        Generate baseline from current findings
--no-baseline              Disable baseline suppression for current run
```

### Example Usage

📝 Note:
-f (file types) is optional. If not specified, DakshSCRA uses the default file types for the selected platform(s).

```
# Specify platforms with '-r' (single or multiple) for platform-specific rules:
- Single platform:     dakshscra.py -r php -t /source_dir_path
- Multiple platforms:  dakshscra.py -r php,java,cpp -t /source_dir_path
- Auto-detect:         dakshscra.py -r auto -t /source_dir_path

# Override filetypes using '-f' (optional)
- dakshscra.py -r php -f dotnet -t /source_dir_path
- dakshscra.py -r java -f custom -t /source_dir_path

# Perform Reconnaissance and Rule-Based Scanning
- dakshscra.py -recon -r php -t /source_dir_path

# Perform Recon Only (No Rule-Based Scanning)
- dakshscra.py -recon -t /source_dir_path

# Effort Estimation (without scanning)
- dakshscra.py -estimate -t /source_dir_path

# Verbosity: '-v' is default, '-vvv' will show all pattern checks
- dakshscra.py -r php -vvv -t /source_dir_path

# Generate baseline suppression from current findings
- dakshscra.py -r auto -t /source_dir_path --baseline-generate

# Apply baseline suppression for recurring known FPs
- dakshscra.py -r auto -t /source_dir_path --baseline-file config/suppressions.json

# Run without suppression baseline
- dakshscra.py -r auto -t /source_dir_path --no-baseline
```

### View List of Supported Rules

```
dakshscra.py -l R   # List all supported rule types
```

Currently supported:

- dotnet, php, java, javascript,
- kotlin, python, go, c, cpp,
- android, ios, reactnative, flutter, xamarin, ionic, nativescript, cordova,
- ruby, rust, common



## Reports

The tool produces HTML/PDF reports and structured JSON outputs.

### Scanning Report Outputs

- HTML report
- PDF report
- JSON findings (AoI, file-path AoI, summary, recon summary)
- Runtime inventory output

### Effort Estimation Report

- HTML estimation report

> Note: This feature is in early stage. Future versions will improve the accuracy and add PDF support.
