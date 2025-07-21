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

---

### 1. Download Daksh SCRA

Download and save the latest build from here: [https://github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) Save it to your desired folder/directory. Must make sure you have unzipped it.

Alternatively, 'cd' into your desired folder/directory and download using the 'git' command:

```
git clone https://github.com/coffeeandsecurity/DakshSCRA.git
```

---

### 2. Setup a Virtual Environment

> 💡 *You can create the virtual environment in any directory. It does not have to be inside the DakshSCRA folder.*

You have two options:

#### ✅ Option A: One-Step Setup (Recommended) — Use `setup_env.py`

This script automates the full environment setup, including creating a virtual environment, installing dependencies, and installing Playwright's Chromium browser.

```
python setup_env.py
```

What it does:

- Creates a virtual environment in `venv/`
- Activates the environment
- Installs required packages from `requirements.txt`
- Installs Chromium (required by Playwright for PDF export)



#### 🔧 Option B: Manual Setup

##### Step 1: Create a Virtual Environment

**Windows:**

```
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**

```
python3 -m venv venv
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

> ✅ After activation, your terminal prompt should show the environment name: `(venv) $`

You’re now ready to use DakshSCRA.

---

## Tool Usage

```
$ python3 dakshscra.py -h  # To view available options and arguments
```

```
usage: dakshscra.py [-h] [-r RULE_FILE] [-f FILE_TYPES] [-v] [-t TARGET_DIR] [-l {R,RF}] [-recon] [-estimate]

options:
-h, --help                 Show this help message and exit
-r RULE_FILE               Specify platform-specific rule name or 'auto' for auto-detection of platforms
-f FILE_TYPES              Specify file types to scan
-v                         Specify verbosity level {'-v', '-vv', '-vvv'}
-t TARGET_DIR              Specify target directory path
-l {R,RF}, --list {R,RF}   List rules [R] OR rules and filetypes [RF]
-recon                     Detects platform, framework, and programming language used
-estimate                  Estimate efforts required for code review
```

### Example Usage

```
$ python3 dakshscra.py  # To view tool usage along with examples
```

Examples:

- `-f` is optional. If not specified, it will default to the corresponding filetypes of the selected rule.

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
```

### View List of Supported Rules

```
dakshscra.py -l R   # List all supported rule types
```

Currently supported:

- dotnet, php, java, javascript,
- kotlin, python, go, c, cpp,
- android (beta - limited checks), common

---

## Reports

The tool generates reports in three formats: HTML, PDF, and TEXT. Although the HTML and PDF reports are still being improved, they are currently in a reasonably good state. With each subsequent iteration, these reports will continue to be refined and improved even further.

### Scanning (Areas of Security Concerns) Report

- HTML Report:
  - `DakshSCRA/reports/html/report.html`
- PDF Report:
  - `DakshSCRA/reports/html/report.pdf`
- Raw Text Reports:
  - Areas of Interest: `DakshSCRA/reports/text/areas_of_interest.txt`
  - Project Files:     `DakshSCRA/reports/text/filepaths_aoi.txt`
  - Identified Files:  `DakshSCRA/runtime/filepaths.txt`

### Reconnaissance Report

- Text Summary: `DakshSCRA/reports/text/recon.txt`

> Note: Recon report is currently plain text but will be merged into the HTML/PDF report in future versions.

### Effort Estimation Report

- HTML Report: `DakshSCRA/reports/html/estimation.html`

> Note: This feature is in early stage. Future versions will improve the accuracy and add PDF support.

