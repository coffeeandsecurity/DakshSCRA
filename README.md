# Daksh SCRA (Source Code Review Assist)

```
Author:
- Debasis Mohanty (d3basis.m0hanty@gmail.com)
- Twitter / X: @coffeensecurity
- www.coffeeandsecurity.com
```

## About Daksh SCRA

Daksh SCRA (Source Code Review Assist) tool is built to enhance the efficiency of the source code review process, providing a well-structured and organised approach for code reviewers.

Rather than indiscriminately flagging everything as a potential issue, Daksh SCRA promotes thoughtful analysis, urging the investigation and confirmation of potential problems. This approach mitigates the scramble to tag every potential concern as a bug, cutting back on the confusion and wasted time spent on false positives.

## Debut

Daksh SCRA was initially introduced during a source code review training session at Black Hat USA 2022 (August 6-9), where it was subtly presented to a specific audience. Its official public debut took place at Black Hat USA 2023 in Las Vegas.

## Features and Functionalities

### Distinctive Features

- **Identifies Areas of Interest in Source Code:** Encourage focused investigation and confirmation rather than indiscriminately labelling everything as a bug.
- **Identifies Areas of Interest in File Paths (World's First):** Recognises patterns in file paths to pinpoint relevant sections for review.
- **Software-Level Reconnaissance to Identify Technologies Utilised:** Identifies project technologies, enabling code reviewers to conduct precise scans with appropriate rules.
- **Automated Scientific Effort Estimation for Code Review (World's First):** Providing a measurable approach for estimating efforts required for a code review process.
- **Framework-Aware Scanning:** Automatically applies framework-specific rules when the project's framework is detected.
- **Taint Analysis Reports:** Per-platform HTML taint flow reports with hacker-mode and professional-mode themes.
- **RDL (Rule Description Language):** External rule logic referenced with `rdl_ref` - supports `WHEN PRESENT`, `WHEN MISSING`, `WHEN EXPR`, `UNLESS`, `OBSERVE`, project-aware checks, and explicit report/suppression reasons.
- **Scan State / Resume:** Checkpoint long scans and resume after interruption.
- **Suppression Baseline:** Generate and apply a baseline of known false positives to suppress them from future reports.
- **Web UI:** Browser-based scan launcher with real-time console feed and job artifact browser.

> Active enhancements are ongoing. Multiple new features and improvements are planned for upcoming releases.

Feel free to contribute towards updating or adding new rules and future development.

If you find any bugs, report them to [d3basis.m0hanty@gmail.com](mailto:d3basis.m0hanty@gmail.com).

Detailed documentation: [https://dakshlabs.com/#docs](https://dakshlabs.com/#docs)

---

## Tool Setup

### Pre-requisites

- Python 3.8+
- All libraries listed in `requirements.txt`

### 1. Download Daksh SCRA

```bash
git clone https://github.com/coffeeandsecurity/DakshSCRA.git
```

Or download the latest zip from [https://github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) and unzip it.

### 2. Setup a Virtual Environment

> 💡 The virtual environment can be created in any directory - it does not need to be inside the DakshSCRA folder.

#### Option A: One-Step Setup (Recommended)

```bash
python setup_env.py
```

This script creates the virtual environment, installs all dependencies, and installs Playwright's Chromium browser (required for PDF export).

#### Option B: Manual Setup

**Windows:**
```bash
python -m venv daksh-env
.\daksh-env\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv daksh-env
source daksh-env/bin/activate
```

Then install dependencies:
```bash
cd path/to/DakshSCRA
pip install -r requirements.txt
playwright install chromium
```

---

## Tool Usage

Use `python` inside a virtual environment, or `python3` outside one.

### Command-Line Options

```
usage: dakshscra.py [-h] [-r RULES] [-f FILE_TYPES] [-v] [-t TARGET_DIR]
                    [-l {R,RF}] [--recon] [--rs] [--estimate]
                    [-rpt FORMATS] [--pdf-from-json]
                    [--json-input-dir PATH] [--pdf-output PATH]
                    [--pdf-multi-dir PATH] [--pdf-single-only]
                    [--skip-analysis] [--loc]
                    [--baseline-file PATH] [--baseline-generate] [--no-baseline]
                    [--review-config PATH]
                    [--resume-scan] [--state-file PATH] [--no-state] [--state]
```

| Option | Description |
|---|---|
| `-r RULES` | Platform rules (e.g. `php`, `java`, `php,java`) or `auto` for auto-detection |
| `-f FILE_TYPES` | Override default filetypes for scanning |
| `-v` | Verbosity level (`-v`, `-vv`, `-vvv`) |
| `-t TARGET_DIR` | Target source code directory |
| `-l {R,RF}` | List platform rules + frameworks `[R]` or include filetypes `[RF]` |
| `--recon` | Run reconnaissance (platform / framework / language detection) |
| `--rs`, `--recon-strict` | Strict recon: high-confidence detections only (use with `--recon`) |
| `--estimate` | Estimate code review effort based on codebase size |
| `-rpt`, `--report FORMATS` | Report formats: `html`, `pdf`, or `html,pdf` (default: `html`) |
| `--pdf-from-json` | Generate PDF report(s) from existing JSON outputs without re-scanning |
| `--json-input-dir PATH` | JSON report directory (default: `./reports/data`) |
| `--pdf-output PATH` | Single PDF output path (default: `./reports/scan/pdf/report.pdf`) |
| `--pdf-multi-dir PATH` | Multi-file PDF output directory (default: `./reports/scan/pdf/multi-file`) |
| `--pdf-single-only` | Generate only the combined single-file PDF; skip per-platform multi-file set |
| `--skip-analysis` | Disable the analyzer stage for this run |
| `--loc` | Count effective lines of code |
| `--baseline-file PATH` | Suppression baseline file (JSON) |
| `--baseline-generate` | Generate suppression baseline from current findings |
| `--no-baseline` | Disable baseline suppression for this run |
| `--review-config PATH` | Findings triage file (JSON); suppress previously reviewed false positives from reports |
| `--resume-scan` | Resume a previously interrupted scan from state file |
| `--state-file PATH` | Custom scan state / checkpoint file path |
| `--no-state` | Disable scan state checkpointing for this run |
| `--state` | Force enable scan state checkpointing for this run |

### Example Usage

> `-f` (file types) is optional. If not specified, DakshSCRA uses the default filetypes for the selected platform(s).

```bash
# Single platform scan
python dakshscra.py -r php -t /path/to/source

# Multiple platforms
python dakshscra.py -r php,java,cpp -t /path/to/source

# Auto-detect platform and apply matching rules
python dakshscra.py -r auto -t /path/to/source

# Override filetypes
python dakshscra.py -r php -f dotnet -t /path/to/source

# Reconnaissance only (no scanning)
python dakshscra.py --recon -t /path/to/source

# Reconnaissance + scanning
python dakshscra.py --recon -r php -t /path/to/source

# Strict recon (high-confidence detections only)
python dakshscra.py --recon --rs -t /path/to/source

# Effort estimation
python dakshscra.py --estimate -t /path/to/source

# Scan with HTML + PDF report output
python dakshscra.py -r auto -t /path/to/source -rpt html,pdf

# Verbosity levels
python dakshscra.py -r php -v -t /path/to/source     # default
python dakshscra.py -r php -vvv -t /path/to/source   # show all pattern checks

# Generate suppression baseline from current findings
python dakshscra.py -r auto -t /path/to/source --baseline-generate

# Apply suppression baseline (suppress known FPs)
python dakshscra.py -r auto -t /path/to/source --baseline-file config/suppressions.json

# Disable baseline for this run
python dakshscra.py -r auto -t /path/to/source --no-baseline

# Apply findings triage / review config
python dakshscra.py -r auto -t /path/to/source --review-config config/review.json

# Scan with checkpoint state enabled
python dakshscra.py -r auto -t /path/to/source --state

# Resume an interrupted scan
python dakshscra.py -r auto -t /path/to/source --resume-scan

# Resume with a custom state file
python dakshscra.py -r auto -t /path/to/source --resume-scan --state-file runtime/scan_state.json

# Generate PDF from existing JSON outputs (no re-scan)
python dakshscra.py --pdf-from-json

# Generate PDF from a custom JSON directory
python dakshscra.py --pdf-from-json --json-input-dir ./custom/reports/data

# Custom output paths for PDF
python dakshscra.py --pdf-from-json --pdf-output ./reports/scan/pdf/custom.pdf --pdf-multi-dir ./reports/scan/pdf/multi-file

# Single combined PDF only (skip per-platform set)
python dakshscra.py --pdf-from-json --pdf-single-only
```

### View Supported Platform Rules and Frameworks

```bash
python dakshscra.py -l R    # List platform rules and framework mappings
python dakshscra.py -l RF   # List platform rules, framework mappings, and filetypes
```

Current supported platforms and framework mappings:

| Platform | Frameworks |
|---|---|
| dotnet | aspnetcore, entityframework |
| php | codeigniter, drupal, laravel, symfony, wordpress |
| java | hibernate, spring, springboot |
| javascript | angular, express, nestjs, nextjs, react, vue |
| kotlin | ktor, springkotlin |
| python | django, fastapi, flask |
| go | echo, fiber, gin |
| c | freertos |
| cpp | boost, qt |
| android | cordova-android, flutter-android, ionic-android, jetpack, nativescript-android, reactnative-android, xamarin-android |
| ios | cordova-ios, flutter-ios, ionic-ios, nativescript-ios, reactnative-ios, swiftui, uikit, xamarin-ios |
| reactnative | reactnative |
| flutter | flutter |
| xamarin | xamarin |
| ionic | ionic |
| nativescript | nativescript |
| cordova | cordova |
| ruby | rails, sinatra |
| rust | actix, axum, rocket |
| common | - |

To get the latest supported platforms and frameworks, always run:

```bash
python dakshscra.py -l R
```

---

## Configuration Reference

### `config/tool.yaml`

Daksh SCRA runtime defaults are controlled through `config/tool.yaml`.

```yaml
state_management:
  enabled: false
  resume_mode: manual
  persist_after_seconds: 300
  persist_interval_seconds: 30
  default_state_file: runtime/scan_state.json
  cleanup_on_success: false

analysis:
  run_by_default: true
  include_frameworks: true
  report_theme: hacker_mode
```

**Analyzer config options:**

- `analysis.run_by_default`
  - `true`: analyzer runs automatically during scan
  - `false`: analyzer disabled unless re-enabled in config or via CLI
- `analysis.include_frameworks`
  - `true`: include framework-level analyzer entries where framework detection exists
  - `false`: platform-level analyzer output only
- `analysis.report_theme`
  - `hacker_mode`: dark high-contrast modern analyzer theme (default)
  - `professional_mode`: light modern analyzer theme
  - `both`: generate both theme variants side-by-side

### RDL Rule Authoring

RDL (Rule Description Language) is DakshSCRA's file-aware rule logic layer. The current engine uses
external `.rdl` files referenced from XML with `<rdl_ref>.../rule_name.rdl</rdl_ref>`. The older
inline `<rdl>` form is retired.

#### Scan sequence

For a source rule, DakshSCRA evaluates logic in this order:

1. Recon selects matching platforms and frameworks.
2. The XML rule is loaded from `rules/scanning/platform/...`.
3. `regex` finds candidate lines or file-level matches.
4. `exclude` removes obvious noise for that rule, if present.
5. The external `.rdl` file from `rdl_ref` is evaluated against the current file and, when needed, the project root.
6. If the RDL script passes, the finding is reported. If it fails, the match is suppressed with the RDL fail reason and trace metadata.

For file-path rules in `filepaths.xml`, the same `rdl_ref` model applies, but the matching subject is
the normalized relative path instead of source code text.

#### Current rule structure

```xml
<rule>
  <name>Rule Name</name>
  <regex><![CDATA[regex_to_match]]></regex>
  <rdl_ref>logic/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
  <exclude><![CDATA[pattern_to_exclude_lines]]></exclude>  <!-- optional -->
  <scan_config>...</scan_config>                           <!-- optional -->
  <rule_desc>Short description of what the rule detects.</rule_desc>
  <vuln_desc>Why the pattern matters.</vuln_desc>
  <developer>Fix guidance for developers.</developer>
  <reviewer>Manual confirmation guidance for reviewers.</reviewer>
</rule>
```

#### Current `.rdl` structure

```text
VERSION 1
WHEN PRESENT /\\b(?:mysql_query|mysqli_query|->query)\\s*\\(/i
WHEN EXPR PRESENT:\\$_(GET|POST|REQUEST|COOKIE) && MISSING:\\b(?:prepare|bindParam|bindValue|PDO::prepare)\\b
REPORT AS area_of_interest
REASON SQL query execution appears reachable without parameterisation in this file.
FAIL_REASON Matching query API was found, but the file also contains prepared-statement indicators.
TRACE SQLi gate: input source present and mitigation missing.
```

#### Supported RDL commands

| Command | Behaviour | Typical use |
|---|---|---|
| `WHEN PRESENT <regex>` | Require a pattern to exist in the current file text | Require a co-occurring risky API or sensitive field |
| `WHEN MISSING <regex>` | Require a pattern to be absent from the current file text | Suppress when mitigation already exists |
| `WHEN EXPR <expr>` | Evaluate boolean expressions using `PRESENT:` / `MISSING:` / `EXISTS:` with `&&`, `||`, `!` | Express compact risk gates |
| `WHEN CURRENT_FILE_MATCHES <regex>` | Match against the full current file text | Re-check complex whole-file conditions |
| `WHEN FILE_NAME_IS <name>` | Require the current filename to match exactly | Limit plist / manifest / config rules |
| `WHEN FILE_PATH_MATCHES <glob>` | Require the current relative path to match a glob | Narrow framework/config path rules |
| `UNLESS PRESENT <regex>` | Fail when a safe pattern is present | Early mitigation exclusion |
| `UNLESS CURRENT_FILE_MATCHES <regex>` | Fail when the whole file matches an exclusion pattern | Block known-safe structural cases |
| `OBSERVE PROJECT_HAS_GLOB <glob> AS <label>` | Record related project files in trace metadata | Surface supporting config or companion files |
| `REPORT AS <outcome>` | Set the rule outcome, usually `area_of_interest` | Future-proof explicit outcomes |
| `REASON <text>` | Reason shown when the rule passes | Explain why the finding stayed visible |
| `FAIL_REASON <text>` | Reason shown when the rule suppresses a match | Explain why the hit was filtered |
| `TRACE <text>` | Add debug/decision trace lines | Migration/debugging support |

Boolean expressions in `WHEN EXPR` support:
- `PRESENT:<regex>`
- `MISSING:<regex>`
- `EXISTS:<regex>`
- `&&`, `||`, `!`, and parentheses

#### Example 1 - PHP SQL injection gating

XML rule:

```xml
<rule>
  <name>Possible SQL Injection in Query Execution</name>
  <regex><![CDATA[(?i)\b(?:mysql_query|mysqli_query|->query)\s*\(]]></regex>
  <rdl_ref>logic/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
  <rule_desc>...</rule_desc>
</rule>
```

External RDL:

```text
VERSION 1
WHEN PRESENT /\b(?:mysql_query|mysqli_query|->query)\s*\(/i
WHEN EXPR PRESENT:\$_(GET|POST|REQUEST|COOKIE) && MISSING:\b(?:prepare|bindParam|bindValue|PDO::prepare)\b
REPORT AS area_of_interest
REASON Query execution appears to rely on direct input without parameterisation.
FAIL_REASON Query API matched, but parameterised query indicators were also found in the file.
```

#### Example 2 - Android manifest rule with file-aware checks

XML rule:

```xml
<rule>
  <name>Exported Components Without Permission</name>
  <regex><![CDATA[<(?P<component>activity|service|receiver|provider)\s[^>]*android:name="(?P<name>[^"]+)"[^>]*android:exported="true"[^>]*(?:/>|>)]]></regex>
  <rdl_ref>logic/mobile/android/core/exported_components.rdl</rdl_ref>
  <scan_config>...</scan_config>
</rule>
```

External RDL:

```text
VERSION 1
WHEN FILE_NAME_IS AndroidManifest.xml
WHEN CURRENT_FILE_MATCHES /android:exported\s*=\s*"true"/i
WHEN MISSING /android:permission\s*=\s*"/i
REPORT AS area_of_interest
REASON Exported component appears reachable without a permission guard.
```

#### Example 3 - File-path area-of-interest rule

XML rule:

```xml
<rule>
  <name>Admin Section File Path</name>
  <regex><![CDATA[(?i)(^|/)(admin|administrator|root)(/|$)]]></regex>
  <rdl_ref>logic/filepaths/core/admin_section.rdl</rdl_ref>
</rule>
```

External RDL:

```text
VERSION 1
WHEN CURRENT_FILE_MATCHES /(^|\/)(admin|administrator|root)(\/|$)/i
UNLESS CURRENT_FILE_MATCHES /(^|\/)(tests?|docs?|samples?|examples?)(\/|$)/i
REPORT AS area_of_interest
REASON File path suggests privileged application functionality.
FAIL_REASON Path matched an excluded documentation or sample location.
```

#### Authoring guidance

- Keep `regex` broad enough to catch candidates, then use RDL to filter context.
- Prefer `rdl_ref` for all rule logic; do not add new inline `<rdl>` blocks.
- Use `WHEN PRESENT` / `WHEN MISSING` for simple gates and `WHEN EXPR` only when the logic is genuinely boolean.
- Put reviewer-facing reasoning in `REASON` and suppression explanations in `FAIL_REASON`.
- Treat `PRESENT` and `MISSING` as whole-file checks. A mitigation anywhere in the file can suppress every match from that file.

---

## Report Output Structure

All outputs are written under the `reports/` directory:

```
reports/
├── scan/
│   ├── html/
│   │   ├── report.html                 # Single-file HTML scan report
│   │   └── multi-file/                 # Per-platform HTML report set
│   ├── pdf/
│   │   ├── report.pdf                  # Single-file PDF scan report
│   │   └── multi-file/                 # Per-platform PDF report set
│   ├── recon/
│   │   └── reconnaissance.html         # Reconnaissance HTML report
│   └── estimate/
│       └── estimation.html             # Effort estimation HTML report
├── analysis/
│   └── <platform>/
│       ├── analysis.html               # Taint analysis report (default theme)
│       ├── analysis_professional.html  # Professional theme (if theme=both)
│       ├── analysis_xref.html          # Cross-reference report
│       └── analysis.json               # Structured analysis data
└── data/
    ├── areas_of_interest.json          # AoI findings
    ├── filepaths_aoi.json              # File path AoI findings
    ├── summary.json                    # Scan summary
    ├── recon.json                      # Recon summary
    └── analysis.json                   # Analyzer output
```

Runtime files (scan state, logs, inventory) are written under `runtime/`.

---

## Web UI

Daksh SCRA includes a browser-based frontend for launching scans and watching progress in real time.

```bash
docker compose up --build
```

Then open: [http://localhost:8080](http://localhost:8080)

**Web UI capabilities:**

- Responsive command builder for scan, recon, estimate, recon+estimate, list, and PDF-from-JSON modes
- Real-time console feed during execution
- Per-job artifact snapshots for HTML / PDF / JSON outputs
- Fast in-browser navigation across run form, live feed, artifacts, and recent jobs
- Built-in directory browser for selecting target paths (OS-aware: Windows, macOS, Linux / Docker)

**Execution model:**

- The CLI remains the source of truth and generates all HTML / PDF / JSON outputs
- The web UI supports one active job at a time (the CLI writes to shared `runtime/` and `reports/` paths)
- Completed jobs snapshot outputs into `runtime/webui/jobs/<job-id>/artifacts/` so previous reports stay accessible

---

## Docker

The Docker setup supports web UI and CLI independently using separate Compose services built from the same image.

**Launch the web UI:**

```bash
docker compose up --build
```

Then open: [http://localhost:8080](http://localhost:8080)

**Run the CLI in Docker:**

```bash
docker compose run --rm cli -h
docker compose run --rm cli -r auto -t /scan-targets/path/to/source
```

**Stop the stack:**

```bash
docker compose down
```

**What Docker includes:**

- FastAPI + web frontend
- Full Daksh SCRA CLI as a separate service
- Playwright Chromium for PDF generation
- Persistent `reports/` and `runtime/` volumes
- Host path mounts so scans can reach source trees from inside the container

**Key mount points:**

| Mount | Path inside container |
|---|---|
| Project source | `/app` |
| Default scan root | `/scan-targets` |
| Host drive aliases | `/host`, `/host/c`, `/host/d` |
| WSL mounts | `/mnt`, `/run/desktop/mnt/host` |

**Environment variables (configure in `.env`):**

| Variable | Description |
|---|---|
| `DAKSH_PORT` | Web UI port (default: `8080`) |
| `DAKSH_SCAN_ROOT` | Default target directory inside the container |
| `DAKSH_HOST_SOURCE` | Host path to mount as `/scan-targets` (default: `/tmp`) |
| `DAKSH_HOST_MOUNT` | Additional host mount root |
| `DAKSH_HOST_C` | Windows C: drive path (WSL) |
| `DAKSH_HOST_D` | Windows D: drive path (WSL) |
| `DAKSH_DESKTOP_MOUNT` | WSL desktop mount path |
| `DAKSH_BROWSE_ROOTS` | Override directory browser roots (comma-separated) |

Copy `.env.example` to `.env` and set the paths for your machine before running Docker.

---

## Author

| | |
|---|---|
| Website | [coffeeandsecurity.com](https://www.coffeeandsecurity.com) |
| Email | d3basis.m0hanty@gmail.com |
| Twitter / X | [@coffeensecurity](https://x.com/coffeensecurity) |
| Source | [github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) |
| License | GNU General Public License v3.0 (GPL-3.0) |

Found a bug or want to contribute? Open an issue or pull request on GitHub.
