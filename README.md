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
- **RDL (Rule Description Language):** Conditional rule logic beyond regex — supports `FLAG`, `IF`, `MISSING`, `PRESENT`, `EXISTS`, `&&`, `||`, `!`.
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

> 💡 The virtual environment can be created in any directory — it does not need to be inside the DakshSCRA folder.

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
| common | — |

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

RDL (Rule Description Language) is DakshSCRA's second-pass conditional filter applied **after** a regex match. Every rule can include an optional `<rdl>` block that adds context-aware conditions, significantly reducing false positives without writing separate rules for every edge case.

> RDL is a world-first concept in open-source code scanners — conditional rule logic previously found only in commercial security tools.

#### Operators

RDL conditions are evaluated against the **entire file content** of each matched file, not just the matched line.

| Operator | Behaviour | When to use |
|---|---|---|
| `FLAG:<pattern>` | Anchors the condition — defines what the rule is built around | Always the first clause |
| `IF(condition)` | Match is only reported when this condition is true | Wraps PRESENT / MISSING predicates |
| `PRESENT:<pattern>` | True when the pattern **is** found anywhere in the file | Require a co-occurring risky call |
| `MISSING:<pattern>` | True when the pattern is **not** found anywhere in the file | Suppress when a mitigation is already present |
| `EXISTS:<pattern>` | Like PRESENT but evaluated at file-path level | Check for a related config file |
| `&&` | Both conditions must hold | Require multiple simultaneous conditions |
| `\|\|` | Either condition must hold | Match any one of several conditions |
| `!` | Negation | Invert a predicate |

#### How RDL reduces false positives

| Pattern | Without RDL | With RDL |
|---|---|---|
| `getSharedPreferences()` | Flags every preference access | Only flags when sensitive keys AND no encryption present |
| `loadUrl(someVar)` | Flags hardcoded safe URLs like `about:blank` | Only flags dynamic / interpolated URLs |
| `Room.databaseBuilder()` | Flags DB setup — zero injection risk (100% FP) | Replaced with `@Query` interpolation pattern |
| `System.getenv("SECRET")` | Flags as hardcoded secret (FP) | Suppressed by `MISSING:System.getenv` |

> **File-scope limitation:** PRESENT and MISSING are evaluated against the entire file, not just the matched line. If a mitigation appears *anywhere* in the file, all matches in that file are suppressed — even an unprotected call in the same file. This is a deliberate FP trade-off; the reviewer note on every finding always advises manual confirmation.

#### Example 1 — PHP SQL injection with missing parameterisation

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

Fires when user-controlled input (`$_GET`, `$_POST`, etc.) is present **and** no parameterised query methods are found in the file. A file already using PDO prepared statements is **not** flagged.

#### Example 2 — Android SharedPreferences storing sensitive data without encryption

```xml
<rdl><![CDATA[[FLAG:getSharedPreferences\(][IF(PRESENT:(token|secret|password|auth|session) && MISSING:(EncryptedSharedPreferences|MasterKey|KeyStore|Cipher|encrypt))]]]></rdl>
```

Only fires when the file references sensitive field names **and** no encryption APIs are present. Files using `EncryptedSharedPreferences` are automatically suppressed.

#### Example 3 — Hardcoded secrets excluding environment-variable reads

```xml
<rdl><![CDATA[[FLAG:(api_key|secret|token|password)\s*[:=]\s*"[^"]{8,}"][IF(MISSING:System\.getenv\s*\(|System\.getProperty\s*\(|BuildConfig\. && MISSING:example|sample|dummy|test|placeholder)]]]></rdl>
```

Without this RDL, `TOKEN = "${System.getenv("TOKEN")}"` would be flagged as a hardcoded secret. The MISSING conditions exclude reads from environment variables, build config, and placeholder values.

Supported RDL operators (summary):
- `FLAG:<regex>` — anchor condition in the file context
- `IF(...)` — conditional evaluation
- Predicates: `MISSING:`, `PRESENT:`, `EXISTS:`
- Boolean: `&&`, `||`, `!`

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
