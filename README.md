# Daksh SCRA (Source Code Review Assist)

```
Author:
- Debasis Mohanty (d3basis.m0hanty@gmail.com)
- Twitter / X: @coffeensecurity
- www.coffeeandsecurity.com
```

## About Daksh SCRA

Daksh SCRA (Source Code Review Assist) is built to enhance the efficiency of the source code review process, providing a well-structured and organised approach for code reviewers.

Rather than indiscriminately flagging everything as a potential issue, Daksh SCRA promotes thoughtful analysis, urging the investigation and confirmation of potential problems. This approach mitigates the scramble to tag every potential concern as a bug, cutting back on the confusion and wasted time spent on false positives.

### Debut

Daksh SCRA was initially introduced during a source code review training session at Black Hat USA 2022 (August 6-9), where it was subtly presented to a specific audience. Its official public debut took place at Black Hat USA 2023 in Las Vegas.

## Features and Functionalities

- **Identifies Areas of Interest in Source Code:** Encourages focused investigation and confirmation rather than indiscriminately labelling everything as a bug.
- **Identifies Areas of Interest in File Paths (World's First):** Recognises patterns in file paths to pinpoint relevant sections for review.
- **Software-Level Reconnaissance to Identify Technologies Utilised:** Identifies project technologies, enabling code reviewers to conduct precise scans with appropriate rules.
- **Automated Scientific Effort Estimation for Code Review (World's First):** Provides a measurable approach for estimating the effort required for a code review.
- **Framework-Aware Scanning:** Automatically applies framework-specific rules when the project's framework is detected.
- **Taint Analysis Reports:** Per-platform HTML taint flow reports with hacker-mode and professional-mode themes.
- **RDL (Rule Description Language):** External rule logic referenced with `rdl_ref` and executed by the `core/rdl_engine.py` pipeline - supports file-aware gates, boolean expressions, project observations, and exported logic metadata in reports.
- **Scan State / Resume:** Checkpoint long scans and resume after interruption.
- **Suppression Baseline:** Generate and apply a baseline of known false positives to suppress them from future reports.
- **Web UI:** Browser-based scan launcher with real-time console feed and job artifact browser.

> Active enhancements are ongoing. Multiple new features and improvements are planned for upcoming releases.

Feel free to contribute towards updating or adding new rules and future development.

If you find any bugs, report them to [d3basis.m0hanty@gmail.com](mailto:d3basis.m0hanty@gmail.com).

Detailed documentation: [https://dakshlabs.com/#docs](https://dakshlabs.com/#docs)

---

## Getting Started

There are two ways to run Daksh SCRA - pick whichever fits your workflow:

| | Best for | Jump to |
|---|---|---|
| 🌐 **Web UI (Docker)** | The easiest way to get started - one command, a browser dashboard, live scan progress, and a report/artifact browser. Recommended for most users. | [Web UI (Docker)](#web-ui-docker) |
| 💻 **CLI (Python)** | Scripting, CI pipelines, or running scans without Docker. | [CLI Setup](#cli-setup) |

Both paths run the exact same scanning engine - the Web UI is a browser front end over the same CLI, so results are identical either way.

---

## Web UI (Docker)

The fastest way to run Daksh SCRA is through its browser-based Web UI, launched with a single Docker Compose command. It gives you a scan launcher, a live console feed, and a browsable history of past reports, without needing a local Python environment.

The Docker setup runs the Web UI and the CLI as independent services built from the same image, so you can use either (or both) from the same container.

### Launch the Web UI

Foreground mode (logs stream to your terminal):

```bash
docker compose up --build
```

Detached / background mode:

```bash
docker compose up --build -d
```

Then open [http://localhost:8080](http://localhost:8080).

To use a different port:

```bash
DAKSH_PORT=9090 docker compose up
```

Stop the stack with:

```bash
docker compose down
```

### Logging in

The Web UI requires an account. On first startup, an initial admin account is created from `DAKSH_ADMIN_USERNAME` / `DAKSH_ADMIN_PASSWORD` (set these in `.env`); if `DAKSH_ADMIN_PASSWORD` is left unset, a random password is generated and printed once to the API's startup log - save it, since it cannot be recovered afterward.

You'll be required to set your own password (and, optionally, username) the first time you log in. An admin account can create further accounts via the `POST /api/v1/auth/users` API endpoint (no dedicated UI for this yet). See `.env.example` for the full list of authentication-related settings (session lifetime, cookie security, CORS).

### What you get

- Responsive command builder for scan, recon, estimate, recon+estimate, list, and PDF-from-JSON modes
- Real-time console feed and live per-stage progress during execution
- Per-job artifact snapshots for HTML / PDF / JSON outputs
- Fast in-browser navigation across run form, live feed, artifacts, and recent jobs
- Built-in directory browser for selecting target paths (OS-aware: Windows, macOS, Linux / Docker)

Under the hood, the CLI remains the source of truth - it does all the scanning and generates every HTML / PDF / JSON output. The Web UI runs one active job at a time and snapshots each completed job's outputs into `runtime/webui/jobs/<job-id>/artifacts/` so past reports stay accessible.

### Running the CLI in Docker

You don't need a local Python environment to use the CLI either - it's available as its own Compose service, built from the same image:

```bash
docker compose run --rm cli -h
docker compose run --rm cli -r auto -t /scan-targets/path/to/source
```

### What's in the image

- FastAPI backend + Web UI frontend
- The full Daksh SCRA CLI, as a separate service
- Playwright Chromium, for PDF generation
- Persistent `reports/` and `runtime/` volumes
- Host path mounts so scans can reach source trees from inside the container

**Key mount points:**

| Mount | Path inside container |
|---|---|
| Project source | `/app` |
| Default scan root | `/scan-targets` |
| Host drive aliases | `/host`, `/host/c`, `/host/d` |
| WSL mounts | `/mnt`, `/run/desktop/mnt/host` |

**Environment variables** (configure in `.env`):

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
| `DAKSH_ADMIN_USERNAME` | Initial admin username (default: `admin`) |
| `DAKSH_ADMIN_PASSWORD` | Initial admin password - strongly recommended to set explicitly |

Copy `.env.example` to `.env` and set the paths and credentials for your machine before running Docker.

---

## CLI Setup

Prefer running Daksh SCRA directly with Python? Here's how to set it up locally.

### Pre-requisites

- Python 3.8+
- All libraries listed in `requirements.txt`

### 1. Download Daksh SCRA

```bash
git clone https://github.com/coffeeandsecurity/DakshSCRA.git
```

Or download the latest zip from [https://github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) and unzip it.

### 2. Set Up a Virtual Environment

> 💡 The virtual environment can be created in any directory - it does not need to be inside the DakshSCRA folder.

**Option A: One-step setup (recommended)**

```bash
python setup_env.py
```

This script creates the virtual environment, installs all dependencies, and installs Playwright's Chromium browser (required for PDF export).

**Option B: Manual setup**

Windows:
```bash
python -m venv daksh-env
.\daksh-env\Scripts\activate
```

macOS / Linux:
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

## CLI Usage

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

### Supported Platform Rules and Frameworks

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

RDL (Rule Description Language) is DakshSCRA's externalized rule-logic layer. In the current architecture:

- XML rules remain the rule inventory and carry metadata such as `name`, `regex`, descriptions, and optional `scan_config`.
- RDL logic is executed by [`core/rdl_engine.py`](core/rdl_engine.py).
- Rule logic files live under `rules/scanning/logic/...` and are referenced from XML using `<rdl_ref>`.
- `rdl_ref` values are resolved relative to `rules/scanning/`, for example:
  `logic/php/core/some_rule.rdl` -> `rules/scanning/logic/php/core/some_rule.rdl`
- Logic outcomes are exported into report JSON as metadata such as `logic_engine`, `logic_source`,
  `logic_reason`, `logic_trace`, `logic_consulted_files`, and `logic_outcome`.

The older inline `<rdl>` form is no longer the active architecture and should not be used for new rules.

#### RDL architecture at a glance

```text
XML rule
  -> regex / exclude / scan_config / descriptions
  -> rdl_ref
       -> rules/scanning/logic/<platform>/<scope>/<rule>.rdl
           -> core/rdl_engine.py
               -> pass / fail
               -> reason / fail_reason
               -> trace / consulted_files / outcome
```

#### Scan sequence

For a source rule, DakshSCRA evaluates logic in this order:

1. Recon selects matching platforms and frameworks.
2. The XML rule is loaded from `rules/scanning/platform/...`.
3. `regex` finds candidate lines or whole-file matches when present.
4. `exclude` removes obvious noise for that rule, if present.
5. The external `.rdl` file from `rdl_ref` is evaluated against the current file text, current file path, and project root.
6. If the RDL script passes, DakshSCRA keeps the finding and merges exported logic metadata into the report output.
7. If the RDL script fails, the match is suppressed with the RDL fail reason and decision trace metadata.

For file-path rules in `filepaths.xml`, the same `rdl_ref` model applies, but the matching subject is
the normalized relative path instead of source code text. In that mode, RDL receives the relative path
string as the current-file text and path context.

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

#### Current layout

```text
rules/
└── scanning/
    ├── platform/
    │   ├── php/php.xml
    │   ├── java/java.xml
    │   └── ...
    └── logic/
        ├── common/core/
        ├── php/core/
        ├── php/framework/laravel/
        ├── mobile/android/core/
        ├── filepaths/core/
        └── ...
```

#### Execution semantics

- `WHEN PRESENT`, `WHEN MISSING`, and `WHEN CURRENT_FILE_MATCHES` evaluate against the current file text.
- `WHEN FILE_NAME_IS` and `WHEN FILE_PATH_MATCHES` evaluate against the current file path context.
- `WHEN EXPR` supports boolean logic over `PRESENT:`, `MISSING:`, and `EXISTS:` predicates.
- `OBSERVE PROJECT_HAS_GLOB ... AS ...` does not gate the finding; it records related project files in trace metadata.
- `REPORT AS`, `REASON`, `FAIL_REASON`, and `TRACE` control the exported reporting metadata.
- Regex tokens can be written either as raw patterns or as `/pattern/flags`, with `i`, `m`, and `s` supported.

#### Supported RDL commands

| Command | Behaviour | Typical use |
|---|---|---|
| `WHEN PRESENT <regex>` | Require a pattern to exist in the current file text | Require a co-occurring risky API or sensitive field |
| `WHEN MISSING <regex>` | Require a pattern to be absent from the current file text | Suppress when mitigation already exists |
| `WHEN EXPR <expr>` | Evaluate boolean expressions using `PRESENT:` / `MISSING:` / `EXISTS:` with `&&`, `||`, `!` | Express compact risk gates |
| `WHEN CURRENT_FILE_MATCHES <regex>` | Match against the full current file text | Re-check complex whole-file conditions |
| `WHEN FILE_NAME_IS <name>` | Require the current filename to match exactly | Limit plist / manifest / config rules |
| `WHEN FILE_PATH_MATCHES <glob>` | Require the current relative path to match a glob | Narrow framework/config path rules |
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
- Prefer `rdl_ref` for all rule logic and keep the `.rdl` file beside the appropriate platform/framework logic tree.
- Do not add new inline `<rdl>` blocks.
- Use `WHEN PRESENT` / `WHEN MISSING` for simple gates and `WHEN EXPR` only when the logic is genuinely boolean.
- Put reviewer-facing reasoning in `REASON` and suppression explanations in `FAIL_REASON`.
- Treat `PRESENT` and `MISSING` as whole-file checks. A mitigation anywhere in the file can suppress every match from that file.
- Use `OBSERVE PROJECT_HAS_GLOB` to enrich findings with project context, not as a pass/fail gate.
- Keep `logic/...` paths stable and platform-scoped so XML rules remain thin and the logic layer stays reusable.

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

When running via the Web UI, each job's outputs are additionally snapshotted under `runtime/webui/jobs/<job-id>/artifacts/` (see [Web UI (Docker)](#web-ui-docker)).

---

## Author

| | |
|---|---|
| Website | [coffeeandsecurity.com](https://www.coffeeandsecurity.com) |
| Email | d3basis.m0hanty@gmail.com |
| Twitter / X | [@coffeensecurity](https://x.com/coffeensecurity) |
| Source | [github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) |
| License | GNU General Public License v3.0 (GPL-3.0) |

If DakshSCRA has helped your team save significant time, effort, or cost, reduced dependence on expensive commercial tools, improved review coverage, or made code review more structured and effective, feel free to reach out and share your experience. I am always open to thoughtful feedback and interesting conversations.

Found a bug or want to contribute? Open an issue or pull request on GitHub.
