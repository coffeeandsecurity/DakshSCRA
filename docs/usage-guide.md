# DakshSCRA Usage Guide

## Contents

1. [What is DakshSCRA?](#what-is-dakshscra)
2. [Installation](#installation)
3. [CLI Usage](#cli-usage)
   - [Syntax](#syntax)
   - [Scan Options](#scan-options)
   - [Mode Options](#mode-options)
   - [Output Options](#output-options)
   - [Advanced Options](#advanced-options)
   - [CLI Examples](#cli-examples)
   - [Output Structure](#output-structure)
4. [Web UI Usage](#web-ui-usage)
   - [Starting the Web UI](#starting-the-web-ui)
   - [Dashboard](#dashboard)
   - [Projects](#projects)
   - [Scans & Findings](#scans--findings)
   - [Understanding Findings](#understanding-findings)
   - [Reports & Artifacts](#reports--artifacts)
5. [Platforms & Rules](#platforms--rules)
6. [Findings Reference](#findings-reference)
7. [PDF Reports](#pdf-reports)
8. [Tips & Common Patterns](#tips--common-patterns)

---

## What is DakshSCRA?

DakshSCRA (Source Code Review Assist) is a security-focused static analysis tool built to support manual code review engagements. It helps surface areas of interest in source code through rule-based pattern matching, technology stack reconnaissance, and dataflow taint analysis.

It is a tool for reviewers, not a replacement for one. The goal is to cut down on manual triage time by pointing out relevant code patterns, inter-file data flows, and effort estimates, so the reviewer can focus on what actually matters.

### Distinctive Features

DakshSCRA introduced several capabilities that were first-of-their-kind in open source code review tooling at the time of release (Black Hat USA 2022/2023).

| Feature | Why it matters |
|---|---|
| **File path areas of interest** *(World's First)* | Scans file and directory names themselves - not just code - to flag suspicious paths like backup files, debug endpoints, config dumps, and credential files that reviewers often miss |
| **Scientific effort estimation** *(World's First)* | Produces a quantified, defensible estimate of how long a manual review will take based on codebase size, file count, and finding volume - not a guess |
| **Areas of interest, not bug flags** | Surfaces patterns worth investigating rather than tagging everything as a vulnerability. Reduces false-positive noise and keeps the reviewer in control |
| **Software reconnaissance** | Detects languages, frameworks, and infrastructure from file contents and structure before scanning, so the right rules get applied automatically |
| **Cross-file taint analysis** | Traces user-controlled data from source to sink across file boundaries, not just within a single file |
| **RDL conditional rules** | Rules can include conditional logic (`FLAG`, `IF`, `MISSING`, `PRESENT`) beyond simple regex, allowing context-aware pattern matching |

DakshSCRA was first introduced at **Black Hat USA 2022** and publicly debuted at **Black Hat USA 2023** in Las Vegas.

### What it does

| Capability | Description |
|---|---|
| **Rule-based scanning** | Matches platform-specific patterns (SQL queries, command execution, file I/O, etc.) against source files |
| **Reconnaissance** | Detects languages, frameworks, and technology stack from file contents and structure |
| **Taint analysis** | Traces data flows from user-controlled sources to security-sensitive sinks across files |
| **Effort estimation** | Estimates manual review time based on codebase size, complexity, and finding volume |
| **Report generation** | Produces HTML reports (single-file and per-platform multi-file) and optionally PDF |

---

## Installation

### Requirements

- Python 3.9 or later
- pip

### Setup

```bash
git clone <repo>
cd DakshSCRA
python3.9 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium        # Required for PDF generation only
```

### Docker (Web UI)

```bash
docker compose up --build
```

Open `http://localhost:8080`

---

## CLI Usage

### Syntax

```
python dakshscra.py [SCAN OPTIONS] [MODE OPTIONS] [OUTPUT OPTIONS] [ADVANCED OPTIONS]
```

Run with no arguments to see the full help:

```bash
python dakshscra.py
```

---

### Scan Options

These options control what to scan and how.

| Option | Description |
|---|---|
| `-r RULES` | Platform rules to apply. Comma-separated (e.g. `php,java`) or `auto` for automatic detection. |
| `-f FILE_TYPES` | Override default file extensions for the selected platform. |
| `-t TARGET_DIR` | Path to the source code directory to scan. |
| `-v` / `-vv` / `-vvv` | Verbosity level. Higher levels show more detail during scanning. |

#### The `-r auto` mode

When `-r auto` is used, DakshSCRA detects which languages and frameworks are present in the target directory, then applies the matching platform rules automatically. A good starting point when the codebase is unfamiliar.

```bash
python dakshscra.py -r auto -t ./codebase
```

---

### Mode Options

Modes change *what* the tool does during a run. Multiple modes can be combined.

| Option | Description |
|---|---|
| `--recon` | Run technology stack reconnaissance. Detects languages, frameworks, libraries, and infrastructure clues. Can be used alone or alongside `-r` for scanning. |
| `--rs` / `--recon-strict` | Filter recon output to high-confidence detections only. Use with `--recon` to reduce noise on large or generic codebases. |
| `--estimate` | Generate a manual review effort estimation report based on codebase size and finding volume. |
| `--pdf-from-json` | Generate PDF reports from existing JSON output without re-running a scan. Useful after a completed scan when PDF was not initially requested. |
| `-l {R,RF}` | List available platform rules. `R` lists rules, `RF` also lists associated file types. |

#### Combining modes

```bash
# Recon + scan + estimate in one pass
python dakshscra.py --recon --estimate -r php -t ./app

# Recon only, no scanning
python dakshscra.py --recon -t ./app

# Recon with strict filtering
python dakshscra.py --recon --rs -t ./app

# Scan with auto detection
python dakshscra.py -r auto --recon -t ./app
```

---

### Output Options

| Option | Default | Description |
|---|---|---|
| `-rpt FORMATS` | `html` | Report formats to generate. Values: `html`, `pdf`, or `html,pdf`. PDF requires Playwright/Chromium. |
| `--json-input-dir PATH` | `./reports/data` | JSON input directory for `--pdf-from-json` mode. |
| `--pdf-output PATH` | `./reports/scan/pdf/report.pdf` | Custom output path for the single combined PDF. |
| `--pdf-multi-dir PATH` | `./reports/scan/pdf/multi-file` | Custom output directory for the per-platform PDF set. |
| `--pdf-single-only` | off | Generate only the combined single PDF; skip the per-platform multi-file PDF set. Applies to both scan and `--pdf-from-json` mode. |

**Note:** PDF is not generated by default. At the end of any scan that did not produce a PDF, the tool prints a reminder with the exact command to generate one afterwards.

---

### Advanced Options

| Option | Description |
|---|---|
| `--skip-analysis` | Disable the taint analysis stage for this run. Scanning and recon still run normally. |
| `--loc` | Count effective lines of code (may add scan time). Included in effort estimation. |
| `--baseline-file PATH` | Path to a suppression baseline JSON file. |
| `--baseline-generate` | Generate a new suppression baseline from current findings. |
| `--no-baseline` | Ignore the baseline suppression file for this run. |
| `--resume-scan` | Resume a previously interrupted scan from its last saved checkpoint. |
| `--review-config PATH` | Apply a findings triage file (JSON). Previously reviewed false positives and suppressed findings will be excluded from generated reports. |
| `--state-file PATH` | Custom path for the scan state/checkpoint file. |
| `--no-state` | Disable scan state checkpointing for this run. |
| `--state` | Force enable scan state checkpointing for this run. |

---

### CLI Examples

```bash
# Basic PHP scan
python dakshscra.py -r php -t ./src

# Multi-platform scan with verbose output
python dakshscra.py -r php,java -vv -t /path/to/code

# Auto-detect and scan
python dakshscra.py -r auto -t ./codebase

# Recon only
python dakshscra.py --recon -t ./api

# Recon with strict confidence filter
python dakshscra.py --recon --rs -t ./mobile_app

# Recon + scan
python dakshscra.py --recon -r java -t ./javaapp

# Scan with specific file types
python dakshscra.py -r dotnet -f dotnet -t ./dotnetapp

# Full scan with HTML + PDF output
python dakshscra.py -r php -t ./app -rpt html,pdf

# Scan with effort estimation
python dakshscra.py --recon --estimate -r php -t ./app

# Generate PDF from a previous scan
python dakshscra.py --pdf-from-json

# Generate PDF from a custom JSON directory
python dakshscra.py --pdf-from-json --json-input-dir ./custom/reports/data

# Single combined PDF only (skip per-platform set)
python dakshscra.py --pdf-from-json --pdf-single-only

# Skip taint analysis for faster scan
python dakshscra.py -r php -t ./app --skip-analysis

# List available rules
python dakshscra.py -l R

# List rules with file types
python dakshscra.py -l RF

# Resume an interrupted scan
python dakshscra.py --resume-scan -r php -t ./app
```

---

### Output Structure

After a scan, output is written to the following directories (relative to the project root, or to `DAKSH_REPORTS_DIR` / `DAKSH_RUNTIME_DIR` if set):

```
reports/
  scan/
    html/
      report.html            <- Single-file HTML report (all platforms)
      multi-file/
        index.html           <- Multi-file report index
        <platform>/          <- Per-platform HTML pages
    pdf/
      report.pdf             <- Single combined PDF (if pdf requested)
      multi-file/            <- Per-platform PDFs (if pdf requested)
    recon/
      reconnaissance.html    <- Recon report (if --recon was used)
    estimate/
      estimation.html        <- Effort estimate (if --estimate was used)
  analysis/
    <platform>/
      analysis.html          <- Taint analysis report (themed)
      analysis_xref.html     <- Cross-reference dataflow report
      analysis.json          <- Taint flow data
  data/
    areas_of_interest.json   <- Scanner findings
    filepaths_aoi.json       <- File path findings
    summary.json             <- Scan summary metadata
    recon.json               <- Recon results
    analysis.json            <- Taint analysis summary
runtime/
  scan_summary.json          <- Live scan state (updated during run)
  filepaths.json             <- Discovered file inventory
```

---

## Web UI Usage

### Starting the Web UI

```bash
docker compose up --build
```

Open `http://localhost:8080` in a browser.

To change the port:

```bash
DAKSH_PORT=9090 docker compose up
```

---

### Dashboard

The Dashboard is the landing page. It shows:

- **Summary metrics**: total projects, scans run, success/failure counts, and success rate
- **Recent scan activity**: a daily bar chart of scan volume
- **Project list**: all projects with scan counts and last-scan timestamps
- **Quick actions**: navigate directly to a project or start a new scan

---

### Projects

The Projects section organises scans into named groups. A project is created automatically the first time you run a scan with a given project name.

| Column | Description |
|---|---|
| Project Name | The name you assigned when creating the scan |
| Rules | Platform rules used |
| Target | The scanned source directory |
| Total Scans | Number of scans run under this project |
| Running | Scans currently in progress |
| Last Scanned | Timestamp of the most recent scan |

Click a project row to jump to its scan history in the Scans view.

---

### Scans & Findings

This is the primary working area. It has three panels:

#### Scan Form (left)

Configure and launch a new scan:

| Field | Description |
|---|---|
| **Project Name** | Groups this scan with previous runs. Leave blank for an unnamed scan. |
| **Target Directory** | Path to the source code. Use the browse button to navigate the filesystem. |
| **Platform Rules** | Which rule set to apply. `auto` detects the platform automatically. |
| **File Types** | Override the default extensions. `auto` uses platform defaults. |
| **Report Format** | `html` (default) or `html,pdf`. PDF requires Playwright/Chromium. |
| **Verbosity** | Output detail level (1-3). |
| **Recon** | Enable technology stack detection. |
| **Effort Estimate** | Generate a review effort estimation report. |
| **LOC Count** | Include effective lines of code in the scan summary. |
| **Skip Analysis** | Skip the taint analysis stage (faster for large codebases). |

Click **Run Scan** to start. The scan runs as a background process; you can navigate away and return.

#### Scan Table (top right)

Lists all scans for the selected project, most recent first. Each row shows:

- Status badge (running / success / failed / stopped)
- Scan UUID and timestamp
- Duration
- Platform rules used

Click a row to load its details below.

#### Scan Detail (bottom right)

Shows the full detail of the selected scan across four tabs:

**Log**: Live streaming output from the scan process. Shows each stage as it runs.

**Findings**: Organised into sub-tabs:
- *Scanner*: Rule-based source code findings. Each finding shows the rule name, file path, matched line, and surrounding context.
- *Paths*: File path findings (suspicious filenames, backup files, config files).

**Taint Analysis**: Dataflow findings showing source-to-sink traces. Each finding includes:
- Confidence level (high / medium / low)
- Source location (where user-controlled data enters)
- Sink location (where it reaches a security-sensitive call)
- Full trace path with intermediate steps
- Cross-references to related flows

**Insights**: Three sub-sections:
- *File Paths*: Full inventory of discovered source files
- *Recon*: Technology stack detection results (if `--recon` was enabled)
- *Effort Estimate*: Link to the estimation report (if `--estimate` was enabled)

---

### Understanding Findings

#### Scanner Findings

Each scanner finding is a pattern match against a code construct known to be risky or worth reviewing. Fields:

| Field | Description |
|---|---|
| Rule | The rule name (e.g. `sql_injection`, `command_exec`) |
| File | Source file path |
| Line | Line number of the match |
| Snippet | Surrounding code context |
| Platform | Language/framework platform the rule belongs to |

Not every finding is a vulnerability. Scanner findings are areas of interest that need manual review. Common false positives include commented-out code, test fixtures, and safe wrapper functions.

#### Taint Analysis Findings

Taint findings trace actual data flow, which makes them higher-signal than scanner findings. They show how user-controlled data travels from a source to a security-sensitive sink.

| Field | Description |
|---|---|
| Confidence | `high` (cross-file, multiple steps), `medium`, or `low` (single-file, no assignment steps) |
| Source | Where user-controlled data originates (request parameter, environment variable, etc.) |
| Sink | The call that receives the tainted data |
| Trace | Ordered list of intermediate steps connecting source to sink |
| Cross-file | Whether the flow spans multiple files |

**Reading confidence levels:**
- `high`: Cross-file flows with assignment steps. Review these first.
- `medium`: Same-file flows with partial tracing. Worth reviewing.
- `low`: File-scope fallback or single-step match. May be noise; verify manually.

#### Recon Results

Recon output is grouped by technology type (Framework, Language, Frontend, Backend, etc.). Each detection shows the technology name, confidence level, and which files were used as evidence.

Use `--recon --rs` to filter to high/medium confidence only when the output is too noisy.

---

### Reports & Artifacts

After a scan completes, generated files are accessible from the Scan Detail view. The **Artifacts** section (within the Insights tab or directly from the scan row) provides links to:

- HTML report (single file)
- HTML multi-file report set
- Taint analysis cross-reference report
- Effort estimation report
- JSON data files
- Scan log

All artifacts are served directly from the API. Click **Open Report** to view in a new browser tab, or **Download** to save locally.

---

### Directory Browser

The Web UI includes a directory browser that lets you navigate the server filesystem to pick a scan target. Only directories under the configured browse roots are accessible. The API enforces this boundary at the server level.

**Default roots (auto-detected at startup):**

| Platform | Default browse roots |
|---|---|
| Linux / Docker | `/`, `/home`, `/srv`, `/opt`, `/mnt`, `/tmp`, `/scan-targets`, `/host` |
| Windows / WSL | `/`, `/mnt`, `/mnt/c`, `/mnt/d` (any single-letter drives under `/mnt`), `/host/c`, `/host/d` |
| macOS | `/`, `/Users`, `/Volumes`, `/tmp` |

**Customising the browser roots:**

Set `DAKSH_BROWSE_ROOTS` as a comma-separated list of allowed absolute paths:

```bash
# In .env (Docker Compose picks this up automatically):
DAKSH_BROWSE_ROOTS=/scan-targets,/host,/mnt

# Or inline before starting the API directly:
DAKSH_BROWSE_ROOTS=/home/user/projects uvicorn api.main:app
```

When using Docker Compose, the volume mounts determine what is actually accessible. Configure them in `.env` before starting the stack:

```bash
# Windows / WSL
DAKSH_SCAN_ROOT=/mnt/c
DAKSH_HOST_MOUNT=/mnt
DAKSH_HOST_C=/mnt/c
DAKSH_HOST_D=/mnt/d

# Linux
DAKSH_SCAN_ROOT=/home
DAKSH_HOST_MOUNT=/

# macOS
DAKSH_SCAN_ROOT=/Users
DAKSH_HOST_MOUNT=/
```

See `.env.example` in the repository root for the full list of variables and per-platform examples.

> **Note:** Only include paths you actually intend to scan. Setting `DAKSH_BROWSE_ROOTS` tightly limits accidental exposure when the Web UI is reachable on a shared network.

---

---

## RDL - Rule Description Language

RDL is DakshSCRA's second-pass conditional filter applied **after** a regex match. Every rule can optionally include an `<rdl>` block that adds context-aware conditions, significantly reducing false positives without writing separate rules for every edge case.

> **World's first in open source** - conditional rule logic previously found only in commercial security scanners.

### How it works

When the scanner finds a regex match, it evaluates the RDL expression against the **entire file content** - not just the matched line. If the RDL condition is not satisfied, the match is suppressed and never reaches the report.

### Operators

| Operator | Behaviour | When to use |
|---|---|---|
| `FLAG:<pattern>` | Anchors the condition - the subject the rule is built around | Always the first clause |
| `IF(condition)` | Match is reported only when this condition is true | Wraps PRESENT / MISSING predicates |
| `PRESENT:<pattern>` | True when the pattern **is** found anywhere in the file | Require a co-occurring risky call |
| `MISSING:<pattern>` | True when the pattern is **not** found anywhere in the file | Suppress when a mitigation is already present |
| `EXISTS:<pattern>` | Like PRESENT but evaluated at file-path level | Check for a related config file |
| `&&` | Both conditions must hold | Require multiple simultaneous conditions |
| `\|\|` | Either condition must hold | Match any one of several conditions |
| `!` | Negation | Invert a predicate |

### How RDL reduces false positives

| Pattern | Without RDL | With RDL (result) |
|---|---|---|
| `getSharedPreferences()` | Flags every preference access (high FP rate) | Only flags when sensitive keys AND no encryption present |
| `loadUrl(someVar)` | Flags hardcoded safe URLs like `about:blank`, `file:///android_asset` | Only flags dynamic / interpolated URLs |
| `Room.databaseBuilder()` | Flags DB setup calls - zero injection risk (100% FP) | Replaced with `@Query` string interpolation pattern only |
| `System.getenv("SECRET")` | Flags as hardcoded secret (FP - it is a safe read) | Suppressed by `MISSING:System.getenv` condition |
| `viewModelScope.launch {}` | Flags every coroutine dispatch including benign UI commands | Only flags when body contains sensitive ops without error handling |

> **File-scope limitation:** PRESENT and MISSING conditions are evaluated against the entire file, not per-line. If a mitigation pattern appears *anywhere* in the file, all matches in that file are suppressed - even an unprotected call in the same file. This is a deliberate trade-off: lower noise at the cost of occasionally missing an issue in an otherwise-safe file. The reviewer note on every finding always advises manual confirmation.

### Example 1 - PHP SQL injection with missing parameterisation

```xml
<rule>
  <name>Conditional SQLi Check</name>
  <regex><![CDATA[(?i)(?:mysql_query|mysqli_query|->query)\s*\(]]></regex>
  <rdl><![CDATA[[FLAG:\$_(GET|POST|REQUEST|COOKIE)][IF(MISSING:(?:prepare|bindParam|bindValue|PDO::prepare))]]></rdl>
  <rule_desc>...</rule_desc>
</rule>
```

Fires when user-controlled input (`$_GET`, `$_POST`, etc.) is present **and** no parameterised query APIs are found in the file. A file that already uses `PDO::prepare` is not flagged.

### Example 2 - Android SharedPreferences storing sensitive data without encryption

```xml
<rdl><![CDATA[[FLAG:getSharedPreferences\(][IF(PRESENT:(token|secret|password|auth|session) && MISSING:(EncryptedSharedPreferences|MasterKey|KeyStore|Cipher|encrypt))]]]></rdl>
```

Fires only when the file references sensitive field names (token, password, etc.) **and** no Android encryption APIs are present. Files using `EncryptedSharedPreferences` are automatically suppressed.

### Example 3 - Hardcoded secrets excluding environment-variable reads

```xml
<rdl><![CDATA[[FLAG:(api_key|secret|token|password)\s*[:=]\s*"[^"]{8,}"][IF(MISSING:System\.getenv\s*\(|System\.getProperty\s*\(|BuildConfig\. && MISSING:example|sample|dummy|test|placeholder)]]]></rdl>
```

Without this RDL, `TOKEN = "${System.getenv("TOKEN")}"` would be flagged as hardcoded. The MISSING conditions exclude reads from environment variables, build config, and placeholder values in comments or tests.

### Rule XML structure reference

```xml
<rule>
  <name>Rule Name</name>
  <regex><![CDATA[regex_to_match]]></regex>
  <rdl><![CDATA[[FLAG:anchor_pattern][IF(PRESENT:risky_pattern && MISSING:mitigation_pattern)]]]></rdl>
  <exclude><![CDATA[pattern_to_exclude_lines]]></exclude>  <!-- optional -->
  <rule_desc>Short description of what the rule detects.</rule_desc>
  <vuln_desc>Explanation of the vulnerability class.</vuln_desc>
  <developer>Guidance for developers on how to fix.</developer>
  <reviewer>Guidance for reviewers on how to confirm the issue.</reviewer>
</rule>
```

## Platforms & Rules

DakshSCRA includes built-in rules for the following platforms:

| Platform | `-r` value | Default extensions |
|---|---|---|
| PHP | `php` | `.php` |
| Java | `java` | `.java` |
| .NET / C# | `dotnet` | `.cs`, `.aspx`, `.cshtml` |
| Python | `python` | `.py` |
| JavaScript / Node | `javascript` | `.js`, `.ts`, `.jsx`, `.tsx` |
| Go | `golang` | `.go` |
| Ruby / Rails | `ruby` | `.rb` |
| Kotlin | `kotlin` | `.kt`, `.kts` |
| C | `c` | `.c`, `.h` |
| C++ | `cpp` | `.cpp`, `.cc`, `.cxx`, `.hpp` |

Combine multiple platforms with commas: `-r php,java,javascript`

To list all available rules for a platform:

```bash
python dakshscra.py -l RF
```

---

## Findings Reference

### Common Rule Categories

| Category | Examples |
|---|---|
| Injection | SQL, command, LDAP, XPath, template injection |
| File operations | Path traversal, arbitrary file read/write, include/require |
| Authentication | Hardcoded credentials, weak hashing, session mismanagement |
| Cryptography | Weak algorithms, insecure random, hardcoded keys |
| Deserialization | Unsafe object deserialization |
| SSRF / Open redirect | Unvalidated URL construction |
| Information disclosure | Debug output, error exposure, sensitive data logging |
| Configuration | Dangerous settings, debug mode enabled |

---

## PDF Reports

PDF generation requires Playwright's Chromium browser:

```bash
playwright install chromium
```

### Generate PDF during a scan

```bash
python dakshscra.py -r php -t ./app -rpt html,pdf
```

### Generate PDF after a scan (from existing JSON)

```bash
# Both single and multi-file PDFs
python dakshscra.py --pdf-from-json

# Single combined PDF only
python dakshscra.py --pdf-from-json --pdf-single-only

# From a custom JSON directory
python dakshscra.py --pdf-from-json --json-input-dir ./custom/reports/data
```

PDF is not generated by default. The JSON output is always saved, so PDFs can be generated at any point after the scan completes.

---

## Tips & Common Patterns

### Starting with an unknown codebase

```bash
python dakshscra.py -r auto --recon --estimate -t ./target
```

Detects the technology stack, picks the right rules, and produces an effort estimate in one pass.

### Faster pass on large codebases

```bash
python dakshscra.py -r auto --skip-analysis -t ./large_app
```

Skipping taint analysis cuts down scan time significantly. Run it as a separate step once you have the recon and scanner results.

### Resuming an interrupted scan

```bash
python dakshscra.py --resume-scan -r php -t ./app
```

Scan state is saved by default. An interrupted scan can pick up from its last checkpoint rather than restarting from scratch.

### Suppressing known false positives

Generate a baseline from current findings:

```bash
python dakshscra.py -r php -t ./app --baseline-generate
```

On subsequent scans, the baseline is loaded automatically and those findings are excluded from reports. Use `--no-baseline` to run without it temporarily.

### Checking what rules exist

```bash
# List rule names
python dakshscra.py -l R

# List rules with associated file types
python dakshscra.py -l RF
```

---

## About

DakshSCRA was created by **Debasis Mohanty**, a security researcher and code review specialist. The tool was first introduced at Black Hat USA 2022 and expanded at Black Hat USA 2023.

| | |
|---|---|
| Website | [coffeeandsecurity.com](https://www.coffeeandsecurity.com) |
| Email | d3basis.m0hanty@gmail.com |
| Twitter / X | [@coffeensecurity](https://x.com/coffeensecurity) |
| Source | [github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) |
| License | GNU General Public License v3.0 (GPL-3.0) |

Found a bug or want to contribute? Open an issue or pull request on GitHub.
