# DakshSCRA Usage Guide

## Contents

1. [What is DakshSCRA?](#what-is-dakshscra)
   - [Distinctive Features](#distinctive-features)
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
6. [RDL - Rule Description Language](#rdl---rule-description-language)
   - [Current Status and Architecture](#current-status-and-architecture)
   - [Rule Evaluation Sequence](#rule-evaluation-sequence)
   - [Rule XML Structure](#rule-xml-structure)
   - [External RDL File Structure](#external-rdl-file-structure)
   - [RDL Commands](#rdl-commands)
   - [Examples](#rdl-examples)
   - [How RDL Reduces False Positives](#how-rdl-reduces-false-positives)
   - [Validating and Linting Rules](#validating-and-linting-rules)
   - [RDL v2 Direction](#rdl-v2-direction)
   - [Authoring Guidance](#authoring-guidance)
7. [scan_config - Rule-Driven Scanning & Reporting](#scan_config--rule-driven-scanning--reporting)
   - [Full Schema](#full-schema)
   - [Platform Profiles](#platform-profiles)
   - [Highlighting](#highlighting)
   - [Rule Authoring Guide](#rule-authoring-guide)
8. [Findings Reference](#findings-reference)
9. [PDF Reports](#pdf-reports)
10. [Tips & Common Patterns](#tips--common-patterns)
11. [About](#about)

---

## What is DakshSCRA?

DakshSCRA (Source Code Review Assist) is a security-focused static analysis tool built to support manual code review engagements. It helps surface areas of interest in source code through rule-based pattern matching, technology stack reconnaissance, and dataflow taint analysis.

It is a tool for reviewers, not a replacement for one. The goal is to cut down on manual triage time by pointing out relevant code patterns, inter-file data flows, and effort estimates, so the reviewer can focus on what actually matters.

### Distinctive Features

DakshSCRA brings together distinctive capabilities for manual source code review, from file-path areas of interest and effort estimation to software reconnaissance, contextual rules and cross-file analysis.

| Feature | Tag | Why it matters |
|---|---|---|
| **File Path Areas of Interest** | World's First* | Scans file and directory names themselves, alongside code, to flag suspicious paths such as backup files, debug endpoints, configuration dumps and credential files that reviewers often miss. |
| **Scientific Effort Estimation** | World's First* | Produces a quantified estimate of manual-review effort based on codebase size and project signals. Configurable assumptions make engagement planning explicit and repeatable. |
| **Areas of Interest, Not Bug Flags** | Reviewer in Control | Surfaces patterns worth investigating rather than tagging every match as a vulnerability. Contextual rules and suppression evidence reduce triage noise and keep the reviewer in control. |
| **Software Reconnaissance** | Integrated Software Recon | Detects languages, frameworks and infrastructure from file contents and project structure before scanning. Connects the technology inventory to automatic rule selection, semantic analysis and review planning. |
| **RDL Conditional Rules** | Advanced Conditional Rules | Goes beyond simple regex with PRESENT, MISSING, boolean expressions and file/path conditions. RDL v1 records decisions and suppression reasons; RDL v2 adds typed semantic services and bounded cross-file evidence. |
| **Advanced Semantic and Cross-File Analysis** | Built from the Ground Up | Traces user-controlled data from source to sink across supported file boundaries using purpose-built analysis. Advanced Analysis shipped alongside the original RDL in March 2026; RDL v2 extends semantic rule evaluation across files. |
| **Platform-Agnostic Auto Scanning** | Automatic Multi-Platform | Use `-r auto` to scan mixed-technology projects without choosing a single language beforehand. Recon selects supported platform and framework rules automatically. Introduced in v0.23-beta, November 2024. |
| **Application-Specific Security Logic** | Custom RDL Packs | Encode application trust boundaries, authorization decisions and business invariants in optional custom RDL packs. Project-specific logic runs alongside the generic scanning rules. |
| **Interactive Text and Graph Evidence** | Follow the Evidence | Follow recorded source-to-sink paths in linked Text and Graph views. Source excerpts, file lanes and handoff details make cross-file evidence easier to inspect. |
| **Review Lifecycle and Portable Reports** | Review, Resume and Export | Keep scan history, review suppressions and resume interrupted scans. Export HTML, PDF, editable Word and JSON through shared CLI and Web UI reports, with offline evidence navigation where available. |

* World's First badges reflect the project's original claims; worldwide priority has not been independently verified.

### Feature History and Evidence

| Feature / milestone | Date | Release | Evidence / scope |
|---|---|---|---|
| Training introduction | 2022 (Black Hat USA) | Not recorded | [Contemporary project README; introduction milestone.](https://github.com/coffeeandsecurity/DakshSCRA/blob/fe878be/README.md) |
| Initial beta and file-path rules | 22 October 2022 | v0.1-beta | [Initial release; retained source includes the dedicated file-path rule inventory.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.1-beta) |
| PDF and HTML reports | 23 May 2023 | v0.2-beta | [Release notes list PDF/HTML report generation and scanning-rule updates.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.2-beta) |
| Software reconnaissance (published introduction) | 9 July 2023 | v0.3-beta | [Release notes introduce recon; earlier repository code is separate implementation evidence.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.3-beta) |
| Manual-review effort estimation (implementation) | 29 July 2023 | Implementation commit | [Dedicated estimation module added; not the date of the later fix release.](https://github.com/coffeeandsecurity/DakshSCRA/commit/65d5c6a) |
| Effort-estimation fix | 5 August 2023 | v0.7-beta | [Release notes state fixed effort estimation; this is a correction milestone, not its first introduction.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.7-beta) |
| Early Android manifest and Kotlin checks | 27 April 2024 | v0.16-beta | [Introduced Android manifest misconfiguration checks and Kotlin-specific checks; module described as early development, with broader coverage still in progress.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.16-beta) |
| Multi-platform scan flags (initial design) | 4 November 2024 | v0.20-beta | [Added comma-separated platform selection with -r; initial implementation did not yet isolate each platform rule set to its own file types.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.20-beta) |
| Platform-agnostic auto scanning | 10 November 2024 (release listing) | v0.23-beta | [Automatic platform/rule selection; implementation commit dated 11 November.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.23-beta) |
| PDF rendering upgrade | 21 July 2025 | v0.29-beta | [Migrated PDF export from WeasyPrint to Playwright and Chromium; added HTML-size-based timeouts for large reports and cross-platform setup instructions.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.29-beta) |
| Initial iOS scanning support | 2 March 2026 | v0.31-beta | [Added iOS rules and Swift/Objective-C/configuration file selection; later releases expanded coverage.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.31-beta) |
| Original RDL and inter-file Advanced Analysis | 2 March 2026 | v0.31-beta | [Conditional rule logic and independent cross-file analysis shipped together. Release display date is 2 March; publication timestamp is 1 March 2026 at 18:39 UTC.](https://github.com/coffeeandsecurity/DakshSCRA/commit/d90ba51) |
| Web UI and Docker rollout | 16 March 2026 | v0.33-beta | [Introduced browser-launched scans, live progress, findings/artifact browsing, OS-aware directory selection and built-in Help; added Docker Compose Web UI/CLI services and portable environment setup.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.33-beta) |
| External RDL architecture and reporting | 22 March 2026 | v0.37-beta | [External rule logic and revised advanced reports.](https://github.com/coffeeandsecurity/DakshSCRA/commit/5b17d89) |
| RDL v2 semantic services and integrated workflow | Current development; no published release date | Unreleased development | Typed semantic rules, bounded cross-file evidence and custom packs. |

### Comparative evidence

- **Recon predecessor:** [Microsoft Application Inspector](https://www.microsoft.com/en-us/security/blog/2020/01/16/introducing-microsoft-application-inspector/) — 16 January 2020. Documents an earlier source-characteristics tool; does not establish a worldwide first/second ranking.
- **Automatic multi-language scanning:** [Semgrep auto example](https://semgrep.dev/blog/2022/autofixing-code-with-semgrep/) — 3 November 2022. Earlier automatic multi-language scanning prevents a broad first-in-open-source claim.
- **Semantic and data-flow analysis:** [Joern data-flow documentation](https://docs.joern.io/cpgql/data-flow-steps/) — No release date established here. Documents prior open-source capabilities; no comparative benchmark establishes overall superiority.

Dates identify repository or release milestones; they do not independently establish worldwide priority. “Not verified” means a release number has not been established from the reviewed evidence.

Release milestones and comparative evidence are listed above.

DakshSCRA was introduced during **Black Hat USA 2022** training and publicly debuted at **Black Hat USA 2023**. Those dates describe the project's introduction, not every current feature.

### What it does

| Capability | Description |
|---|---|
| **Rule-based scanning** | Matches platform-specific patterns (SQL queries, command execution, file I/O, etc.) against source files |
| **Reconnaissance** | Detects languages, frameworks, and technology stack from file contents and structure |
| **Taint analysis** | Traces data flows from user-controlled sources to security-sensitive sinks across files |
| **Effort estimation** | Estimates manual review time based on codebase size, complexity, and finding volume |
| **Report generation** | Produces indexed HTML bundles, PDF, editable Word, and JSON using shared CLI/web renderers |

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

Normal (foreground) mode:

```bash
python3 tools/start_webui.py
# Windows: py tools/start_webui.py
```

Detached (background) mode:

```bash
python3 tools/start_webui.py --detach
# Windows: py tools/start_webui.py --detach
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
| `-rpt FORMATS` | `html` | Report formats to generate. Values: `html`, `pdf`, `docx`, `json`, or a comma-separated combination. PDF requires Playwright/Chromium. |
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

RDL rule-evaluation decisions (matches, suppressions, fail reasons) are additionally logged as JSONL under `runtime/diagnostics/` for post-scan debugging. This is controlled by the `DAKSH_DECISION_TRACE` environment variable (default on; set to `0` to disable).

```
reports/<project>/<scan>/
  scan/
    html/
      report.html            <- Summary and report index (open first)
      report-files/          <- Linked paginated sections and saved-results.json
      multi-file/
        index.html           <- Multi-file report index
        <platform>/          <- Per-platform HTML pages
    pdf/
      report.pdf             <- Consolidated PDF (if pdf requested)
      multi-file/            <- Per-platform PDFs (if pdf requested)
    word/
      report.docx            <- Editable Word report (if docx requested)
    json/
      report.json            <- Shared report document (if json requested)
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

Normal (foreground) mode:

```bash
python3 tools/start_webui.py
# Windows: py tools/start_webui.py
```

Detached (background) mode:

```bash
python3 tools/start_webui.py --detach
# Windows: py tools/start_webui.py --detach
```

Open `http://localhost:8080` in a browser.

To change the port:

```bash
DAKSH_PORT=9090 python3 tools/start_webui.py
```

### Logging In

The Web UI requires an account. On first startup, an initial admin account
is created from `DAKSH_ADMIN_USERNAME`/`DAKSH_ADMIN_PASSWORD` (set these in
`.env`); if `DAKSH_ADMIN_PASSWORD` is left unset, a random password is
generated and printed once to the API's startup log - save it, since it
cannot be recovered afterward. An admin account can create further accounts
via the `POST /api/v1/auth/users` API endpoint. See `.env.example` for the
full list of authentication-related settings (session lifetime, cookie
security, CORS for `npm run dev`).

---

### Dashboard

The Dashboard is the landing page. It shows:

- **Summary metrics**: total projects, scans run, success/failure counts, and success rate
- **Recent scan activity**: a daily bar chart of scan volume
- **Project list**: all projects with scan counts and last-scan timestamps
- **Quick actions**: navigate directly to a project or start a new scan

---

### Projects

Projects uses compact rows with project name, target, status counts and latest scan.
Search by project name, ID or target; filter by active, completed, failed, stopped
or removed-data scans; sort by latest scan, name or scan count.

Open a project to see its complete paginated scan history. Search and status
filters include retained records whose scan data was removed. **View results**
opens a completed scan at Summary; active, queued or stopping scans open live
telemetry. **Project scans** returns from scan details to that project's history.

### Scans & Findings

#### New Scan

New Scan is a separate page with five configuration tabs:

| Tab | Controls |
|---|---|
| **Setup** | Project, target browser, auto/manual platform rules, file types and review mode |
| **Check Classes** | Enabled bug classes and optional per-scan exclusions |
| **Exclusions** | File/directory exclusions and scan scope |
| **Analysis & Output** | Recon, LOC, effort estimate, optional inter-file analyzer, verbosity and output settings |
| **Custom RDL** | Optional application-specific rule packs |

Reconnaissance and lines of code are selected by default; either can be deselected.
The optional inter-file analyzer follows Settings and is independent of RDL engine
selection. Comprehensive Review uses both engines; Finding Analysis Only uses v2;
Areas of Interest Review Only uses v1. See Scan configuration
for all controls, defaults and CLI equivalents.

#### Active Scans

Jobs run one at a time in queue order. Active Scans shows queued and running jobs;
queued time is separate from execution duration. Open a job for persistent Live
Scan Telemetry and Log. Stop a running job or cancel a queued job using its controls.

#### Completed scan details

Completed Scans and project history open saved results at **Summary**, with recorded
scan configuration, review metrics and links into the evidence views.

- **Areas of Interest:** contextual v1 source and file-path review leads.
- **Vulnerability Analysis:** v2 Summary, Confirmed Findings, Suppressed False
  Positives, Needs Manual Review and coverage limitations. A confirmed rule match
  establishes the named security property, not exploitability.
- **Advanced Analysis:** recorded v2 source-to-sink paths, input entry points and
  symbol cross references, with Text and Graph views where evidence is available.
- **Insights:** file inventory, recon and review effort.
- **Suppressed Findings:** recorded rule, version, rationale and trace; review an
  entry or promote it back to findings with notes.
- **Reports:** generate Full, Findings, Analysis or Suppressed scope as HTML, PDF,
  Word or JSON from saved results. Extract the HTML ZIP and open index.html.
- **Log:** retained scan output.

Historical scans retain their original evidence. Unavailable v2 analysis is shown
explicitly. Removing completed scan data deletes its evidence/reports while retaining
a history record; clearing that record is a separate action. Active jobs are protected.

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

Open the completed scan's **Reports** tab to generate HTML, PDF, Word (`.docx`), or JSON from saved results. Choose Full Scan, Areas of Interest, Advanced Analysis, or Suppressed Findings, then download the completed background job. Web scans retain data without automatically creating report files.

Extract an HTML ZIP and open `index.html` first. Its lightweight summary links to indexed, paginated detail pages; keep the files together for offline navigation. PDF provides linked contents and bookmarks, Word provides editable sections and linked contents, and JSON retains the original saved fields. Saved data and the scan log remain available alongside the report generator. See [On-demand reports](#on-demand-reports) for format details.

Software Reconnaissance starts with a technology overview and groups evidence by category and technology. Each detection shows recorded file/directory counts, detection confidence, a directory table and saved sample files. Paths inside the target are shown relative to it; original paths remain in JSON. Totals include overlapping technology matches and are not unique file counts. Generate a new Full scan report to apply the current layout to a saved scan; existing downloads remain unchanged.

---

### Directory Browser

The Web UI includes a directory browser that lets you navigate the server filesystem to pick a scan target. Only directories under the configured browse roots are accessible. The API enforces this boundary at the server level.

For Docker, run the host-aware launcher from the repository folder:

```bash
python3 tools/start_webui.py --detach
# Windows PowerShell / Command Prompt:
py tools/start_webui.py --detach
```

It detects the machine running Docker, mounts its filesystem root, available
Windows drives and common directories read-only, and supplies labeled shortcuts.
The browser's operating system does not determine mounts. Docker Desktop may
require file-sharing permission; denied or missing mounts produce an explicit
error instead of silently creating empty directories. WSL discovery excludes
unmounted drive-letter placeholders.

| Host location | Container path |
|---|---|
| Filesystem root (system drive on Windows) | `/host/root` |
| Additional Windows / WSL drives | `/host/drives/<letter>` |
| Current user's home | `/host/user` |
| Common folders | `/host/locations/<name>` |
| Repository or `DAKSH_SCAN_ROOT` | `/scan-targets` |

Click a folder once to open it. **Up** navigates to its allowed parent. You can
also enter a path and press Enter, filter the folder list, or use Quick Access.
**Select This Folder** selects the successfully loaded directory. An empty
folder remains selectable; an unreadable folder displays an error.

Optional `.env` overrides include `DAKSH_SCAN_ROOT`, `DAKSH_HOST_MOUNT`,
`DAKSH_HOST_SOURCE`, and `DAKSH_HOST_<drive letter>`. The helper respects these.
Plain `docker compose up --build -d api web` uses only the baseline scan/root
mounts; use the helper for automatic host detection. Restart with the helper
after attaching a drive. Existing runtime volumes and accounts are preserved.

`DAKSH_BROWSE_ROOTS` optionally restricts browsing and scan creation to a
comma-separated list of **container** paths, for example:

```bash
DAKSH_BROWSE_ROOTS=/scan-targets,/host/drives/c
```

Leave this unset to use discovered roots. An allow-list does not create mounts.
An invalid explicit list does not fall back to broader filesystem access.
Native API installations continue to detect the server OS's filesystem roots.
Automatic Docker mount discovery requires a local engine; for a remote engine,
run the helper on that host. See `.env.example` for path overrides.

---

---

## RDL - Rule Description Language

RDL is DakshSCRA's rule logic layer for contextual filtering, suppression, and reporting decisions.
In the current engine, RDL lives in external `.rdl` files and is attached to XML rules through
`<rdl_ref>`. The older inline `<rdl>` format is retired.

> **Current model:** XML supplies the candidate match pattern and reporting metadata. The external
> `.rdl` file decides whether that candidate stays visible, gets suppressed, or records extra trace
> information.

### Current status and architecture

RDL v1 evaluates contextual file/path rules; RDL v2 executes typed rules through the CLI
and Web UI. Both engines run by default. Semantic analysis remains experimental and
depends on rules, adapter capabilities and analysis budgets:

- External v1 rules use `VERSION 1` and execute through `core/rdl_engine.py`;
  v2 definitions have their own typed compiler and executor.
- `core/rdl/` provides a side-effect-free typed compiler and linter for v1 source. It identifies
  malformed regexes, unknown instructions, missing/unsupported versions, empty operands, and
  implicit whole-file scope before a scan is run.
- The complete shipped v1 rule collection is compiled as a compatibility corpus by
  `tests/rdl/test_legacy_corpus.py`.
- V2 parsing, typed AST, semantic validation and capability-aware execution plans
  support scan-time native text/path rules and configured semantic checks.
  Bounded cross-file analysis preserves parameter/return evidence and explicit limits.
  See the feature history table above for the original March 2026 RDL and
  independent inter-file analyzer milestone, followed by current v2 development.

The long-term execution model separates the security property from the analysis needed to prove it:

```text
RDL source
    |
    v
parser and semantic validation
    |
    v
typed execution plan
    |
    +--> text/path index
    +--> language-neutral semantic IR
    +--> data-flow, control-flow, call-graph and state services
    |
    v
MATCH / NO_MATCH / RULE_ERROR / INDETERMINATE
    |
    v
machine-readable evidence graph and reports
```

Simple text rules use the text/path layer. Advanced rules request AST,
semantic, flow, path, or state capabilities only when needed. This keeps simple rules readable and
inexpensive while allowing complex analysis to be expressed without embedding language-specific
implementation logic in every rule.

V2 rule definitions use the versioned [`rules/scanning/logic/rdl/v2/`](../rules/scanning/logic/rdl/v2/README.md)
tree. Shared properties live in `common/core/<bug-class>/`, language-specific
rules in `<platform>/core/<bug-class>/`, and framework-specific rules in
`<platform>/framework/<framework>/<bug-class>/`. The
[scope index](../rules/scanning/logic/rdl/v2/INDEX.md) traces rule IDs and current v1 mappings;
README-only scopes are extension points, not implemented coverage.

Choose **RDL v1**, **RDL v2 (Experimental)**, or **Both** in the Web UI's New
Scan form. **Both is the default** in the Web UI and CLI. Docker startup is simply
`python3 tools/start_webui.py --detach`; no RDL environment variable is required.

- **V1:** the established source/path rule engine and existing language/framework rules.
- **V2 (Experimental):** native text/path baseline rules, additional source/configuration
  checks and configured semantic definitions. Consult the versioned coverage audit
  for current registrations; development samples do not imply enabled detectors.
  Android/iOS security review documents mobile coverage,
  source/configuration precision checks, suspicious behavior review and runtime limits.
  The coverage audit separates verified legacy predicate
  parity from incomplete semantic coverage and lists mobile review areas.
- **Both:** run both engines with separate result tabs. V2 does not change v1 decisions.

V2 is intended to replace v1 only after repeated tests and iterations establish
coverage of all existing bug classes across every supported language and framework.
V1 remains supported until then. New v2 reports preserve original source evidence,
including credential values, in the UI and exports. Existing saved evidence is not
reconstructed; rescan to replace previously masked snippets. Mobile v2 scans also
apply relevant language and Android/iOS native-bridge checks.
The optional inter-file analyzer is independent
of this selection and retains its own results.

```bash
python3 dakshscra.py -r auto -t /path/to/source --rdl-engine both
python3 dakshscra.py -r php -t /path/to/source --rdl-engine v1
python3 dakshscra.py -r php -t /path/to/source --rdl-engine v2
```

For app-specific trust boundaries or business logic, select an optional pack with
`--custom-rdl /path/to/pack.json`, or enter its mounted path in the New Scan form's
**Custom RDL** tab’s **App-specific RDL packs** field. Packs are saved per scan and require v2 or both
engines. See Custom RDL packs for the manifest format,
file scopes, limits, semantic checks and the SchoolHub example.

New Scan uses Setup, Check Classes, Exclusions, Analysis & Output, and Custom RDL tabs. See Scan configuration for bug-class selection, file exclusions, per-scan CLI options and their defaults.

Select `--rdl-engine v1` to run only the established engine. The CLI choice takes
precedence over the legacy `DAKSH_RDL_V2_SHADOW` setting. New scans save their
selection; changing defaults does not reinterpret historical results. Checkpoint
resume requires the same engine choice.

**Vulnerability Analysis** is the sole vulnerability decision view and uses RDL v2
outcomes. Its subsections are Summary, Confirmed Findings, Suppressed False
Positives, Manual Inspection Recommended, and Mitigated Implementations. The
separate legacy Vulnerabilities tab and analyzer sink-name classification are
retired. Advanced Analysis uses the RDL v2 source-to-sink path, symbol cross-reference and
input entry-point views. Its counts and filters come from recorded RDL evidence.
The separate analyzer-ranked flow presentation is no longer used in the portal.

An RDL `MATCH` is an engine-confirmed finding: the named rule property matched
recorded evidence. It is not proof of exploitability or human confirmation.
Source-code matches appear under Confirmed Findings. Manual Inspection requires located
partial security evidence of a recorded flow or state violation and a specific investigation step. Analyzer errors without
such evidence are recorded separately as coverage limits. A recorded false-positive review can suppress a
match. A `NO_MATCH` is not automatically a mitigation: positive control evidence
is required. The main tab counts distinct matched finding locations; category
lists count grouped rule/file evaluations. Unresolved checks do not inflate the
main findings badge. Filename-only matches remain Areas of Interest and RDL
coverage observations; they do not count as vulnerability findings.

Historical scans keep their original evidence. The new view classifies their RDL
outcomes conservatively; it does not import old analyzer confirmation labels.
Scans without RDL v2 display an explicit unavailable state. Regenerated reports
use RDL classifications; existing downloaded artifacts retain their original text.

V2-only scans record v1 as `NOT_RUN`; agreement/disagreement comparisons apply
only when both engines ran. Unmapped languages or files do not imply safety.

V2 results include source locations, flow steps, excerpts, impact, remediation,
and confidence limits. Reports includes `scan/html/rdl-v2.html` for download when mapped
properties were evaluated. See the accuracy review
for historical validation evidence and limits.

The checked real-codebase baseline scanned 119 first-party DakshSCRA Python
files: 116 comparisons agreed, three disagreed, and none failed or became
indeterminate. Manual review classified all three disagreements as v1
presence-based false positives where v2 correctly found no untrusted flow.
These results validate this codebase and mapping set; they are not a claim of
perfect accuracy on arbitrary software.

The expanded iAcademy validation covers 712 PHP files and five properties:
9,256 mapped evaluations, three distinct credential leads, and zero execution
errors. Relevant PHP flows requiring unsupported control-flow reasoning remain
explicitly indeterminate. Disagreements are retained as review evidence and do
not alter v1 findings. The earlier single-mapping baseline is historical.


### Rule evaluation sequence

For source and framework rules, DakshSCRA processes a rule in this order:

1. Reconnaissance detects the relevant platform/framework or the user selects rules explicitly.
2. The scanner loads the matching XML rule from `rules/scanning/platform/...`.
3. The rule's `<regex>` finds candidate matches.
4. Optional `<exclude>` removes known-noise lines for that rule.
5. The rule's external `.rdl` file from `<rdl_ref>` is loaded from `rules/scanning/...` and evaluated.
6. If the RDL script passes, the finding is reported. If it fails, the candidate is suppressed with the recorded fail reason and trace.

For file-path analysis, the same `rdl_ref` model is used, but the evaluation subject is the normalized
relative path rather than source code text.

### Rule XML structure

This is the current XML layout for scanner rules:

```xml
<rule>
  <name>Rule Name</name>
  <regex><![CDATA[regex_to_match]]></regex>
  <rdl_ref>logic/rdl/v1/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
  <exclude><![CDATA[pattern_to_exclude_lines]]></exclude>  <!-- optional -->
  <scan_config>...</scan_config>                           <!-- optional -->
  <rule_desc>Short description of what the rule detects.</rule_desc>
  <vuln_desc>Explanation of why the pattern matters.</vuln_desc>
  <developer>Fix guidance for developers.</developer>
  <reviewer>Manual confirmation guidance for reviewers.</reviewer>
</rule>
```

What each field does:

| Element | Purpose |
|---|---|
| `<regex>` | Finds candidate lines or file-level matches |
| `<rdl_ref>` | Points to the external `.rdl` script that decides if the candidate should survive |
| `<exclude>` | Removes noisy matches before RDL evaluation |
| `<scan_config>` | Controls match mode, context capture, aggregation, highlighting, and report formatting |
| Descriptive fields | Explain the issue and provide reviewer/developer guidance |

### External RDL file structure

The external `.rdl` file is a small line-oriented script:

```text
VERSION 1
WHEN PRESENT /\b(?:mysql_query|mysqli_query|->query)\s*\(/i
WHEN EXPR PRESENT:\$_(GET|POST|REQUEST|COOKIE) && MISSING:\b(?:prepare|bindParam|bindValue|PDO::prepare)\b
REPORT AS area_of_interest
REASON Query execution appears to rely on direct input without parameterisation.
FAIL_REASON Matching query API was found, but prepared-statement indicators also exist in the same file.
TRACE SQLi gate: input source present and mitigation missing.
```

The engine evaluates RDL against the **entire file content** of the current file, not only the
matched line. File-path rules evaluate against the normalized relative path string. Project-level
observations can also be recorded from the repository root.

### RDL commands

| Command | Behaviour | When to use |
|---|---|---|
| `WHEN PRESENT <regex>` | Require a pattern to appear in the current file text | Confirm a risky API or sensitive field exists |
| `WHEN MISSING <regex>` | Require a pattern to be absent from the current file text | Suppress when a mitigation is already present |
| `WHEN EXPR <expr>` | Evaluate a boolean expression using `PRESENT:` / `MISSING:` / `EXISTS:` | Combine multiple conditions compactly |
| `WHEN CURRENT_FILE_MATCHES <regex>` | Match against the entire current file content | Whole-file config or structure checks |
| `WHEN FILE_NAME_IS <name>` | Require an exact filename | `AndroidManifest.xml`, `Info.plist`, `web.xml` |
| `WHEN FILE_PATH_MATCHES <glob>` | Require the current path to match a glob | Path-specific or framework-specific rules |
| `UNLESS CURRENT_FILE_MATCHES <regex>` | Fail if the full file matches an exclusion pattern | Skip known-safe structural cases |
| `OBSERVE PROJECT_HAS_GLOB <glob> AS <label>` | Record related files from the project root in the trace | Supporting config visibility |
| `REPORT AS <outcome>` | Set the rule outcome | Usually `area_of_interest` |
| `REASON <text>` | Explanation stored when the rule passes | Report-side rationale |
| `FAIL_REASON <text>` | Explanation stored when the rule suppresses a match | Suppression rationale |
| `TRACE <text>` | Add trace/debug notes | Migration, tuning, or reviewer context |

Inside `WHEN EXPR`, the engine supports:

- `PRESENT:<regex>`
- `MISSING:<regex>`
- `EXISTS:<regex>`
- `&&`, `||`, `!`
- Parentheses for grouping

### RDL examples

#### Example 1 - PHP SQL injection with missing parameterisation

XML rule:

```xml
<rule>
  <name>Possible SQL Injection in Query Execution</name>
  <regex><![CDATA[(?i)\b(?:mysql_query|mysqli_query|->query)\s*\(]]></regex>
  <rdl_ref>logic/rdl/v1/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
  <rule_desc>Detects unsafe SQL query execution patterns.</rule_desc>
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

The regex stays broad enough to catch all candidate query APIs. The `.rdl` file then keeps only the
cases where user input is present and parameterisation appears absent.

#### Example 2 - Android manifest rule using filename and full-file checks

XML rule:

```xml
<rule>
  <name>Exported Components Without Permission</name>
  <regex><![CDATA[<(?P<component>activity|service|receiver|provider)\s[^>]*android:name="(?P<name>[^"]+)"[^>]*android:exported="true"[^>]*(?:/>|>)]]></regex>
  <rdl_ref>logic/rdl/v1/mobile/android/core/exported_components.rdl</rdl_ref>
  <scan_config>
    <match_mode>file</match_mode>
    <context_type>named_groups</context_type>
    <aggregate>file</aggregate>
    <report_format>component_list</report_format>
  </scan_config>
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
FAIL_REASON Exported component marker was found, but the file also contains a permission requirement.
```

This is a good example of the split of responsibilities:

- `regex` finds candidate exported components.
- `scan_config` decides how to present them.
- `rdl_ref` confirms the broader file context before the finding survives.

#### Example 3 - File-path rule

XML rule:

```xml
<rule>
  <name>Admin Section File Path</name>
  <regex><![CDATA[(?i)(^|/)(admin|administrator|root)(/|$)]]></regex>
  <rdl_ref>logic/rdl/v1/filepaths/core/admin_section.rdl</rdl_ref>
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

For file-path analysis there is still a regex candidate stage, but the current file text for RDL is
the normalized relative path string, not the file contents.

#### Example 4 - Project observation rule

```text
VERSION 1
WHEN FILE_NAME_IS AndroidManifest.xml
WHEN CURRENT_FILE_MATCHES /android:usesCleartextTraffic\s*=\s*"true"/i
OBSERVE PROJECT_HAS_GLOB **/network_security_config*.xml AS network_security_configs
REPORT AS area_of_interest
REASON Cleartext traffic is enabled; related network security config files were recorded for reviewer context.
```

`OBSERVE` does not currently gate the rule result. It records related project files into trace metadata
so the reviewer can see that supporting config exists.

### How RDL reduces false positives

| Pattern | Without RDL | With RDL (result) |
|---|---|---|
| `getSharedPreferences()` | Flags every preference access (high FP rate) | Only flags when sensitive keys AND no encryption present |
| `loadUrl(someVar)` | Flags hardcoded safe URLs like `about:blank`, `file:///android_asset` | Only flags dynamic / interpolated URLs |
| `Room.databaseBuilder()` | Flags DB setup calls - zero injection risk (100% FP) | Replaced with `@Query` string interpolation pattern only |
| `System.getenv("SECRET")` | Flags as hardcoded secret (FP - it is a safe read) | Suppressed by `MISSING:System.getenv` condition |
| `viewModelScope.launch {}` | Flags every coroutine dispatch including benign UI commands | Only flags when body contains sensitive ops without error handling |

> **Whole-file limitation:** `WHEN PRESENT`, `WHEN MISSING`, and `WHEN EXPR` are evaluated against
> the entire file text, not per-line. If a mitigation appears anywhere in the file, all candidate
> matches for that file can be suppressed. This is deliberate: lower noise at the cost of potentially
> hiding an issue in an otherwise-safe file. Reviewer guidance should always reflect that trade-off.

### Validating and linting rules

Lint RDL before running a scan or submitting a new rule:

```bash
# Validate one rule
python3 tools/rdl_lint.py rules/scanning/logic/rdl/v1/python/core/command_injection_eval.rdl

# Validate every shipped external rule
python3 tools/rdl_lint.py rules/scanning/logic/rdl/v1

# Produce machine-readable diagnostics for automation
python3 tools/rdl_lint.py rules/scanning/logic/rdl/v1 --json
```

The command exits with status `0` when there are no rule errors and `1` when at least one error is
present. Human-readable diagnostics include the file, line, severity, stable diagnostic code,
message, and a remediation hint when available. JSON output contains the same fields plus the total
error count.

Important diagnostic categories include:

| Code | Meaning |
|---|---|
| `RDL001` | Missing `VERSION` declaration |
| `RDL003` / `RDL004` | Invalid or unsupported language version |
| `RDL101` | Unknown instruction that the v1 runtime would otherwise ignore |
| `RDL102` | Empty command or regex operand |
| `RDL103` | Malformed regex |
| `RDL106` | Boolean expression has no recognized predicate |
| `RDL201` | Rule has no gating predicate and therefore always passes |
| `RDL301` | Informational warning that a v1 text predicate uses whole-file scope |

`NO_MATCH` and `RULE_ERROR` are different security-analysis outcomes. The current production v1
evaluator preserves its established runtime behavior for compatibility, but the linter must pass
before a rule is considered valid. V2 execution carries rule errors and analysis-budget
exhaustion as explicit outcomes rather than negative matches.

Run the compiler and full legacy-corpus tests with:

```bash
python3 -m unittest tests.rdl.test_compiler tests.rdl.test_legacy_corpus
```

Every newly discovered parser, semantic, or evasion defect should gain a permanent regression test.

### RDL v2 direction

RDL v2 runs through the Web UI and CLI alongside v1 by default. Its native text/path
baseline covers the existing rule inventory; deeper analysis remains capability-dependent
and experimental. Its implemented language model and analysis levels are:

1. Simple text and path predicates such as `PRESENT`, `MISSING`, `MATCHES`, `PROJECT_HAS`, and
   `PATH_MATCHES`.
2. Typed entities and relationships such as functions, variables, calls, assignments, parameters,
   return values, resources, sources, sinks, and sanitizers.
3. Source-to-sink data flow with propagation, aliases, transformations, sanitizers, fields, and
   bounded interprocedural analysis.
4. Control-flow and path reasoning including reachability, branches, loops, dominance, and
   exceptional paths where an adapter supports them.
5. Generic state transitions for memory lifetime, resources, locks, authentication, authorization,
   workflows, and business invariants.

Language adapters map supported native syntax and APIs into a normalized semantic representation. Generic
rules target concepts such as `command.execution` or `sql.execution`; catalog packs map
Python, Java, Go, proprietary languages, and other platforms to those concepts without adding new
RDL keywords for each language.

Severity and confidence are separate in the v2 model. Severity describes impact; confidence describes
evidence strength. Findings also record whether their evidence came from a heuristic text match,
semantic match, verified data flow, feasible control-flow path, or state violation.

The parser/scopes/entities, semantic IR/adapters, intraprocedural data-flow, control-flow/path
analysis, generic state-machine, bounded interprocedural, and broader-adapter phases are complete.
The current executor runs configured v2 checks in scans. Coverage expansion, performance
hardening and fuzzing remain ongoing. Dual-run comparisons and safe/unsafe regressions
validate migration; implemented services do not imply complete semantic coverage
for every registered platform or framework.

### Authoring guidance

- Keep `<regex>` broad enough to catch candidate matches. Let RDL remove safe contexts.
- Use `<rdl_ref>` for every new rule. Do not add new inline `<rdl>` blocks.
- Prefer `WHEN PRESENT` / `WHEN MISSING` for simple gating and `WHEN EXPR` only when the logic genuinely needs boolean composition.
- Put report-facing intent in `REASON` and suppression-facing intent in `FAIL_REASON`.
- For path rules, write the regex and RDL conditions against normalized slash-separated relative paths.
- Use `TRACE` and `OBSERVE` when reviewers benefit from extra context, but do not rely on `OBSERVE` for gating.
- Run `python3 tools/rdl_lint.py <path>` before testing a rule against source code.
- Treat every v1 text predicate as file-scoped. Do not assume a mitigation is tied to the same
  function, variable, call, or data-flow path as the candidate.
- Do not use draft v2 syntax in active rules until the v2 parser and execution plan are enabled.
- If a rule requires variable identity, data flow, control flow, type information, call graphs, or
  state tracking, do not approximate the property by continually adding regexes. Record it as a
  semantic-analysis requirement for the appropriate RDL phase.

## scan_config - Rule-Driven Scanning & Reporting

`scan_config` is an optional XML block inside any `<rule>` that controls how the engine scans for that
rule and how matches appear in reports. Rules without `<scan_config>` behave exactly as before - the
block is fully opt-in and every field has a safe default.

### Why scan_config exists

The default model - regex applied line-by-line, one finding entry per match - works well for
self-contained code patterns. It falls short for:

- **Structural / declarative files** (AndroidManifest, Kubernetes YAML, Terraform HCL, Dockerfile)
  where the useful context is the parent element, not the matching attribute line.
- **Rules that fire many times in one file** for the same conceptual issue (e.g. five exported Android
  components → five identical-looking findings with no component identity shown).
- **Multi-line patterns** that cannot be expressed in a single-line regex.
- **Reviewer experience** - showing N lines of context around a match is far more useful than a naked
  matched snippet.

`scan_config` solves all of these without changing any existing rules.

---

### Full Schema

```xml
<scan_config>

    <!-- ── MATCH MODE ──────────────────────────────────────────────── -->
    <!-- line : regex applied per line (default - all existing rules)   -->
    <!-- file : regex applied to full file content with MULTILINE|      -->
    <!--        DOTALL flags. Use for structured/declarative files.      -->
    <match_mode>line</match_mode>

    <!-- ── CONTEXT TYPE ───────────────────────────────────────────── -->
    <!-- none         : show only the matched line (default)            -->
    <!-- named_groups : extract named (?P<name>...) capture groups from -->
    <!--               the regex and display them as labelled fields.   -->
    <!-- lines        : include N raw lines before and/or after the     -->
    <!--               match. Use context_lines_before / _after.        -->
    <!-- backward     : scan backward from the match line for a         -->
    <!--               secondary pattern. The first capture group       -->
    <!--               becomes the context label.                       -->
    <context_type>none</context_type>

    <!-- Used when context_type = lines -->
    <!-- before: useful for variable assignments and function args       -->
    <!--         that lead into the vulnerable call.                    -->
    <!-- after : useful for seeing how a block closes, whether error    -->
    <!--         handling follows, or how a value is used downstream.   -->
    <!-- Both are independent - set either or both.                     -->
    <!-- Recommended: context_lines_before + context_lines_after <= 12  -->
    <context_lines_before>0</context_lines_before>
    <context_lines_after>0</context_lines_after>

    <!-- Used when context_type = backward -->
    <!-- Regex applied scanning upward from the match line.             -->
    <!-- First capture group becomes the displayed context label.       -->
    <context_pattern></context_pattern>
    <context_depth>10</context_depth>   <!-- max lines to scan upward  -->

    <!-- ── AGGREGATION ────────────────────────────────────────────── -->
    <!-- none : each match = one finding entry (default)               -->
    <!-- file : all matches of this rule in a file collapse into one   -->
    <!--        finding entry. All match locations listed together.     -->
    <!--        Eliminates walls of identical repeated entries.         -->
    <aggregate>none</aggregate>

    <!-- ── REPORT FORMAT ──────────────────────────────────────────── -->
    <!-- default        : match snippet + context lines (default)       -->
    <!-- component_list : table of named_group captures + line numbers  -->
    <!--                  Use with context_type:named_groups             -->
    <!-- secret_list    : compact list, masks long values after 12 chars -->
    <!--                  Use for credential/secret detection rules      -->
    <report_format>default</report_format>

    <!-- ── HIGHLIGHTING ───────────────────────────────────────────── -->
    <!-- Controls what gets highlighted in CLI (ANSI colour) and web   -->
    <!-- (CSS span) output. Default: highlight full regex match in red. -->
    <highlight_enabled>true</highlight_enabled>

    <!-- SIMPLE HIGHLIGHT (single target - covers most rules)          -->
    <!-- highlight_target options:                                      -->
    <!--   match   : highlight the full regex match (default)           -->
    <!--   groups  : highlight named capture groups in highlight_groups  -->
    <!--   pattern : highlight occurrences of highlight_pattern          -->
    <highlight_target>match</highlight_target>
    <highlight_groups></highlight_groups>   <!-- comma-sep group names  -->
    <highlight_pattern></highlight_pattern> <!-- regex for pattern mode  -->

    <!-- Colour options: red | yellow | cyan | green | magenta | bold   -->
    <!-- Semantic guide:                                                 -->
    <!--   red     - dangerous sinks, injections, hardcoded secrets     -->
    <!--   yellow  - weak patterns, missing flags, deprecated functions  -->
    <!--   cyan    - structural/informational (exports, routes, config)  -->
    <!--   green   - mitigations present (Mitigation Identified rules)   -->
    <!--   magenta - framework-specific patterns                         -->
    <!--   bold    - emphasis only, no colour (safe for mono terminals)  -->
    <highlight_color>red</highlight_color>

    <!-- MULTI HIGHLIGHT (advanced - overrides simple fields above)    -->
    <!-- Each <mark> is one independent highlight pass over the snippet -->
    <!-- type values: match | group:<name> | pattern:<regex>           -->
    <!-- Processed in order. Max 3 marks recommended.                  -->
    <marks>
        <mark color="red">match</mark>
        <mark color="yellow">group:component</mark>
        <mark color="cyan">pattern:android:name="[^"]+"</mark>
    </marks>

</scan_config>
```

---

### Platform Profiles

Three profiles cover the vast majority of rule types. Start from the matching profile when authoring
a new rule, then adjust fields as needed.

#### Profile A - `structured` (declarative / config files)

Use for: AndroidManifest.xml, Kubernetes YAML, Terraform HCL, Dockerfile, plist, web.xml - any file
where structure is hierarchical and predictable.

```xml
<scan_config>
    <match_mode>file</match_mode>
    <context_type>named_groups</context_type>
    <aggregate>file</aggregate>
    <report_format>component_list</report_format>
    <highlight_enabled>true</highlight_enabled>
    <marks>
        <mark color="red">match</mark>
    </marks>
</scan_config>
```

The regex must use named capture groups (`(?P<name>...)`). The engine extracts them and displays them
as labelled columns alongside the line number.

**Full example - AndroidManifest exported components:**

```xml
<rule>
    <name>Exported Components Without Permission</name>
    <regex><![CDATA[<(?P<component>activity|service|receiver|provider)\s[^>]*android:name="(?P<name>[^"]+)"[^>]*android:exported="true"[^>]*(?:/>|>)]]></regex>
    <rdl_ref>logic/rdl/v1/mobile/android/core/exported_components.rdl</rdl_ref>
    <scan_config>
        <match_mode>file</match_mode>
        <context_type>named_groups</context_type>
        <aggregate>file</aggregate>
        <report_format>component_list</report_format>
        <marks>
            <mark color="red">pattern:android:exported\s*=\s*"true"</mark>
            <mark color="cyan">pattern:android:name\s*=\s*"[^"]+"</mark>
        </marks>
    </scan_config>
    <rule_desc>Detects Android components exported without a permission requirement.</rule_desc>
    <vuln_desc>Exported components accessible without a permission can be invoked by any app on the device.</vuln_desc>
    <developer>Restrict exported components with android:permission or set android:exported="false" where external access is not required.</developer>
    <reviewer>Confirm each exported component has a restrictive permission defined or that unrestricted access is intentional.</reviewer>
</rule>
```

**Report output (`component_list` format):**
```
Exported Components Without Permission        HIGH    AndroidManifest.xml

  Line  82    activity    .MainActivity
  Line  95    service     .SyncService
  Line 110    receiver    .BootReceiver
  Line 125    activity    .DeepLinkActivity
```

Instead of five separate identical findings, the reviewer sees one clean table identifying exactly
which components are affected.

---

#### Profile B - `code` (source code files)

Use for: Python, JavaScript, PHP, Java, Go, Kotlin, Ruby, C, C++, .NET, Bash, PowerShell - any file
where structure is scope-dependent and cannot be parsed by regex alone.

```xml
<scan_config>
    <match_mode>line</match_mode>
    <context_type>lines</context_type>
    <context_lines_before>3</context_lines_before>
    <context_lines_after>0</context_lines_after>
    <aggregate>none</aggregate>
    <report_format>default</report_format>
    <highlight_enabled>true</highlight_enabled>
    <highlight_target>match</highlight_target>
    <highlight_color>red</highlight_color>
</scan_config>
```

Use `context_lines_before` to show what leads into the vulnerable call (variable assignments, function
arguments). Use `context_lines_after` to show what follows (error handling, return value usage).

**Full example - PHP file inclusion:**

```xml
<rule>
    <name>Insecure File Inclusion</name>
    <regex><![CDATA[\b(?:include|require)(?:_once)?\s*\(\s*\$\w+]]></regex>
    <rdl_ref>logic/rdl/v1/php/core/insecure_file_inclusion_include_require.rdl</rdl_ref>
    <scan_config>
        <match_mode>line</match_mode>
        <context_type>lines</context_type>
        <context_lines_before>4</context_lines_before>
        <context_lines_after>0</context_lines_after>
        <highlight_target>match</highlight_target>
        <highlight_color>red</highlight_color>
    </scan_config>
    ...
</rule>
```

**Report output:**
```
Insecure File Inclusion                       HIGH    controllers/page.php : Line 47

  44 |  $page = $_GET['page'];
  45 |  $page = str_replace('../', '', $page);
  46 |
  47 >  include($page . '.php');
```

The reviewer immediately sees the inadequate sanitisation on line 45 without opening the source file.

**When to use `context_lines_after`** - use it when the match opens a block and you need to see what's
inside:

```xml
<scan_config>
    <context_type>lines</context_type>
    <context_lines_before>0</context_lines_before>
    <context_lines_after>6</context_lines_after>
    <marks>
        <mark color="yellow">pattern:transaction\s*\{</mark>
        <mark color="red">pattern:\b(insert|update|delete)\b</mark>
    </marks>
</scan_config>
```

```
Exposed Transaction Without Exception Handling    Kotlin/db/UserRepo.kt : Line 34

  34 >  transaction {
  35       userTable.insert { it[name] = username }
  36       auditTable.insert { it[event] = "created" }
  37       emailQueue.add(username)
  38   }
```

---

#### Profile C - `config` (flat configuration / secret files)

Use for: `.env`, `.properties`, `appsettings.json`, `*.tfvars`, `*.ini`, any flat key-value config file.

```xml
<scan_config>
    <match_mode>line</match_mode>
    <context_type>none</context_type>
    <aggregate>file</aggregate>
    <report_format>secret_list</report_format>
    <highlight_enabled>true</highlight_enabled>
    <highlight_target>match</highlight_target>
    <highlight_color>red</highlight_color>
</scan_config>
```

The matched line is self-explanatory (`DB_PASSWORD=prod_secret`). No surrounding context adds value.
`aggregate:file` collapses multiple secrets in the same file into one finding entry.

**Report output (`secret_list` format):**
```
Hardcoded Credentials                         CRITICAL   .env

  Line  3    DB_PASSWORD    = "prod_p@ssw..."
  Line  7    API_KEY        = "sk-live-xK..."
  Line 12    JWT_SECRET     = "mySuperSec..."
```

---

### Highlighting

#### Colour palette

| Value | CLI (ANSI) | Web CSS class | Use for |
|---|---|---|---|
| `red` | bright red | `hl-red` | Dangerous sinks, injections, RCE, hardcoded secrets |
| `yellow` | bright yellow | `hl-yellow` | Weak patterns, deprecated, missing flags |
| `cyan` | bright cyan | `hl-cyan` | Structural / informational (exports, routes, config) |
| `green` | bright green | `hl-green` | Mitigations present ("Mitigation Identified" rules) |
| `magenta` | bright magenta | `hl-magenta` | Framework-specific patterns |
| `bold` | bold only | `hl-bold` | Emphasis with no colour - safe for monochrome terminals |

#### Simple vs. multi highlight

**Simple** - one thing to highlight:
```xml
<highlight_target>match</highlight_target>
<highlight_color>red</highlight_color>
```

**Named group** - highlight a specific captured group:
```xml
<highlight_target>groups</highlight_target>
<highlight_groups>name,component</highlight_groups>
<highlight_color>cyan</highlight_color>
```

**Pattern** - highlight a sub-pattern within the displayed snippet:
```xml
<highlight_target>pattern</highlight_target>
<highlight_pattern>android:exported\s*=\s*"true"</highlight_pattern>
<highlight_color>red</highlight_color>
```

**Multi** - multiple independent highlight passes, different colours:
```xml
<marks>
    <mark color="cyan">pattern:android:name\s*=\s*"[^"]+"</mark>
    <mark color="red">pattern:android:exported\s*=\s*"true"</mark>
</marks>
```

Max 3 marks per rule. Beyond that, the snippet becomes visually noisy. If you need more than 3
highlights, the rule is probably doing too much - consider splitting it.

Set `<highlight_enabled>false</highlight_enabled>` for file-level structural rules where there is no
specific substring to highlight (e.g., "no USER directive in Dockerfile").

---

### Rule Authoring Guide

Answer these questions before writing `scan_config` values:

**Q1 - What type of file does this rule target?**

| File type | Profile | `match_mode` |
|---|---|---|
| AndroidManifest.xml, plist, web.xml | structured | `file` |
| Kubernetes YAML, Helm charts | structured | `file` |
| Terraform HCL, .tfvars | structured | `file` |
| Dockerfile | structured | `file` |
| Python, JS, PHP, Java, Go, Kotlin, Ruby, C/C++, .NET | code | `line` |
| Bash, PowerShell | code | `line` |
| .env, .properties, appsettings.json, config files | config | `line` |

**Q2 - Does the matched line tell the full story?**

- Yes → `context_type:none`
- Setup / source is above the match → `context_lines_before: 3–5`, `context_lines_after: 0`
- Match opens a block, need to see what's inside → `context_lines_before: 0`, `context_lines_after: 5–8`
- Both sides needed → set both, keep total ≤ 12 lines

**Q3 - Can this rule fire many times in one file for the same conceptual issue?**

- Yes, all instances are the same issue → `aggregate:file`
- Each instance is distinct → `aggregate:none`

**Q4 - Which `report_format`?**

- `context_type:named_groups` → `component_list`
- Detecting secrets / credentials → `secret_list`
- Everything else → `default`

**Q5 - What to highlight?**

| Situation | Config |
|---|---|
| One clear dangerous element | `highlight_target:match`, `color:red` |
| Dangerous pattern within a wider match | `highlight_target:pattern` + tighter regex, `color:red` |
| Match has identity + dangerous attribute | `<marks>` with `cyan` for identity, `red` for risk |
| Rule detects absence (missing flag) | Highlight what IS there in `yellow` |
| Mitigation Identified rule | `color:green` |
| Deprecated / weak, not directly exploitable | `color:yellow` |

**Pre-submission checklist:**
```
[ ] scan_config block is present (even if using all defaults)
[ ] match_mode is appropriate for the file type
[ ] If match_mode=file, regex uses named groups for all meaningful captures
[ ] context_lines_before + context_lines_after <= 12
[ ] aggregate setting is justified
[ ] report_format matches context_type
[ ] highlight colour follows the semantic palette above
[ ] Rule tested on at least one real sample file
[ ] Report output reviewed manually for clarity
```

---

### Complete scan_config Examples

**Kubernetes - privileged container:**
```xml
<scan_config>
    <match_mode>line</match_mode>
    <context_type>lines</context_type>
    <context_lines_before>3</context_lines_before>
    <aggregate>none</aggregate>
    <marks>
        <mark color="red">pattern:privileged\s*:\s*true</mark>
        <mark color="cyan">pattern:- name:\s*\S+</mark>
    </marks>
</scan_config>
```

**Terraform - S3 bucket missing encryption:**
```xml
<scan_config>
    <match_mode>file</match_mode>
    <context_type>named_groups</context_type>
    <aggregate>file</aggregate>
    <report_format>component_list</report_format>
    <marks>
        <mark color="red">pattern:resource\s+"aws_s3_bucket"</mark>
        <mark color="cyan">group:bucket_name</mark>
    </marks>
</scan_config>
```

**JavaScript - hardcoded JWT secret:**
```xml
<scan_config>
    <match_mode>line</match_mode>
    <context_type>lines</context_type>
    <context_lines_before>2</context_lines_before>
    <context_lines_after>2</context_lines_after>
    <highlight_target>pattern</highlight_target>
    <highlight_pattern>(?:secret|key)\s*[:=]\s*["'][^"']{8,}["']</highlight_pattern>
    <highlight_color>red</highlight_color>
</scan_config>
```

**C - unsafe buffer write:**
```xml
<scan_config>
    <match_mode>line</match_mode>
    <context_type>lines</context_type>
    <context_lines_before>3</context_lines_before>
    <context_lines_after>1</context_lines_after>
    <highlight_target>match</highlight_target>
    <highlight_color>red</highlight_color>
</scan_config>
```

---

## Platforms & Rules

Current registries contain 27 platform packs and 73 framework mappings:

| Platform | Frameworks |
|---|---|
| dotnet | aspnetcore, blazor, entityframework, identity |
| php | codeigniter, drupal, laravel, symfony, wordpress, yii |
| java | hibernate, mybatis, spring, springboot, struts |
| javascript | angular, electron, express, nestjs, nextjs, react, vue |
| kotlin | exposed, ktor, springkotlin |
| python | django, fastapi, flask, sqlalchemy |
| go | echo, fiber, gin, gorilla, gorm |
| c | freertos |
| cpp | boost, qt |
| android | cordova-android, flutter-android, ionic-android, jetpack, nativescript-android, reactnative-android, retrofit, room, xamarin-android |
| ios | alamofire, cordova-ios, coredata, flutter-ios, ionic-ios, nativescript-ios, reactnative-ios, swiftui, uikit, xamarin-ios |
| reactnative | expo, reactnative |
| flutter | flutter, flutter-dio, flutter-hive |
| xamarin | xamarin |
| maui | - |
| kmp | - |
| ionic | ionic |
| nativescript | nativescript |
| cordova | cordova |
| bash | - |
| powershell | - |
| dockerfile | - |
| terraform | terraform-aws, terraform-azure, terraform-gcp |
| kubernetes | - |
| ruby | rails, sinatra |
| rust | actix, axum, rocket |
| common | - |

Registered rule packs and semantic coverage are separate; coverage varies by rule
and adapter. Use `-r auto` or select several packs with `-r php,java,javascript`.
Run `python3 dakshscra.py -l RF` for current registrations and file types. The
README support table documents its registry refresh and freshness-check command.

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

DakshSCRA was built as a structured source code review assistant for complex manual security reviews. It is designed to help reviewers move beyond ad hoc pattern searching and toward a more systematic, coverage-oriented review process across large codebases, multiple platforms, and diverse frameworks.

The project was started by **Debasis Mohanty** after many years of using a mix of manual review methods and custom scripting during real-world source code review engagements. The goal was not simply to build another pattern-matching scanner, but to create a flexible code review tool that could guide both reviewers and developers through a structured and holistic analysis workflow.

### Why It Was Built

Debasis has been performing code reviews for more than two decades across a wide range of platforms, frameworks, and architectures. That experience made one point clear: source code review is tedious, mentally demanding, and often difficult to scale when an application becomes large, distributed, or highly customized.

Over time, experienced reviewers learn that the only reliable way to maintain depth and coverage is to structure the review and follow a systematic approach. DakshSCRA was created from that idea. The tool is intended to support disciplined review methodology by surfacing areas of interest, organizing evidence, and performing advanced analysis that helps reviewers focus on what matters most.

Another motivation was the gap in the tooling market. Commercial products that perform strong taint analysis with real control-flow and data-flow tracing are often expensive niche offerings. Many open-source alternatives either stop at pattern checks or require heavy customization while still leaving major coverage gaps. DakshSCRA was written to set a much higher standard for open-source code review tooling, while keeping the architecture flexible enough to support deeper and broader review use cases.

### History

- **Black Hat USA 2022:** DakshSCRA was first introduced privately during the secure code review training **Source Code Review (Raise Your Bar Beyond Grep)**. It was shown to trainees as part of the review methodology and supporting workflow, after having been kept private for years.
- **Black Hat USA 2023 Arsenal:** DakshSCRA made its official public debut as an open-source tool demonstration. This was the point at which the project moved from a private capability into a public release.
- **Public Release:** After the Black Hat USA 2023 Arsenal debut, the project was made publicly available on GitHub so the wider community could use it, study it, and contribute to its continued evolution.

### Project Direction

The long-term direction of DakshSCRA is to remain a structured and systematic code review companion rather than a shallow alert generator. It aims to guide both developers and reviewers with areas of interest, advanced analysis, extensible rule logic, wide platform and framework coverage, and reporting that helps explain why something matters.

A central design goal has always been flexibility. The architecture is meant to be extensible so the tool can be adapted to different review styles, technologies, and depth requirements without forcing users into a narrow scanner-only model.

The broader objective is straightforward: provide a serious open-source code review tool without the ridiculous licensing costs typically associated with advanced commercial offerings, while continuing to push distinctive capabilities that raise the bar for what open-source review tooling can do.

### Author Details

| | |
|---|---|
| Author | Debasis Mohanty |
| Website | [coffeeandsecurity.com](https://www.coffeeandsecurity.com) |
| Email | d3basis.m0hanty@gmail.com |
| Twitter / X | [@coffeensecurity](https://x.com/coffeensecurity) |
| Source | [github.com/coffeeandsecurity/DakshSCRA](https://github.com/coffeeandsecurity/DakshSCRA) |
| License | GNU General Public License v3.0 (GPL-3.0) |

If DakshSCRA has helped your team save significant time, effort, or cost, reduced dependence on expensive commercial tools, improved review coverage, or made code review more structured and effective, feel free to reach out and share your experience. I am always open to thoughtful feedback and interesting conversations.

Found a bug or want to contribute? Open an issue or pull request on GitHub.


## Web results and CLI reports

Web scans save findings, source evidence, cross-references, native analysis and
review state inside the scan runtime directory. They do not generate HTML/PDF
reports or populate the repository's `reports/` directory. The browser reads
these saved results directly. Promoting a suppressed finding updates the saved
results; report regeneration is not required. Explicit download actions may
return data to the browser without creating a report on the server.

CLI scans generate a summary/index HTML with a linked detail subfolder: sidebar navigation,
platform groups, collapsible findings and line-numbered source evidence in HTML;
cover, contents, executive metrics, charts and paginated finding cards in PDF.
HTML, PDF and Word include saved vulnerability assessments, mitigations, attack vectors,
taint paths, cross references, RDL review evidence and coverage limitations. Native
`analysis.html` and `analysis_xref.html` use the same document templates. Reports
work offline without an API or CDN; no frontend build is required to render them.

HTML and PDF templates are in `resources/templates/report_modern.html` and
`resources/templates/pdf_report.html`, with shared analysis sections alongside
them. Repeated baseline predicate evidence and source lines are consolidated,
with every finding location retained and linked to its saved source excerpt.
PDF uses Playwright/Chromium to preserve the print layout; the Docker API/CLI
image includes Chromium and its system dependencies. JSON remains the complete
machine-readable export of saved fields.


### On-demand reports

Open a completed scan’s **Reports** tab, select its project and scan, then choose a report type and HTML, PDF, Word (`.docx`), or JSON. Select **Generate report**; the background job appears below with a download link when ready. Generation uses saved results and does not rerun scanning. Full scan exports include available RDL review evidence and cross-references; these remain review evidence rather than automatically confirmed vulnerabilities. HTML and PDF use the same structured document templates as CLI reports, including the additional analysis evidence shown in the Web UI. HTML downloads as a ZIP containing `index.html` and an `index-files/` subfolder. Extract the entire ZIP and open `index.html`; its summary links to paginated vulnerabilities, attack vectors, flows, cross references, areas of interest, suppressed findings and source evidence. Each detail page links back to the summary and other report sections. Keep the files together when moving the report. PDF and Word are consolidated, paginated documents with contents and section headings. Word includes a contents field that can be refreshed in the word processor. Existing downloaded files remain unchanged; generate a new report to use the current templates.

Recorded traces offer **Text / Graph** views. The graph uses file lanes, source/evidence/sink blocks, recorded handoff connections, a minimap, pan/zoom and a selected-step code inspector. Use Overview, Focus step, Up/Down, Home/End or Go to step to navigate; Expand workspace opens a larger view. Both text and graphical stories use bounded segments for long traces, and every step remains accessible. SVG exports contain the displayed segment. Arrows reflect the recorded order, not invented branches or proof of runtime execution. Newly generated HTML packages include the same offline explorer; extract all files together. PDF and Word preserve static evidence.

System → Disk info groups application storage by project and scan, including generated reports, saved results, runtime files, logs and temporary diagnostics. Inspect individual file sizes and modification dates, select generated reports or diagnostics for cleanup, or delete all data for a finished scan or project. Review the confirmation before deletion: scan history and project configuration remain, but removed results cannot be recovered or exported. Cleanup is blocked while related scans or report jobs are active. Source directories, account data and settings are preserved. Unassigned files are listed for inspection without automatic deletion.

Web scans do not automatically write report files. Explicitly requested exports are retained privately with that scan under `runtime/web_runs_v2/<run>/exports/` and are removed when its scan data is deleted. Opening the Reports tab only lists existing exports. Saved scan data remains available below the generator.

CLI report selection supports the same four formats as web exports, for example `-rpt html,pdf,docx,json`. HTML opens at the scan's `scan/html/report.html` with linked files in `scan/html/report-files/`; PDF is saved to `scan/pdf/report.pdf`, Word to `scan/word/report.docx`, and the complete JSON document to `scan/json/report.json`. Every scan retains its own report directory. Both entry points use one saved-data collector and the same renderers. Complete original saved fields are included in the JSON export and the HTML package's `saved-results.json`; readable documents consolidate repeated RDL evidence while retaining all finding locations and source excerpts. Cross-reference tables show every saved symbol and call site, with unresolved relationships labelled explicitly; raw graph metadata remains available in JSON.

The summary presents native assessments and RDL findings separately, including severity distributions and recorded coverage limits. These populations may overlap and their counts should not be added together. PDF rendering processes bounded sections before assembling one document with linked contents, bookmarks and a global page sequence; long source lines wrap and full file inventories remain printable. Word opens with cached, linked contents; update the contents field explicitly if page numbers are needed. It includes readable cross-reference tables, a catalogue of shared flow references, and linked catalogues of source excerpts and repeated review text/diagnostics. All original diagnostic text is retained; long paragraphs are split for word processor compatibility. For very large scans, HTML offers the quickest way to open the summary and browse specific evidence without loading the entire report into one page.

When effort estimation is requested, CLI and web scans retain `data/estimation.json`. Full exports include that saved estimate; HTML places it on a separate indexed page.

Manual Inspection Recommended contains located partial security evidence with a recorded input-to-operation flow, or a recorded security-state violation. Each item states the unresolved question and investigation steps. Analyzer errors, missing capabilities and timeouts without such evidence are coverage limits, retained separately and excluded from vulnerability-category counts.
