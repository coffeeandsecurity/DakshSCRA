# DakshSCRA Usage Guide

## Contents

- [CFG and DFG across platforms](#cfg-and-dfg-across-platforms)
- [Read this guide](#read-this-guide)
- [What is DakshSCRA?](#what-is-dakshscra)
  - [Distinctive Features](#distinctive-features)
  - [Feature History and Evidence](#feature-history-and-evidence)
  - [Comparative evidence](#comparative-evidence)
  - [What it does](#what-it-does)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Setup](#setup)
  - [Docker (Web UI)](#docker-web-ui)
- [CLI Usage](#cli-usage)
  - [Syntax](#syntax)
  - [Scan Options](#scan-options)
  - [Mode Options](#mode-options)
  - [Output Options](#output-options)
  - [Advanced Options](#advanced-options)
  - [CLI Examples](#cli-examples)
  - [Output Structure](#output-structure)
- [Web walkthrough](#web-walkthrough)
  - [1. Sign in and orient yourself](#1-sign-in-and-orient-yourself)
  - [2. Locate a project and its history](#2-locate-a-project-and-its-history)
  - [3. Configure the scan: Setup](#3-configure-the-scan-setup)
  - [4. Inspect Check Classes](#4-inspect-check-classes)
  - [5. Set exclusions and suppression inputs](#5-set-exclusions-and-suppression-inputs)
  - [6. Choose supporting analysis and output](#6-choose-supporting-analysis-and-output)
  - [7. Add optional Custom RDL packs](#7-add-optional-custom-rdl-packs)
  - [8. Submit, monitor, and edit queued work](#8-submit-monitor-and-edit-queued-work)
  - [9. Open completed results at Summary](#9-open-completed-results-at-summary)
  - [10. Review Areas of Interest](#10-review-areas-of-interest)
  - [11. Triage Vulnerability Analysis](#11-triage-vulnerability-analysis)
  - [12. Follow text and graph evidence](#12-follow-text-and-graph-evidence)
  - [13. Inspect Insights and plan review effort](#13-inspect-insights-and-plan-review-effort)
  - [14. Export and hand off reports](#14-export-and-hand-off-reports)
  - [15. Configure defaults and manage storage](#15-configure-defaults-and-manage-storage)
- [Troubleshooting and recovery](#troubleshooting-and-recovery)
- [Web UI Usage](#web-ui-usage)
  - [Starting the Web UI](#starting-the-web-ui)
  - [Error references](#error-references)
  - [Logging In](#logging-in)
  - [Dashboard](#dashboard)
  - [Projects](#projects)
  - [Scans & Findings](#scans--findings)
  - [Understanding Findings](#understanding-findings)
  - [Reports & Artifacts](#reports--artifacts)
  - [Directory Browser](#directory-browser)
- [Pattern Rules and Semantic Rules](#pattern-rules-and-semantic-rules)
  - [Choosing a review mode](#choosing-a-review-mode)
  - [Understanding outcomes](#understanding-outcomes)
  - [Authoring a Pattern Rule](#authoring-a-pattern-rule)
  - [Guidance and code evidence](#guidance-and-code-evidence)
  - [Validate and try the rule](#validate-and-try-the-rule)
  - [Import an external legacy pack](#import-an-external-legacy-pack)
- [scan_config - Evidence and Presentation](#scan_config---evidence-and-presentation)
- [Platforms & Rules](#platforms--rules)
- [Findings Reference](#findings-reference)
  - [Common Rule Categories](#common-rule-categories)
- [PDF Reports](#pdf-reports)
  - [Generate PDF during a scan](#generate-pdf-during-a-scan)
  - [Generate PDF after a scan (from existing JSON)](#generate-pdf-after-a-scan-from-existing-json)
- [Tips & Common Patterns](#tips--common-patterns)
  - [Starting with an unknown codebase](#starting-with-an-unknown-codebase)
  - [Faster pass on large codebases](#faster-pass-on-large-codebases)
  - [Resuming an interrupted scan](#resuming-an-interrupted-scan)
  - [Suppressing known false positives](#suppressing-known-false-positives)
  - [Checking what rules exist](#checking-what-rules-exist)
- [About](#about)
  - [Why It Was Built](#why-it-was-built)
  - [History](#history)
  - [Project Direction](#project-direction)
  - [Author Details](#author-details)
- [Web results and CLI reports](#web-results-and-cli-reports)
  - [On-demand reports](#on-demand-reports)
  - [Mobile security review coverage](#mobile-security-review-coverage)
  - [Security operation and control context](#security-operation-and-control-context)
  - [Overlapping rule evidence](#overlapping-rule-evidence)

---

## Read this guide

Use the [Web walkthrough](#web-walkthrough) for a first scan, [CLI Usage](#cli-usage) for terminal workflows, and [troubleshooting](#troubleshooting-and-recovery) when a scan or export needs attention. The HTML edition has a searchable contents panel and section links. Both editions contain the same instructions.

This guide covers the public CLI and Web UI workflows, scan configuration, effort planning, reporting and recovery.

## What is DakshSCRA?

DakshSCRA (Source Code Review Assist) is a security-focused static analysis tool built to support manual code review engagements. It helps surface areas of interest in source code through rule-based pattern matching, technology stack reconnaissance, and dataflow taint analysis.

It is a tool for reviewers, not a replacement for one. The goal is to cut down on manual triage time by pointing out relevant code patterns, inter-file data flows, and effort estimates, so the reviewer can focus on what actually matters.

### Distinctive Features

DakshSCRA brings together distinctive capabilities for manual source code review, from file-path areas of interest and effort estimation to software reconnaissance, contextual rules and cross-file analysis.

| Feature | Tag | Why it matters |
|---|---|---|
| **File Path Areas of Interest** | World's First* | Scans file and directory names themselves, alongside code, to flag suspicious paths such as backup files, debug endpoints, configuration dumps and credential files that reviewers often miss. |
| **Scientific Effort Estimation** | World's First* | Produces a quantified estimate of manual-review effort based on codebase size and project signals. Configurable assumptions make engagement planning explicit and repeatable. |
| **Software Reconnaissance** | World's Second* | Detects languages, frameworks and infrastructure from file contents and project structure before scanning. Connects the technology inventory to automatic rule selection, semantic analysis and review planning. |
| **Advanced Semantic and Cross-File Analysis** | Most Advanced Open Source at Release* | Traces user-controlled data from source to sink across supported file boundaries using purpose-built analysis. Advanced Analysis shipped alongside the original RDL in March 2026; RDL v2 extends semantic rule evaluation across files. |

* Based on general searches at the time each feature was introduced. No similar feature was found in open source security code review tools. For effort estimation, no similar approach was found in commercial tools either. Recon came second after Microsoft Application Inspector. Cross-file analysis was the most advanced among open source code review tools at the time of its release.

### Feature History and Evidence

| Feature / milestone | Date | Release | Evidence / scope |
|---|---|---|---|
| Initial beta and file-path rules | 22 October 2022 | v0.1-beta | [Initial release; retained source includes the dedicated file-path rule inventory.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.1-beta) |
| Software reconnaissance (published introduction) | 9 July 2023 | v0.3-beta | [Release notes introduce recon; earlier repository code is separate implementation evidence.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.3-beta) |
| Manual-review effort estimation (implementation) | 29 July 2023 | Implementation commit | [Dedicated estimation module added; not the date of the later fix release.](https://github.com/coffeeandsecurity/DakshSCRA/commit/65d5c6a) |
| Original RDL and inter-file Advanced Analysis | 2 March 2026 | v0.31-beta | [Conditional rule logic and independent cross-file analysis shipped together. Release display date is 2 March; publication timestamp is 1 March 2026 at 18:39 UTC.](https://github.com/coffeeandsecurity/DakshSCRA/commit/d90ba51) |

### Comparative evidence

- **Recon predecessor:** [Microsoft Application Inspector](https://www.microsoft.com/en-us/security/blog/2020/01/16/introducing-microsoft-application-inspector/) (16 January 2020) documents an earlier source-characteristics tool. Daksh SCRA recon is placed second after it.

Dates identify repository or release milestones.

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

Run from the extracted or cloned repository root containing `docker-compose.yml`.
The recommended single-line launcher is `python3 tools/start_webui.py --detach`
(Windows: `py tools/start_webui.py --detach`). It discovers host folders and starts
the Docker portal in the background, preserving existing accounts and scans.

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

Open `http://localhost:3030`

#### Docker cleanup and full purge

Stop without deleting saved data: `docker compose down`.

Two separate scripts are provided. Both preview their scope by default; deletion
requires `--execute` and typing the confirmation phrase. Back up required data first.
On Windows, replace `python3` with `py`.

| Script | Preview | Delete |
|---|---|---|
| Project cleanup | `python3 tools/clean_project_docker.py` | `python3 tools/clean_project_docker.py --execute` |
| All-project Docker purge | `python3 tools/purge_all_docker.py` | `python3 tools/purge_all_docker.py --execute` |

**Project cleanup deletes this Compose project's containers (including orphans),
networks, service images and volumes, including accounts, saved scans and artifacts
in the runtime volume.** Type `DELETE DAKSH` to confirm. A custom Compose project
name must be supplied with `--project-name NAME` if used at startup. Shared service
images may remain if another container uses them. Shared build cache is preserved
because it cannot safely be attributed to this project. Bind-mounted repository
files, scan targets and host-side reports remain on disk.

**All-project purge forcibly removes running and stopped containers across every
project on the selected Docker engine**, then prunes unused images, networks,
anonymous and named volumes, and default-builder cache. After reviewing the
displayed engine identity, enter `Y` or `Yes` to confirm (case-insensitive);
`N`, `No` or Enter cancels. The active Docker context
and `DOCKER_HOST` select the engine, which may be remote. Stop other Docker jobs
first so they do not recreate resources during cleanup. Other Buildx builders,
Swarm-managed resources, plugins, Docker installation/settings and bind-mounted
host files are outside this script's scope. Removal errors stop the script; do not
assume a complete purge after an error.

Inspect usage with `docker system df`. To remove unused shared build cache alone,
use `docker builder prune --all` and review Docker's confirmation; this affects
cache across projects. Restart the portal with `python3 tools/start_webui.py --detach`.

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
| `--rule-mode pattern\|semantic\|both` | Select Pattern Rules, Semantic Rules, or both (default). |
| `--rdl-engine v1\|v2\|both` | Compatibility option for existing scripts. |
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

In **New Scan → Analysis & Output**, selecting **Review effort estimate** automatically selects and locks **Reconnaissance** and **Lines of code**, because they supply the required inventory and technology context. Expand **Effort estimation settings (optional)** to set per-scan reviewer/company rates; otherwise organization defaults apply. Use identical low/high values for a fixed rate, or different values for a range. Overrides are retained with the scan and used in its generated effort report. Completed scans offer Daksh-assisted, targeted, fully manual and AI review scenarios in Insights. Switching scenarios recalculates the estimate immediately. Model 2.1 compares manual, Daksh-assisted and AI-assisted reviewer effort for the same scope. Default planning fractions are 50% of manual time for Daksh and 10% of Daksh time for AI; these are configurable assumptions, not measured speed guarantees. Full-code inspection includes ordinary investigation; additional evidence work shares a configurable budget (default 18% of inspection time) rather than adding a full assessment for every rule site and trace step. Task breakdowns show budget/scenario allocations. Displayed reviewer hours round to half-hour increments (for example, 2.5–3 hours); positive tasks below a quarter-hour show <0.5. Calculations and JSON retain full precision. Reviewer days default to eight productive hours and display in quarter-day increments (0.25, 0.5, 0.75); smaller positive durations show less than 0.25 day. Project-size ballparks cover small, medium, large and extremely large examples. The 75-file, 5,850-LOC reference scope plans approximately 6–7.5 manual days, 3–3.75 Daksh days, and approximately 0.25 AI reviewer day (rounded) at eight productive hours/day. Model execution, remediation and retesting are separate. Targeted selections recalculate immediately. Related files count once; inspection and mapping effort use the selected domains’ share of each file’s recorded domains, so overlapping files do not force every domain subset to cost a full-file review. Equivalent planned inspection LOC is shown separately from actual related-file LOC. This is a planning allocation, not measured source-line coverage. Targeted review cannot exceed the full assisted plan.

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

## CFG and DFG across platforms

Open **Completed Scans → View results → Advanced Analysis → CFG & DFG**. Choose a
language, file and function, then switch **CFG · Control flow** / **DFG · Data flow**.
Select a node to inspect its saved source; pan, zoom, fit, export SVG, or download
the complete selected graph as JSON. These views are available independently of
whether taint or vulnerability findings exist.

The same controls and saved-data format cover all 19 executable-language profiles,
including native/server code and mobile implementation languages. Configuration-only
formats are explicitly not applicable. Read the [platform coverage, detailed
walkthrough, model limits and portable report behavior](#cfg-and-dfg-across-platforms).
Saved graphs do not reread current source. **Build from current source** creates a
separate review snapshot and labels its provenance; it does not alter scan verdicts
or reconstruct missing historical evidence.

## Web walkthrough

### 1. Sign in and orient yourself

Start the Web UI using the commands in [Starting the Web UI](#starting-the-web-ui), open `http://localhost:3030`, and sign in with your configured account. If prompted, complete the initial password change before proceeding. The account menu provides **Change password** and **Log out**. Never place passwords in screenshots or exported review notes.

The sidebar is the main navigation. **Dashboard** summarizes work; **Projects** groups scans by project; **New Scan** configures a job; **Active Scans** shows execution; **Queued Scans** shows waiting jobs; **Completed Scans** opens saved evidence. **System** manages runtime resources and storage; **Settings** controls defaults; **Help** and **About** provide reference material. Use the application controls to switch views; do not rely on a copied URL to restore an in-memory selection.

Read the dashboard counts as a summary of scan activity, not a count of validated vulnerabilities. A successful scan means the job completed; it does not establish that its target is safe. Select a project or use **New Scan** to begin.

### 2. Locate a project and its history

Choose **Projects**. Search by project name, identifier or target; narrow by status, and change the sort order when needed. Open the project row to inspect its paginated history. Each scan has its own status, timestamp and recorded duration. Select **View results** for completed evidence. Use **Project scans** in a scan detail view to return to the history.

Keep a consistent project name for repeat reviews, and check the recorded target before comparing scans. A retained history record whose data has been removed cannot supply the original findings or regenerate its reports.

### 3. Configure the scan: Setup

1. Select **New Scan** in the sidebar.
2. Enter a recognizable project name, such as `Example Store`.
3. Enter `/workspace/example-store` as an illustrative target, replacing it with a directory available to your backend. On Windows, an example is `C:\Review\ExampleStore`; in Docker, use the mounted container path such as `/scan-targets/example-store`.
4. Use **Browse** to select a directory visible to the scan server. The browser does not upload your laptop's source code. A host path must be mounted before a container can read it.
5. Leave technology rules and file types on automatic selection for an unfamiliar or mixed stack. Select explicit supported technologies only when the review scope calls for them.
6. Select **Pattern + Semantic Rules** for combined review, **Pattern Rules** for contextual areas of interest, or **Semantic Rules** for modeled security properties. Expand **Read more** to inspect the distinction.

The right-hand **Scan summary** reflects the draft. Changing tabs preserves it. **Previous** and **Next** move through configuration; selecting a tab directly also works. **Start Scan** remains unavailable until required fields are valid. The optional inter-file analyzer is a separate control under **Analysis & Output**.

### 4. Inspect Check Classes

Select **Check Classes**. Inspect the available security classes and exclude only those outside the agreed scope. Class exclusions apply to this scan; they do not remove rules from the installation. Check the summary's excluded-class count before submitting. If the inventory fails to load, retry it before making scope decisions.

### 5. Set exclusions and suppression inputs

Select **Exclusions**. Enter one project-relative file path or glob per line, such as `vendor/**` or `**/generated/**`. Path matching is case-sensitive. File-type exclusions accept extensions or filename globs, such as `.map` or `*.snap`, and match case-insensitively. Content-keyword exclusions accept literal phrases and exclude the entire matching file, including when the phrase occurs in a comment.

Excluded files are removed from discovery, source checks and analyzer dependency scope. Excluding a helper can interrupt a source-to-sink trace. Prefer narrow exclusions and record the reason in your engagement notes.

For suppression handling, choose the configured baseline, ignore the baseline for this scan, or supply a custom baseline JSON. Custom baseline and review/triage JSON paths must be accessible to the backend within allowed directories. A baseline match is retained as suppressed evidence, rather than proving the code is safe. See [scan configuration](#3-configure-the-scan-setup) for exact semantics and CLI equivalents.

### 6. Choose supporting analysis and output

Select **Analysis & Output**. Choose the report audience, then review reconnaissance, LOC, effort estimation and the optional inter-file analyzer. Recon and LOC start selected. Enabling effort estimation requires both and keeps them selected. Strict reconnaissance is available only with reconnaissance enabled. Choose verbosity and scan recovery behavior according to the engagement.

Review mode controls which rule families run. Report audience controls presentation. Neither is a substitute for inspecting coverage and incomplete evidence. Effort estimates are planning ranges derived from assumptions; adjust those assumptions to your reviewers and scope. See [effort estimation](#13-inspect-insights-and-plan-review-effort).

### 7. Add optional Custom RDL packs

Select **Custom RDL** only when you have an application-specific pack. Enter backend-readable pack locations using the form's controls, and verify the selected-pack count in the summary. For example, use a pack available under `/scan-targets/review-packs/example-store/pack.json`. Do not assume a pack authored for another application proves your application's authorization or business invariants.

See [custom pack authoring](#7-add-optional-custom-rdl-packs) for pack structure and supported contracts. A normal first scan can leave this tab empty.

### 8. Submit, monitor, and edit queued work

Review all values in **Scan summary**, then select **Start Scan** once. Jobs execute one at a time. If another job is running, find the new job in **Queued Scans**; otherwise inspect **Active Scans**. The duration of an executing job starts from execution time, not the time it joined the queue.

Open the active job to inspect **Live Scan Telemetry** and **Log**. Progress describes completed phases; it does not guarantee that the remaining phases take the same time. Use the stop control when you need to interrupt execution, and wait for the stopping state to settle before deciding whether to resume or rerun.

Open a queued job to inspect its waiting state or edit configuration. Editing reserves its queue place and prevents it starting. **Save & requeue** validates and releases the same job; **Cancel edits** restores the saved configuration. **Move to back and keep editing** lets the next job proceed. Leaving the edit view discards unsaved edits and releases the reservation. A disconnected browser leaves it paused; after two minutes, reopen the job to resume or cancel the reservation.

### 9. Open completed results at Summary

Choose **Completed Scans**, locate the desired job, and select **View results**. Check its project, target, status, duration and options before triage. The completed scan opens at **Summary**. Use the scan's result navigation to switch evidence views while keeping the same selected job.

Historical results retain the evidence recorded when that scan ran. Changing defaults or installing new rules does not recompute them. Run a new scan when you need new coverage.

### 10. Review Areas of Interest

Open **Areas of Interest**. Narrow the list using available filters, select a family or finding, and read the rule description, file, line and source excerpt. Investigate whether the matched operation is reachable and whether attacker-controlled input reaches it. For example, a database query is a review lead; a fixed query with correctly bound parameters does not by itself demonstrate SQL injection.

Open **Suppressed Areas of Interests** within this area when you need recorded suppressions. Read the rationale and trace before retaining a suppression. Where promotion is offered, record notes explaining why the item should return to findings. This action changes review classification; it does not repair source code.

### 11. Triage Vulnerability Analysis

Open **Vulnerability Analysis**. Review its summary, then **Confirmed Findings**, **Suppressed False Positives**, **Manual Inspection Recommended**, and **Mitigated Implementations**. Expand a finding family to see individual evidence. Compare the named security property with the code's actual control flow, validation, authorization and deployment assumptions.

A confirmed semantic property is evidence to review, not a guarantee of exploitability. A suppressed item records the modeled reason for withholding that candidate, not overall application safety. Manual Inspection Recommended and coverage limitations explain where the tool could not establish a complete conclusion. Preserve those limits in your assessment.

### 12. Follow text and graph evidence

When a finding has recorded flow evidence, open its **Text** or **Graph** view. Identify the input source, each propagation step, file handoffs, modeled controls and the sensitive sink. Use the graph step controls to move through the path and inspect the corresponding highlighted code. Recheck the file and line at each handoff instead of treating connected nodes as proof of a runtime exploit.

**Advanced Analysis** provides recorded source-to-sink paths, input entry points and symbol cross references where supported. Empty or unavailable analysis can mean the scan did not record that feature, the selected mode did not produce it, or the language/flow was outside modeled coverage. Consult the displayed limitations before drawing a conclusion.

### 13. Inspect Insights and plan review effort

Open **Insights** to inspect file inventory, reconnaissance and effort information. Compare detected technologies with project manifests and actual source. Reconcile unexpected omissions with file-type scope and exclusions. Where effort planning is available, review the assumptions before generating an estimate and distinguish inspection time from finding-triage time.

### 14. Export and hand off reports

Open **Reports**. Select the required scope—Full, Findings, Analysis or Suppressed—then audience and format as offered: HTML, PDF, Word or JSON. Generate the export, wait for completion, and download the resulting artifact. Export generation uses saved scan evidence; it does not rescan the target.

For an HTML ZIP, extract the whole archive and open `index.html`; keep its companion files together so evidence navigation works. Use PDF for a fixed presentation, Word for editable handoff, and JSON for structured processing. Check the first page, scope, audience and finding counts before delivery. Confirm that the selected scope actually contains the evidence your recipient needs. Keep the JSON and source revision when reproducibility matters.

Open **Log** to inspect retained execution output if the expected artifact or analysis is missing. PDF rendering requires Playwright Chromium in the runtime that generates the report, rather than only in your desktop browser.

### 15. Configure defaults and manage storage

Choose **Settings** and use **General**, **Analysis**, **Scan recovery**, or **Effort estimation**. General contains project and date/time preferences; Analysis contains framework coverage and report appearance; Scan recovery controls checkpoint and resume behavior; Effort estimation contains planning rates. Expand or collapse groups, edit the intended values, then use the save control. These are defaults; check each new scan's draft before submitting.

Choose **System** to inspect runtime resources and disk use. Before removing saved data, export anything you need to retain. Removing a completed scan's data deletes evidence and generated reports while retaining its history record; clearing that record is a separate operation. Active jobs are protected. Read the confirmation's project and scan scope carefully.

## Troubleshooting and recovery

| Symptom | What to check | Next action |
|---|---|---|
| Cannot sign in | Configured account, initial startup password, session state | Inspect startup logs for first-run credentials; complete the password change if prompted. |
| Target absent in Browse | Backend filesystem and container mounts | Use a server-visible example-equivalent path; make the intended source available to that runtime. |
| Start Scan unavailable | Required target and custom baseline fields | Return to Setup or Exclusions, complete the missing value, and recheck the summary. |
| Job remains queued | Running job or an edit reservation | Inspect Active Scans and release or cancel queued edits. |
| No findings or missing files | Selected rules, file types, exclusions and scan log | Confirm scope and coverage, then run a new scan with corrected inputs. |
| Analysis unavailable | Recorded scan mode and supporting-analysis settings | Check recorded configuration; rerun with the needed feature and supported scope. |
| Live log stops updating | Connectivity and authentication | Refresh, sign in if needed, and reopen the same job before submitting a duplicate. |
| Export fails | Saved evidence, export status and browser runtime | Inspect the reference code and server logs; install Chromium in the report runtime if missing. |
| HTML export navigation fails | Archive extraction and companion assets | Extract the complete ZIP and open its `index.html`. |
| History row has no evidence | Scan data was removed | Use a retained export or perform a new scan; the history record cannot reconstruct deleted data. |

For an API failure, copy the displayed reference code and correlate it with `runtime/api-errors.log` or container logs. Avoid putting credentials or private source paths into shared bug reports. See [Error references](#error-references) for request-log behavior and [Resuming an interrupted scan](#resuming-an-interrupted-scan) for CLI recovery.

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

Open `http://localhost:3030` in a browser.

To change the port:

```bash
DAKSH_PORT=9090 python3 tools/start_webui.py
```

### Error references

API and backend failures show a short message with a reference code. Use that code to find the technical error in `runtime/api-errors.log` or the API container logs. Gateway requests carry the same code in the nginx access log, together with the upstream status and connection number. The connection number links to nginx's detailed error log.

For Docker deployments, check `docker logs daksh-api` and `docker logs webui`. Filter the output using the reference code shown on the page. Request bodies and authentication headers are not included in request logs. If a network failure prevents a request from reaching the server, the browser retains up to 20 diagnostics for one day and submits them after connectivity and authentication return. Those entries are marked as client reports.

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
selection. Pattern + Semantic Rules is the default; Semantic Rules runs semantic properties without native text baselines; Pattern Rules retains areas of interest for investigation. See rule modes
for all controls, defaults and CLI equivalents.

For large projects, completed analyzer findings use temporary SQLite storage in
the system temporary directory while other targets run. Reports remain ordinary
JSON, with full evidence and exact observation counts. Scratch storage is removed
when the stage finishes or raises an exception; sufficient temporary disk space is
required. Active source graphs and optional review/report processing still require
memory proportional to their inputs.

#### Active Scans

Jobs run one at a time. Active Scans shows running and stopping jobs, with Live
Scan Telemetry and Log. The Duration column updates each second for running or
stopping scans, starting from execution time. Finished scans show their recorded
total execution duration. Queued Scans lists waiting jobs in execution order, next
at the top and newest at the bottom. Opening a queued scan shows its waiting
state and lets you delete it or edit its settings.

Editing reserves the scan's place and prevents it from starting. If it reaches
the front, the queue waits for you; use **Move to back and keep editing** to let
the next scan proceed. **Save & requeue** validates the settings and releases the
same scan for execution at its current position. **Cancel edits** keeps the saved
settings. Leaving the view discards unsaved edits and releases the reservation.
If the browser closes or loses its connection, the scan stays paused. After two
minutes, reopen it to resume or cancel editing; it cannot start until released.

#### Completed scan details

Completed Scans and project history open saved results at **Summary**, with recorded
scan configuration, review metrics and links into the evidence views.

- **Areas of Interest:** contextual v1 source and file-path review leads.
- **Vulnerability Analysis:** v2 Summary, Confirmed Findings, Suppressed False
  Positives, Manual Inspection Recommended and coverage limitations. A confirmed rule match
  establishes the named security property, not exploitability.
- **Advanced Analysis:** recorded v2 source-to-sink paths, input entry points and
  symbol cross references, with Text and Graph views where evidence is available.
- **Insights:** file inventory, recon and review effort.
- **Suppressed Areas of Interests (under Areas of Interest):** recorded rule, version, rationale and trace; review an
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

Recorded paths describe modeled input and propagation. A complete path reaches a
modeled destination; a partial path has unresolved steps. Neither alone proves
external reachability or an exploitable vulnerability.

| Field | Description |
|---|---|
| Confidence | Evidence confidence (`high`, `medium`, or `low`), with the recorded reason; separate from review priority and potential severity |
| Source | Recorded input origin; external control may remain unresolved |
| Sink | Modeled destination, if present; an unresolved call boundary is not a confirmed security sink |
| Trace | Ordered list of intermediate steps connecting source to sink |
| Cross-file | Whether the flow spans multiple files |

**Reading confidence and ratings:**

- Confidence describes observation or modeled-path quality. Extra files or steps do not by themselves prove stronger confidence or greater impact.
- Heuristic scores use a 0–100 review scale; they are not calibrated probabilities or standardized vulnerability scores.
- Review priority, confidence and severity are separate. Inferred origins and unresolved destinations need verification before treating a path as externally controlled.
- Build variants, launcher-only entries and domain-specific network exceptions can change the applicable severity. Read the rating context and verify the selected release/runtime configuration.
- Mobile text/OTP callback input records can be source-only partial paths. Missing propagation is shown as unresolved; no final sink is invented.

#### Recon Results

Recon output is grouped by technology type (Framework, Language, Frontend, Backend, etc.). Each detection shows the technology name, confidence level, and which files were used as evidence.

Use `--recon --rs` to filter to high/medium confidence only when the output is too noisy.

---

### Reports & Artifacts

Open the completed scan's **Reports** tab to generate HTML, PDF, Word (`.docx`), or JSON from saved results. Choose Full Scan, Areas of Interest, Advanced Analysis, or Suppressed Findings, then download the completed background job. Web scans retain data without automatically creating report files.

Choose **Report audience** in **New Scan → Analysis & Output**. **Both** is selected by default and disables the individual audience controls; clear Both to select **Developer Mode** or **Code Review Mode**. The selection is saved with the scan and controls guidance in the results workspace. Reports also offer this selection when generating an export.

Developer Mode provides implementation checks: verify that the required protection exists and is effective before proposing a change. Code Review Mode examines reachable callers, attacker influence, effective mitigations, exploitation prerequisites and possible impact. In Both mode, the order is **Security impact → Review guidance → Recommendations**. Areas of interest remain review leads. The saved scan retains both perspectives; single-audience exports omit the unselected guidance while retaining recorded evidence.

For CLI reports, use `--report-audience developer`, `--report-audience code_review`, or `--report-audience both` (default). This option changes presentation, not the checks or scan verdicts.

Extract an HTML ZIP and open `index.html` first. Its lightweight summary links to indexed, paginated detail pages; keep the files together for offline navigation. PDF provides linked contents and bookmarks, Word provides editable sections and linked contents, and JSON retains the original saved fields. Saved data and the scan log remain available alongside the report generator. See [On-demand reports](#on-demand-reports) for format details.

Software Reconnaissance starts with a technology overview and groups evidence by category and technology. Each detection shows recorded file/directory counts, detection confidence, a directory table and saved sample files. Paths inside the target are shown relative to it; original paths remain in JSON. Totals include overlapping technology matches and are not unique file counts. Generate a new Full scan report to apply the current layout to a saved scan; existing downloads remain unchanged.

The **Incomplete Source Analysis** finding lists files that cannot receive complete source checks, with a reason and required action for each file. It is produced independently of optional reconnaissance and is retained in normal findings and exports. Decode compiled Android XML, decompile bytecode or obtain original source, recover failed methods, restore unreadable files, and review native binaries separately before treating the assessment as complete. A successful scan means the job finished; it does not mean every input was fully analyzed.

For Android, scan decoded Java/Kotlin and decoded XML rather than a ZIP-extracted
APK alone. Recon identifies DEX bytecode and binary Android XML under **Analysis
Coverage**, with a reminder that source rules do not decode these formats. Native
ELF libraries are recorded as binary artifacts requiring separate review. Validated
Firebase and Google Play services properties appear as **Packaged SDK Metadata**;
versions are packaging declarations, not verified runtime versions, vulnerability
checks or proof that the app exercises a dependency. Active Java decompiler failure
stubs are also recorded as coverage limitations. Decoded or obfuscated code can
still have incomplete methods and unresolved calls; no findings does not establish
security. Preserve original artifacts when preparing a separate decoded-source scan.

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

## Pattern Rules and Semantic Rules

**Pattern Rules identify areas of interest using patterns and contextual conditions. A reviewer investigates whether they represent actual security issues.**

**Semantic Rules provide stronger evidence by analyzing code relationships, input propagation and modeled protections. They can support a finding or suppression, but incomplete modeling, deployment settings and runtime behavior can still affect the conclusion.**

Suppressed areas of interest show the rule-filter decision separately from trace coverage. A failed Pattern condition does not prove a mitigation. Older SQL conditions may check markers across the entire file, so parameters on another command do not establish protection at the selected operation. Saved same-file semantic diagnostics and missing modeled entry points are shown explicitly; an unrecorded or incomplete trace remains a manual review question. The original technical reason and evaluation trace remain available, and exports retain these limitations without rewriting saved verdicts.

### Choosing a review mode

- **Pattern + Semantic Rules** (`--rule-mode both`, the default): retain pattern-based areas of interest and add supported semantic evidence.
- **Pattern Rules** (`--rule-mode pattern`): run pattern and contextual checks for manual investigation.
- **Semantic Rules** (`--rule-mode semantic`): run semantic properties and supported input/flow analysis; skip native text-based baseline packs.

```bash
python3 dakshscra.py -r auto -t /path/to/source --rule-mode both
python3 dakshscra.py -r javascript -t /path/to/source --rule-mode pattern
python3 dakshscra.py -r java -t /path/to/source --rule-mode semantic
```

`-r` still selects platforms; detected frameworks retain their platform-specific directories. Optional inter-file analyzer output is controlled separately by `--skip-analysis`. Custom Semantic Rule manifests continue to use `--custom-rdl PACK.json` and require semantic or both mode.

For existing scripts, `--rdl-engine v1|v2|both` remains a compatibility option. Legacy `v2` includes native text-based baselines; it is not equivalent to the new semantic-only mode. Conflicting old/new selections are rejected. Existing saved scans retain their recorded engine and results.

### Understanding outcomes

| Outcome | Meaning |
|---|---|
| Supported finding | The modeled issue conditions are satisfied; reviewer confirmation is still required. |
| Suppressed | Evidence satisfies a defined suppression condition; this does not establish overall safety. |
| Unresolved | Available evidence or analysis coverage is insufficient to decide. |
| Reviewer-confirmed | A reviewer has verified the issue. |

A rule match or complete recorded flow does not establish exploitability. RDL v2 is the internal Semantic Rule language/engine; its text-based baseline checks remain Pattern Rules.

### Authoring a Pattern Rule

Each check has one YAML file containing its candidate pattern, conditions, guidance and optional evidence settings. Built-in packs preserve the existing platform/framework layout:

```text
rules/scanning/platform/
  javascript/javascript.rules/*.yaml
  javascript/framework/react.rules/*.yaml
  java/java.rules/*.yaml
  java/framework/spring.rules/*.yaml
  mobile/android/android.rules/*.yaml
  common.rules/*.yaml
  filepaths.rules/*.yaml
```

A pack's `_pack.yaml` declares `format: daksh-pattern-pack/v1` and `layout: categories` (source checks) or `flat` (path checks). It is not a check. Add a file to the owning pack and give it a globally unique dotted ID; keep IDs stable across edits. The catalog and scanner discover the new file automatically. No separate XML, RDL v1 file, baseline manifest edit or scanner-code change is required for ordinary pattern/condition rules.

For example, save this as `rules/scanning/platform/javascript/javascript.rules/dynamic_evaluation_review.yaml`:

```yaml
format: daksh-pattern-rule/v1
id: javascript.core.dynamic_evaluation_review
title: Dynamic Evaluation Review
category: Code Execution
detection:
  pattern: '\beval\s*\('
  conditions:
    - WHEN PRESENT ${pattern}
reporting:
  type: area_of_interest
  reason: Review whether externally influenced text reaches eval.
  description: Dynamic evaluation requires investigation of its inputs.
  remediation: Prefer fixed operations and data-only inputs.
  reviewer: Verify callers, input origins and the execution context.
scan_config:
  match_mode: line
  aggregate: file
  context_lines_before: 3
  context_lines_after: 2
  highlight_enabled: true
  highlight_color: red
```

`conditions` is optional for regex-only rules. `${pattern}` reuses the candidate expression so it needs only one edit. Conditions use `WHEN PRESENT`, `WHEN MISSING`, `WHEN EXPR`, `WHEN FILE_NAME_IS`, `WHEN FILE_PATH_MATCHES`, `WHEN CURRENT_FILE_MATCHES`, `UNLESS CURRENT_FILE_MATCHES`, or `OBSERVE PROJECT_HAS_GLOB`. Boolean expressions support `PRESENT:`, `MISSING:`, `&&`, `||` and `!`. Project observations provide context rather than proving protection.

Candidate patterns retain their configured regex flags and match mode. Undelimited condition regexes are case-insensitive/multiline; `/pattern/ims` declares explicit condition flags. File/path conditions operate on the full inspected context. A protection elsewhere in a file can affect a whole-file condition: use Semantic Rules when the decision requires call-local or flow-specific evidence.

Legacy per-rule XML filtering is retired and is not recreated in Pattern Rules. Candidate patterns surface areas of interest for review; do not suppress a candidate because unrelated words or protections appear elsewhere in a file. Semantic Rules evaluate modeled protections separately. Use the scan Exclusions settings for intentional keyword, path and file-type scope restrictions. The XML importer rejects legacy per-rule filters so they must be reviewed explicitly. `reporting.reason`, `fail_reason` and `trace` explain decisions; `description`, `impact`, `remediation` and `reviewer` supply review guidance. The optional `order` integer controls pack order. Unknown fields, invalid regexes/conditions and duplicate identities are rejected rather than silently ignored.

### Guidance and code evidence

The unified file retains all the information from the original XML check:

| Original XML field | Pattern Rule field | Result |
|---|---|---|
| `rule_desc` | `reporting.description` | What matched and what needs investigation |
| `vuln_desc` | `reporting.impact` | Conditional security consequence |
| `developer` | `reporting.remediation` | Original developer guidance and correction |
| `reviewer` | `reporting.reviewer` | Original reviewer guidance |
| `scan_config` | `scan_config` | Match mode, context, grouping, highlighting and presentation |

Add `reporting.review_steps` and `reporting.recommendations` as lists of actionable strings. The scanner includes them after the original reviewer and developer text in saved results and reports. They describe the evidence to check and how to validate a correction; they do not change matching or automatically confirm an issue. Guidance also accompanies new suppressed source matches.

For an input rule such as `requestParameters`, review who supplies the input, trace its actual destinations, inspect the protection at each use, and verify resource authorization and error paths. Recommend controls appropriate to the destination rather than generic sanitization of every value.

```yaml
reporting:
  description: Reads externally influenced request data; trace where it is used.
  impact: Unsafe use may expose data or alter an operation; reading input alone is not a vulnerability.
  remediation: Validate input on the server and protect each destination appropriately.
  reviewer: Inspect the reachable input-to-operation path and its effective protections.
  review_steps:
    - Identify the caller, input type and trust boundary.
    - Inspect validation, destination-specific protection and resource authorization.
    - Record evidence for confirmation or suppression; retain unresolved questions.
  recommendations:
    - Bind database values as parameters and encode output for its rendering context.
    - Test rejected input, unauthorized access and a valid protected case.
scan_config:
  match_mode: line
  context_lines_before: 3
  context_lines_after: 2
  aggregate: none
  highlight_enabled: true
  highlight_target: match
  highlight_color: red
```

Context counts, aggregation, named groups and configured colors survive migration unchanged. New source evidence records token offsets and colors using the scanner's Python regex, so the UI does not need to reinterpret it in JavaScript. Highlighting can target the match, the line, capture groups or a separate pattern. `marks` supports multiple `color`/`spec` entries, for example `pattern:android:exported\s*=\s*"true"`. Disabled highlighting stays disabled. Aggregated results retain surrounding code context, and older saved results remain readable.

### Validate and try the rule

```bash
python3 tools/rdl_lint.py rules/scanning/platform/javascript/javascript.rules/dynamic_evaluation_review.yaml
python3 tools/rdl_lint.py rules/scanning/platform --json
python3 dakshscra.py -r javascript -t /path/to/small-fixture --rule-mode pattern --skip-analysis
```

Check both a positive example (`eval(input)`) and a negative example (`JSON.parse(input)`), then inspect retained locations, context and suppression reasons. Linting verifies rule structure; it does not measure vulnerability accuracy.

Semantic Rules remain versioned `.rdl` definitions under `rules/scanning/logic/rdl/v2/`. Semantic authors also need the relevant language capabilities and property registration or a custom manifest. Derived native baseline definitions are compatibility artifacts; author Pattern Rules in YAML rather than editing those copies.

### Import an external legacy pack

```bash
python3 tools/rdl_migrate.py /path/to/old-pack.xml --pattern --logic-root /path/to/scanning --output /path/to/imported.rules
python3 tools/rdl_lint.py /path/to/imported.rules
```

The importer reads XML metadata and referenced RDL v1 logic once. It requires an empty destination and leaves the input files untouched. Built-in authoring uses unified Pattern Rules; external legacy packs remain import-compatible during transition.

## scan_config - Evidence and Presentation

`scan_config` is an optional YAML mapping in the same Pattern Rule. It controls evidence collection and presentation, not whether a review lead is a confirmed issue.

| Fields | Purpose |
|---|---|
| `match_mode`, `aggregate` | Matching granularity and grouping (`line` / `file` in the example). |
| `context_type`, `context_lines_before`, `context_lines_after` | Select the source context surrounding a match. |
| `context_pattern`, `context_depth` | Configure bounded structured context. |
| `report_format` | Choose the supported evidence layout. |
| `highlight_enabled`, `highlight_target`, `highlight_groups`, `highlight_pattern`, `highlight_color` | Configure highlighting. |
| `marks` | Optional list of `color` / `spec` mappings for multiple highlights. |

Omitted settings use the scanner defaults. Preserve match/context settings when migrating a rule, and inspect rendered results using representative source files.

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

**Accumulated generated files** lists audit/replay outputs, report-restoration exports, Python bytecode caches, diagnostic/rotated logs and abandoned analyzer scratch. Each area shows total size, eligible size and file counts, including areas currently using zero space. Select areas and choose **Clean selected areas**, or use **Clean all eligible areas**, then review the confirmation. Previous cleanup activity includes the earlier audit/report cleanup when that local history is available.

Only allowlisted generated files at least 24 hours old are eligible. Referenced fixtures, scripts, summaries, source copies, tracked files, installed dependencies, Git, user media, current logs and account databases stay. Active analyzer scratch holds a process lease; old scratch without a recognized lease is retained. General cleanup waits for scans and report jobs to finish. Sizes are logical file sizes; actual filesystem space reclaimed can differ. Docker images, build cache and volumes remain separate from this file cleanup.

The CLI uses the same generated-file policy. Preview is the default:

```bash
# List local cleanup areas and their used/eligible sizes.
python3 tools/cleanup_storage.py

# Preview or execute a selection; repeat --select for more areas.
python3 tools/cleanup_storage.py --select area:audit-output
python3 tools/cleanup_storage.py --select area:audit-output --execute

# Clean all eligible local generated areas without a confirmation prompt.
python3 tools/cleanup_storage.py --all --execute --force

# List portal areas and saved scan/unit IDs, including Docker runtime storage.
python3 tools/cleanup_storage.py --url http://localhost:3030 --username admin

# Explicitly delete a finished scan's data while retaining its history.
python3 tools/cleanup_storage.py --url http://localhost:3030 --username admin --select scan:RUN_UUID --execute
```

Portal mode securely prompts for the password, or reads it from `DAKSH_CLEANUP_PASSWORD` (change the variable name with `--password-env`). Temporary CLI login sessions are released at completion. Local mode retains runtime diagnostics and saved scan data; use portal mode for those. `--all` selects eligible generated areas and independently removable scan units; complete saved findings require an explicit `scan:RUN_UUID` selection. A whole scan already contains its units and is counted only once. `--force` requires `--execute` and skips confirmation without bypassing protection or the 24-hour age threshold. `--json` provides machine-readable sizes and cleanup results. Failed files are reported and produce a nonzero exit status; refresh the inventory before retrying.

Web scans do not automatically write report files. Explicitly requested exports are retained privately with that scan under `runtime/web_runs_v2/<run>/exports/` and are removed when its scan data is deleted. Opening the Reports tab only lists existing exports. Saved scan data remains available below the generator.

CLI report selection supports the same four formats as web exports, for example `-rpt html,pdf,docx,json`. HTML opens at the scan's `scan/html/report.html` with linked files in `scan/html/report-files/`; PDF is saved to `scan/pdf/report.pdf`, Word to `scan/word/report.docx`, and the complete JSON document to `scan/json/report.json`. Every scan retains its own report directory. Both entry points use one saved-data collector and the same renderers. Complete original saved fields are included in the JSON export and the HTML package's `saved-results.json`; readable documents consolidate repeated RDL evidence while retaining all finding locations and source excerpts. Cross-reference tables show every saved symbol and call site, with unresolved relationships labelled explicitly; raw graph metadata remains available in JSON.

The summary presents native assessments and RDL findings separately, including severity distributions and recorded coverage limits. These populations may overlap and their counts should not be added together. PDF rendering processes bounded sections before assembling one document with linked contents, bookmarks and a global page sequence; long source lines wrap and full file inventories remain printable. Word opens with cached, linked contents; update the contents field explicitly if page numbers are needed. It includes readable cross-reference tables, a catalogue of shared flow references, and linked catalogues of source excerpts and repeated review text/diagnostics. All original diagnostic text is retained; long paragraphs are split for word processor compatibility. For very large scans, HTML offers the quickest way to open the summary and browse specific evidence without loading the entire report into one page.

When effort estimation is requested, CLI and web scans retain `data/estimation.json`. Full exports include that saved estimate; HTML places it on a separate indexed page.

Manual Inspection Recommended contains located partial security evidence with a recorded input-to-operation flow, or a recorded security-state violation. Each item states the unresolved question and investigation steps. Analyzer errors, missing capabilities and timeouts without such evidence are coverage limits, retained separately and excluded from vulnerability-category counts.

Global date and time preferences are shared by the web UI and CLI. Set them in **Settings → Global date and time**. The defaults are `MM-DD-YYYY`, 24-hour time and UTC. Choose `DD-MM-YYYY` or `YYYY-MM-DD`, 12-hour time, and any valid IANA time zone. New scans capture these preferences; web displays use the current global settings. Existing exported files remain unchanged. Machine timestamps and scan IDs retain their canonical format.

```bash
python dakshscra.py --settings
python dakshscra.py --save-settings --date-format MM-DD-YYYY --time-format 12h --timezone Pacific/Auckland
python dakshscra.py -r auto -t ./src --date-format DD-MM-YYYY --time-format 24h --timezone UTC
```

The last command overrides preferences for that scan without saving them globally.

### Mobile security review coverage

Mobile **Security impact** text includes conditional attack mechanisms and their
prerequisites. These hypotheses do not establish exploitability or create a taint
path. Configuration-only findings explain why a taint graph is unavailable.

In **Advanced Analysis**, choose **Semantic rule paths** for RDL v2 evidence or
**Inter-file analyzer** for the separate saved analyzer results. The latter requires
the optional analyzer to have run. Text and Graph show recorded paths where
available; missing endpoints stay unresolved. Updating the display cannot recover
evidence that was never recorded. See [mobile graph availability and CFG/DFG distinctions](#mobile-security-review-coverage).

Mobile scans export **Mobile Review Evidence** as `mobile_review.json` and `mobile_review.html` in the scan data directory, accessible through Reports. The export connects build source sets and module namespaces, credential stores and independent backup/transfer sections, sensitive callback logging, cleanup callers, native bridge identities, client API requests and retained semantic outcomes. Exact React Native module/method and supported Flutter channel/method pairs link their source endpoints; dynamic or ambiguous registrations remain unresolved. A supplied backend handler can be recorded as a source candidate without asserting server authorization.

Additional checks review release builds referencing debug signing, provider streams sized with `available()` and read once without checking the count, missing or empty iOS purpose descriptions associated with supported resource APIs, and credential-related preference writes potentially included by backup policy. OTP callback parameters, aliases and template interpolation are modeled for console logging. Preferences checks include explicit editors, chained writes and supported Kotlin receiver scopes. Generated or localized configuration, unsupported syntax and evidence budgets remain explicit limitations.

Android review also connects supported enqueued Volley credential parameters to locally resolved HTTP endpoints. Backup contracts keep cloud and device-transfer rules independent, including defaults for omitted modes. Imported native text fields and supported barcode scanner callbacks can retain source-only input evidence when deeper propagation is unresolved; matching structural sources are not duplicated. Outgoing URI intents are reviewed separately from nested-intent forwarding. These observations require selected-build, value and runtime confirmation.

Advanced Analysis retains unresolved call traces for investigation and labels them separately from resolved sensitive-sink paths. Nearby validation words, URL parsers, capability checks and wildcard origin policies do not establish an effective security control. Launcher filters, action identifiers, document URLs and cosmetic randomness are distinguished from their security-sensitive counterparts.

Mobile security coverage includes native Android and iOS and the supported hybrid frameworks: React Native, Flutter, Ionic/Capacitor, Cordova, NativeScript, MAUI, Xamarin and Kotlin Multiplatform. Framework packs include Jetpack, Room, Retrofit, UIKit, SwiftUI, Core Data, Alamofire, Dio, Hive and Expo. Applicable native rule overlays also run for hybrid source selections.

| Review area | Source checks and common edge cases |
|---|---|
| Local data and secrets | Preferences versus secure storage, backup and device transfer, file sharing, keychain lock-state and migration policy, restored keys, reinstall persistence, and plaintext fallback after storage failure. |
| Network trust | Cleartext and domain exceptions, hostname and certificate callbacks, mixed content, client-specific trust decisions and release configuration. Missing pinning alone does not prove insecurity. |
| Web content and native bridges | JavaScript, navigation and message origins, file access, web permissions, geolocation and script execution; inspect subframes, redirects and individual WebView instances. |
| Authentication and external entry points | Exported components, inherited permissions, URI grants, nested intents, deep links, biometric key binding, proof-key protection and local authentication overrides. |
| Cryptography and code safety | Weak or constant keys and algorithms, security randomness, decoded object types, archive destinations and untrusted dynamic modules. Distinguish non-security hashes and checksums from authentication. |
| Privacy and sensitive UI | Logs and crash payloads, clipboard, screenshots, input prediction, identifiers and sensitive platform capabilities. A permission or API declaration is a review surface, not evidence of malicious collection. |
| Release and update behavior | Debug variants, merged resources, remote code, signed updates, compatibility and rollback settings. Resolve the actual build and active resource before confirming an issue. |

Pattern Rules preserve broad candidates, including multiline declarations and calls. They do not suppress a candidate merely because a protection keyword occurs elsewhere. Semantic reviews add declaration association, source-operation context and modeled input propagation. Semantic-only scans retain these refined mobile checks and flows while omitting Pattern baselines. Scan scope continues to use the selected keyword, path and file-type exclusions. Malformed or unresolved supported configuration is reported as incomplete evidence rather than a safety result. Candidate, supported, suppressed and unresolved outcomes remain distinct.

Device behavior, compiled artifacts, server authorization, live association files, dependency advisories and controls outside the supplied source still require independent verification. Root/jailbreak, anti-tamper or certificate-pinning markers alone cannot establish security. Source coverage is not a security certification or a promise of zero false negatives.

### Security operation and control context

Pattern packs include candidates for response-origin construction, bulk field binding, literal security-configuration fallbacks, explicit anonymous operations and tenant-associated data constraints in applicable platform/framework scopes. These candidates retain source context and review guidance. Comments and documentation strings do not become executable bulk-binding or anonymous-operation evidence. A tenant constraint candidate is an invitation to verify its provenance, not a claim that the constraint is missing or effective.

Semantic operation models add argument-specific evidence:

| Review | Recorded evidence | Remaining verification |
|---|---|---|
| Response origin | An untrusted input reaches the value of an identified response-origin header through supported local calls. Header names and unrelated arguments are distinguished. | Approved-origin validation, credentials, resource permissions and the actual browser response. |
| Bulk binding | An input reaches a supported bulk-copy, binding or typed model-deserialization operation. Spring and Apache BeanUtils argument order differs; JavaScript Object.assign may have several sources. | The exact writable fields and operation permissions. A data-only deserialization is not automatically unsafe object construction. |
| Cryptographic fallback | An explicit literal configuration fallback reaches a modeled key argument. Supported inline defaults, coalescing expressions and an exact empty-environment branch are retained; overwrites can break the recorded path. | Whether the failure path is reachable and the fallback is active in the deployed environment. |
| Authorization declarations | Supported method/class attributes or Python decorators are associated with the containing operation. Anonymous overrides remain explicit. | Whether the declaration executes and protects this specific user, resource and operation; upstream or external controls can remain unresolved. |
| Typed C# model fields | A typed deserialization can be associated with an unambiguous model in the inspected source scope, including declared setters and serializer attributes. | Custom serializers, inheritance and the effective writable-field policy. Ambiguous definitions remain unresolved. |
| Tenant isolation | Tenant-associated data operations remain candidates for application-specific review. Optional custom packs can encode a supplied trust boundary or invariant. | The trusted tenant identity and exact read/write constraint. Missing marker text does not establish a cross-tenant vulnerability. |

Models are registered by source language and inherited by applicable framework selections, including native source layers in mobile projects. Registration does not mean every API in a framework is modeled. Declarative infrastructure and container files retain configuration review; they do not receive an application call graph. Shell and experimental language constructs may have candidate checks without these semantic operation families.

New findings retain control context and model-field evidence in their JSON, with concise context in reviewer guidance. Control declarations never automatically suppress a candidate. Unsupported syntax, unresolved calls and budget limits remain explicit; an incomplete or no-match result does not establish application safety. Existing saved scan evidence is preserved. Run a fresh scan with `--rule-mode both` to compare Pattern and Semantic outcomes after upgrading.

### Overlapping rule evidence

The same source observation can be reported by baseline, framework and contextual rules. Result cards group these observations by issue family; missing or different CWE metadata does not create a second card. Counts use unique located occurrences, with distinct source-to-destination paths kept separate. Each occurrence retains its contributing rules, explanations and evidence. Areas of Interest also counts a shared source location once across platform aliases.

Filtered scan totals use the same occurrence identities as the paginated cards. A page shows only its available contributions; rule/file evaluation counts remain separate from unique finding counts. Older scan indexes are upgraded without changing original evaluation records or reviewer decisions. Existing portal results can use the corrected grouping without a new scan; regenerate standalone exports to update their presentation.
