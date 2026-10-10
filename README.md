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
| Private training release | 2022 (Black Hat USA) | Private student release | [Distributed privately to Black Hat USA 2022 training students before the public web release.](https://github.com/coffeeandsecurity/DakshSCRA/blob/fe878be/README.md) |
| Initial beta and file-path rules | 22 October 2022 | v0.1-beta | [Initial release; retained source includes the dedicated file-path rule inventory.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.1-beta) |
| PDF and HTML reports | 23 May 2023 | v0.2-beta | [Release notes list PDF/HTML report generation and scanning-rule updates.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.2-beta) |
| Software reconnaissance (published introduction) | 9 July 2023 | v0.3-beta | [Release notes introduce recon; earlier repository code is separate implementation evidence.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.3-beta) |
| Manual-review effort estimation (implementation) | 29 July 2023 | Implementation commit | [Dedicated estimation module added; not the date of the later fix release.](https://github.com/coffeeandsecurity/DakshSCRA/commit/65d5c6a) |
| Early Android manifest and Kotlin checks | 27 April 2024 | v0.16-beta | [Introduced Android manifest misconfiguration checks and Kotlin-specific checks; module described as early development, with broader coverage still in progress.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.16-beta) |
| Multi-platform scan flags (initial design) | 4 November 2024 | v0.20-beta | [Added comma-separated platform selection with -r; initial implementation did not yet isolate each platform rule set to its own file types.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.20-beta) |
| Platform-agnostic auto scanning | 10 November 2024 (release listing) | v0.23-beta | [Automatic platform/rule selection; implementation commit dated 11 November.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.23-beta) |
| PDF rendering upgrade | 21 July 2025 | v0.29-beta | [Migrated PDF export from WeasyPrint to Playwright and Chromium; added HTML-size-based timeouts for large reports and cross-platform setup instructions.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.29-beta) |
| Initial iOS scanning support | 2 March 2026 | v0.31-beta | [Added iOS rules and Swift/Objective-C/configuration file selection; later releases expanded coverage.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.31-beta) |
| Original RDL and inter-file Advanced Analysis | 2 March 2026 | v0.31-beta | [Conditional rule logic and independent cross-file analysis shipped together. Release display date is 2 March; publication timestamp is 1 March 2026 at 18:39 UTC.](https://github.com/coffeeandsecurity/DakshSCRA/commit/d90ba51) |
| Web UI and Docker rollout | 16 March 2026 | v0.33-beta | [Introduced browser-launched scans, live progress, findings/artifact browsing, OS-aware directory selection and built-in Help; added Docker Compose Web UI/CLI services and portable environment setup.](https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.33-beta) |
| External RDL architecture and reporting | 22 March 2026 | v0.37-beta | [External rule logic and revised advanced reports.](https://github.com/coffeeandsecurity/DakshSCRA/commit/5b17d89) |
| RDL v2 semantic services and integrated workflow | 10 October 2026 | v0.39 | Typed semantic rules, bounded cross-file evidence and custom packs. |

### Comparative evidence

- **Recon predecessor:** [Microsoft Application Inspector](https://www.microsoft.com/en-us/security/blog/2020/01/16/introducing-microsoft-application-inspector/) — 16 January 2020. Documents an earlier source-characteristics tool; does not establish a worldwide first/second ranking.

Dates identify repository or release milestones; they do not independently establish worldwide priority. “Not verified” means a release number has not been established from the reviewed evidence.

Release milestones and comparative evidence are listed above.

DakshSCRA was introduced during **Black Hat USA 2022** training and publicly debuted at **Black Hat USA 2023**. Those dates describe the project's introduction, not every current feature.

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

The fastest way to run Daksh SCRA is through its browser-based Web UI, launched with the host-aware Docker startup helper. It gives you a scan launcher, a live console feed, and a browsable history of past reports. The startup helper needs Python 3 (standard library only); the application and its dependencies run in Docker.

The Docker setup runs the Web UI and the CLI as independent services built from the same image, so you can use either (or both) from the same container.

### Launch the Web UI

After downloading Daksh SCRA from GitHub, **extract the ZIP archive first**.
Open a terminal (PowerShell or Command Prompt on Windows) inside the extracted
project folder containing `docker-compose.yml` and `dakshscra.py`.
**Run all startup and Docker Compose commands below from that folder.**

If your terminal opens elsewhere, change into the extracted folder first:

```text
cd "path/to/extracted/DakshSCRA-folder"
```

Replace the example path with your actual download location and folder name.
If you cloned the repository instead, run `cd DakshSCRA` from its parent folder.

The startup helper recognizes Windows, WSL, Linux and macOS, then mounts the
host root, available Windows drives and common folders read-only before
starting the containers. Run it on the computer running Docker.

Linux, macOS or WSL (foreground):

```bash
python3 tools/start_webui.py
```

Windows PowerShell or Command Prompt (foreground):

```powershell
py tools/start_webui.py
```

Add `--detach` for background mode, or `--dry-run` to inspect detected paths.
Existing `.env` path overrides are respected. Accounts, scans and the runtime
volume are preserved when containers are recreated.

Docker Desktop may require permission to share the selected host paths. If it
rejects a mount, allow that location in Docker Desktop and rerun the helper.
A remote browser sees the **Docker host's** folders, not its own computer's drives.
Automatic detection requires a local Docker engine; run the helper on the engine
host when using a remote Docker context.

For manually configured mounts, `docker compose up --build -d api web` remains
available. Its baseline mounts the repository at `/scan-targets` and
`${DAKSH_HOST_MOUNT:-/}` at `/host/root`. Use the helper for Windows drive discovery
and common-folder shortcuts; plain Compose cannot detect the client OS.

Then open [http://localhost:8080](http://localhost:8080).

To use a different port:

```bash
DAKSH_PORT=9090 python3 tools/start_webui.py
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
| Default scan root (repository, or `DAKSH_SCAN_ROOT`) | `/scan-targets` |
| Host filesystem (system drive on Windows) | `/host/root` |
| Additional Windows/WSL drives | `/host/drives/<letter>` |
| Current user's home | `/host/user` |
| Common host folders | `/host/locations/<name>` |
| Optional `DAKSH_HOST_SOURCE` | `/host/source` |

Copy `.env.example` to `.env` for optional path and authentication overrides.
`DAKSH_BROWSE_ROOTS` is a comma-separated allow-list of **container** paths;
leave it unset to discover the mounted locations. Obsolete `/host/c`, `/host/d`
or `/mnt` allow-lists should be removed or updated when switching to the helper.
Host folders are read-only; reports and runtime data remain writable in their
existing application locations. Restart using the helper after attaching another
drive. No Docker socket or privileged container is needed.

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
| `-rpt`, `--report FORMATS` | Report formats: `html`, `pdf`, `docx`, `json`, or a comma-separated combination (default: `html`) |
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

<!-- supported-platforms:start -->
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
<!-- supported-platforms:end -->

This table lists registered rule packs. A dash means no separate framework pack is registered. Analysis coverage varies by language and rule.

After changing the platform or framework registries, refresh this table and check it before submitting changes:

```bash
python3 tools/supported_platforms.py
python3 tools/supported_platforms.py --check
```

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

RDL v1 definitions live under [`rules/scanning/logic/rdl/v1/`](rules/scanning/logic/rdl/v1/).
Experimental RDL v2 definitions live under [`rules/scanning/logic/rdl/v2/`](rules/scanning/logic/rdl/v2/README.md),
using `common/core/`, `<platform>/core/`, and `<platform>/framework/<framework>/`
with bug-class subdirectories. The [v2 scope index](rules/scanning/logic/rdl/v2/INDEX.md) links
all registered language/framework extension points, rule IDs, and current v1-to-v2 mappings.
Directory presence does not imply completed coverage; v1 remains supported.

RDL (Rule Description Language) is DakshSCRA's externalized rule-logic layer. In the v1 architecture:

- XML rules remain the rule inventory and carry metadata such as `name`, `regex`, descriptions, and optional `scan_config`.
- RDL logic is executed by [`core/rdl_engine.py`](core/rdl_engine.py).
- Rule logic files live under `rules/scanning/logic/rdl/v1/...` and are referenced from XML using `<rdl_ref>`.
- `rdl_ref` values are resolved relative to `rules/scanning/`, for example:
  `logic/rdl/v1/php/core/some_rule.rdl` -> `rules/scanning/logic/rdl/v1/php/core/some_rule.rdl`
- Logic outcomes are exported into report JSON as metadata such as `logic_engine`, `logic_source`,
  `logic_reason`, `logic_trace`, `logic_consulted_files`, and `logic_outcome`.

The older inline `<rdl>` form is no longer the active architecture and should not be used for new rules.

#### RDL architecture at a glance

```text
XML rule
  -> regex / exclude / scan_config / descriptions
  -> rdl_ref
       -> rules/scanning/logic/rdl/v1/<platform>/<scope>/<rule>.rdl
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
  <rdl_ref>logic/rdl/v1/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
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
    └── rdl/
        └── logic/
            ├── v1/
            │   ├── common/core/
            │   ├── php/core/
            │   └── ...
            └── v2/
                ├── common/core/
                ├── php/core/
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
  <rdl_ref>logic/rdl/v1/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
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
  <rdl_ref>logic/rdl/v1/mobile/android/core/exported_components.rdl</rdl_ref>
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

#### Authoring guidance

- Keep `regex` broad enough to catch candidates, then use RDL to filter context.
- Prefer `rdl_ref` for all rule logic and keep the `.rdl` file beside the appropriate platform/framework logic tree.
- Do not add new inline `<rdl>` blocks.
- Use `WHEN PRESENT` / `WHEN MISSING` for simple gates and `WHEN EXPR` only when the logic is genuinely boolean.
- Put reviewer-facing reasoning in `REASON` and suppression explanations in `FAIL_REASON`.
- Treat `PRESENT` and `MISSING` as whole-file checks. A mitigation anywhere in the file can suppress every match from that file.
- Use `OBSERVE PROJECT_HAS_GLOB` to enrich findings with project context, not as a pass/fail gate.
- Keep `logic/rdl/v1/...` paths stable and platform-scoped so XML rules remain thin and the logic layer stays reusable.

---

## Report Output Structure

CLI outputs are retained per scan under `reports/<project>/<scan>/`. CLI and Web UI exports share saved-data collection and renderers for HTML, PDF, Word, and JSON. Full HTML opens a lightweight summary/index with linked, paginated detail pages. In the Web UI, generate an export in **Reports**; extract the HTML ZIP and open `index.html` first.

```
reports/<project>/<scan>/
├── scan/
│   ├── html/
│   │   ├── report.html                 # Summary and report index (open first)
│   │   ├── report-files/               # Linked detail pages and saved-results.json
│   │   └── multi-file/                 # Per-platform HTML report set
│   ├── pdf/
│   │   ├── report.pdf                  # Single-file PDF scan report
│   │   └── multi-file/                 # Per-platform PDF report set
│   ├── word/
│   │   └── report.docx                 # Editable Word report when requested
│   ├── json/
│   │   └── report.json                 # Complete structured report document
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
