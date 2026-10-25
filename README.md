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

To run in detached (background) mode, add `--detach`. The containers keep running
after the startup command returns, leaving your terminal available.

Linux, macOS or WSL (detached):

```bash
python3 tools/start_webui.py --detach
```

Windows PowerShell or Command Prompt (detached):

```powershell
py tools/start_webui.py --detach
```

Use `--dry-run` to inspect detected paths without starting the containers.
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

Then open [http://localhost:3030](http://localhost:3030).

To use a different port:

```bash
DAKSH_PORT=9090 python3 tools/start_webui.py
```

Stop the stack with:

```bash
docker compose down
```

### Freeing disk space after repeated Docker builds

Use the separate cleanup helpers from the repository folder. They preview by default:

**This deletes Daksh containers, service images, networks and volumes, including saved accounts, scan history and artifacts stored in the runtime volume. Back up anything you want to keep first.**

```bash
python3 tools/clean_project_docker.py
python3 tools/purge_all_docker.py
```

Add `--execute` to delete, then type the requested confirmation. The first helper
removes this project's containers, networks, service images and volumes, preserving
shared build cache. The second forcibly removes containers across **all projects on
the selected Docker engine** and prunes images, networks, named/anonymous volumes
and default-builder cache. It can affect a remote engine. Neither deletes
bind-mounted host files or uninstalls Docker. Windows users can replace `python3`
with `py`. See [cleanup scope and commands](docs/usage-guide.md#docker-cleanup-and-full-purge)
for custom project names, exclusions and deletion details.

Check remaining Docker disk usage with:

```bash
docker system df
```

To free only unused build cache while keeping saved Daksh data, run just `docker builder prune --all --force`. Files in bind-mounted host folders, including the repository and scan targets, remain on disk. Start again with `python3 tools/start_webui.py --detach` when ready.

### Logging in

The Web UI requires an account. On first startup, an initial admin account is created from `DAKSH_ADMIN_USERNAME` / `DAKSH_ADMIN_PASSWORD` (set these in `.env`); if `DAKSH_ADMIN_PASSWORD` is left unset, a random password is generated and printed once to the API's startup log - save it, since it cannot be recovered afterward.

You'll be required to set your own password (and, optionally, username) the first time you log in. An admin account can create further accounts via the `POST /api/v1/auth/users` API endpoint (no dedicated UI for this yet). See `.env.example` for the full list of authentication-related settings (session lifetime, cookie security, CORS).

### What you get

- Responsive command builder for scan, recon, estimate, recon+estimate, list, and PDF-from-JSON modes
- Real-time console feed and live per-stage progress during execution
- Per-job artifact snapshots for HTML / PDF / JSON outputs
- Developer Mode, Code Review Mode, or Both guidance for results and reports; Both is the default
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

### Pattern Rules and Semantic Rules

**Pattern Rules identify areas of interest using patterns and contextual conditions. A reviewer investigates whether they represent actual security issues.**

**Semantic Rules provide stronger evidence by analyzing code relationships, input propagation and modeled protections. They can support a finding or suppression, but incomplete modeling, deployment settings and runtime behavior can still affect the conclusion.**

Select `--rule-mode pattern|semantic|both` (default `both`), or choose the same modes in New Scan. Semantic-only skips native text baselines while retaining refined mobile source/configuration checks and supported flow models. A supported finding still requires reviewer confirmation; suppression does not establish safety.

Built-in checks are authored as single-file Pattern Rules under [`rules/scanning/platform/`](rules/scanning/platform/), preserving platform and framework directories. For example, Java checks live in `java/java.rules/*.yaml` and Spring checks in `java/framework/spring.rules/*.yaml`. Each file retains the pattern, contextual conditions, rule and impact descriptions, developer and reviewer guidance, recommendations, and all code-context and highlighting settings. Actionable `review_steps` and `recommendations` extend the original guidance with actionable instructions. Add a YAML file to an existing pack, validate it with `python3 tools/rdl_lint.py rules/scanning/platform`, then scan a small positive/negative fixture. The scanner discovers it without editing XML or a separate RDL v1 file.

Semantic definitions remain under [`rules/scanning/logic/rdl/v2/`](rules/scanning/logic/rdl/v2/). Native text baselines evaluated by that engine remain Pattern Rules. Legacy `--rdl-engine` selections remain compatible with saved scans and existing scripts.

See the [rule authoring and migration guide](docs/usage-guide.md#pattern-rules-and-semantic-rules) for the YAML format, conditions, validation, evidence settings and external XML import.

Applicable platform and framework packs also include security-operation review candidates. Semantic models distinguish response-origin values, bulk-binding sources and cryptographic key arguments, and can trace supported configuration fallbacks into key operations. Newly generated findings associate supported method/class control declarations with the operation; typed C# model review can retain declared field policies. Tenant isolation requires an application-specific invariant. These are evidence-backed review capabilities with explicit modeling limits, not guaranteed detection of every authorization or business-logic flaw. See [security operation and control context](docs/usage-guide.md#security-operation-and-control-context).

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

Global date and time preferences are shared by the web UI and CLI. Set them in **Settings → Global date and time**. The defaults are `MM-DD-YYYY`, 24-hour time and UTC. Choose `DD-MM-YYYY` or `YYYY-MM-DD`, 12-hour time, and any valid IANA time zone. New scans capture these preferences; web displays use the current global settings. Existing exported files remain unchanged. Machine timestamps and scan IDs retain their canonical format.

```bash
python dakshscra.py --settings
python dakshscra.py --save-settings --date-format MM-DD-YYYY --time-format 12h --timezone Pacific/Auckland
python dakshscra.py -r auto -t ./src --date-format DD-MM-YYYY --time-format 24h --timezone UTC
```

The last command overrides preferences for that scan without saving them globally.

Mobile reviews cover native Android/iOS and supported framework code, including applicable native bridge files in hybrid projects. Pattern candidates remain available for investigation; semantic refinements associate settings with their declaration or operation and record modeled flows. See the [mobile review coverage guide](docs/usage-guide.md#mobile-security-review-coverage) for checks, edge cases and verification boundaries.

Mobile scans also export `mobile_review.json` and a readable `mobile_review.html` beside the structured scan data. These connect build scope, credential storage and backup policies, sensitive logging, cleanup callers, native bridge identities, API contracts and unresolved analysis. New source checks cover release debug signing, unchecked provider-stream reads and API-to-privacy-description mismatches. Exact source contracts do not establish the shipped artifact, runtime reachability or backend authorization.
