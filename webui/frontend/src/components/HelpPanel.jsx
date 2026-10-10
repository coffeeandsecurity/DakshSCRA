import { useEffect, useRef, useState } from 'react'

/* ─── Table of Contents ─────────────────────────────────────── */
const TOC = [
  { id: 'what-is', label: 'What is DakshSCRA?' },
  { id: 'distinctive', label: 'Distinctive Features' },
  { id: 'installation', label: 'Installation' },
  { id: 'cli-usage', label: 'CLI Usage' },
  { id: 'cli-scan-options', label: '↳ Scan Options', indent: true },
  { id: 'cli-mode-options', label: '↳ Mode Options', indent: true },
  { id: 'cli-output-options', label: '↳ Output Options', indent: true },
  { id: 'cli-advanced-options', label: '↳ Advanced Options', indent: true },
  { id: 'cli-examples', label: '↳ Examples', indent: true },
  { id: 'cli-output-structure', label: '↳ Output Structure', indent: true },
  { id: 'webui-usage', label: 'Web UI Usage' },
  { id: 'webui-dashboard', label: '↳ Dashboard', indent: true },
  { id: 'webui-projects', label: '↳ Projects', indent: true },
  { id: 'webui-scans', label: '↳ Scans & Findings', indent: true },
  { id: 'webui-findings', label: '↳ Understanding Findings', indent: true },
  { id: 'webui-artifacts', label: '↳ Reports & Artifacts', indent: true },
  { id: 'webui-dirbrowser', label: '↳ Directory Browser', indent: true },
  { id: 'platforms', label: 'Platforms & Rules' },
  { id: 'rdl', label: 'RDL - Conditional Rules' },
  { id: 'rdl-operators', label: '↳ Operators', indent: true },
  { id: 'rdl-examples', label: '↳ Examples', indent: true },
  { id: 'rdl-fp-reduction', label: '↳ How FPs Are Reduced', indent: true },
  { id: 'rdl-shadow', label: '↳ RDL Engine Selection', indent: true },
  { id: 'scan-config', label: 'scan_config - Rule Engine' },
  { id: 'scan-config-schema', label: '↳ Full Schema', indent: true },
  { id: 'scan-config-profiles', label: '↳ Platform Profiles', indent: true },
  { id: 'scan-config-highlighting', label: '↳ Highlighting', indent: true },
  { id: 'scan-config-authoring', label: '↳ Rule Authoring Guide', indent: true },
  { id: 'findings-reference', label: 'Findings Reference' },
  { id: 'pdf-reports', label: 'Report Formats & PDF' },
  { id: 'tips', label: 'Tips & Patterns' },
]

/* ─── Reusable primitives ───────────────────────────────────── */
function SectionHeading({ id, children }) {
  return (
    <h2 id={id} className="help-h2">{children}</h2>
  )
}

function SubHeading({ id, children }) {
  return (
    <h3 id={id} className="help-h3">{children}</h3>
  )
}

function P({ children }) {
  return <p className="help-p">{children}</p>
}

function Code({ children }) {
  return <code className="help-inline-code">{children}</code>
}

function CodeBlock({ children }) {
  return (
    <pre className="help-code-block"><code>{children}</code></pre>
  )
}

function Note({ children, type = 'info' }) {
  const labels = { info: 'Note', tip: 'Tip', warn: 'Warning' }
  return (
    <div className={`help-callout help-callout-${type}`}>
      <span className="help-callout-label">{labels[type] || 'Note'}</span>
      {children}
    </div>
  )
}

function Table({ headers, rows }) {
  return (
    <div className="help-table-wrap">
      <table className="help-table">
        <thead>
          <tr>{headers.map((h, i) => <th key={i}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ─── Content sections ──────────────────────────────────────── */
function WhatIsSection() {
  return (
    <section className="help-section">
      <SectionHeading id="what-is">What is DakshSCRA?</SectionHeading>
      <P>
        DakshSCRA (Source Code Review Assist) is a security-focused static analysis tool built to support
        manual code review engagements. It surfaces areas of interest in source code through rule-based
        pattern matching, technology stack reconnaissance, and dataflow taint analysis.
      </P>
      <P>
        It is a tool for reviewers, not a replacement for one. The goal is to cut down on manual triage time
        by pointing out relevant code patterns, inter-file data flows, and effort estimates, so the reviewer
        can focus on what actually matters.
      </P>
      <Table
        headers={['Capability', 'Description']}
        rows={[
          ['Rule-based scanning', 'Matches platform-specific patterns (SQL queries, command execution, file I/O, etc.) against source files'],
          ['Reconnaissance', 'Detects languages, frameworks, and technology stack from file contents and structure'],
          ['Taint analysis', 'Traces data flows from user-controlled sources to security-sensitive sinks across files'],
          ['Effort estimation', 'Plans review work from measured scan evidence with explicit, calibratable assumptions'],
          ['Report generation', 'CLI exports HTML, PDF, Word and JSON; Web UI generates reports on demand from saved results'],
        ]}
      />
    </section>
  )
}

function DistinctiveSection() {
  const features = [
  {
    "title": "File Path Areas of Interest",
    "tag": "World's First*",
    "highlight": true,
    "body": "Scans file and directory names themselves, alongside code, to flag suspicious paths such as backup files, debug endpoints, configuration dumps and credential files that reviewers often miss."
  },
  {
    "title": "Scientific Effort Estimation",
    "tag": "Evidence-based",
    "highlight": true,
    "body": "Plans assisted, targeted and fully manual review from unique files, LOC, active and suppressed decisions, unresolved evidence and traces. Explicit task assumptions and observed calibration make calculations reproducible; AI-assisted duration requires benchmarking."
  },
  {
    "title": "Areas of Interest, Not Bug Flags",
    "tag": "Reviewer in Control",
    "highlight": false,
    "body": "Surfaces patterns worth investigating rather than tagging every match as a vulnerability. Contextual rules and suppression evidence reduce triage noise and keep the reviewer in control."
  },
  {
    "title": "Software Reconnaissance",
    "tag": "Integrated Software Recon",
    "highlight": true,
    "body": "Provides open-source source-code reconnaissance, identifying languages, frameworks, infrastructure and project characteristics from source contents and structure. Uses the technology inventory to guide rule selection and security review planning. Microsoft Application Inspector is an earlier known open-source tool with comparable reconnaissance capabilities."
  },
  {
    "title": "RDL Conditional Rules",
    "tag": "Advanced Conditional Rules",
    "highlight": true,
    "body": "Goes beyond simple regex with PRESENT, MISSING, boolean expressions and file/path conditions. RDL v1 records decisions and suppression reasons; RDL v2 adds typed semantic services and bounded cross-file evidence."
  },
  {
    "title": "Advanced Semantic and Cross-File Analysis",
    "tag": "Built from the Ground Up",
    "highlight": false,
    "body": "Traces user-controlled data from source to sink across supported file boundaries using purpose-built analysis. Advanced Analysis shipped alongside the original RDL in March 2026; RDL v2 extends semantic rule evaluation across files."
  },
  {
    "title": "Platform-Agnostic Auto Scanning",
    "tag": "Automatic Multi-Platform",
    "highlight": true,
    "body": "Use -r auto to scan mixed-technology projects without choosing a single language beforehand. Recon selects supported platform and framework rules automatically. Introduced in v0.23-beta, November 2024."
  },
  {
    "title": "Application-Specific Security Logic",
    "tag": "Custom RDL Packs",
    "highlight": true,
    "body": "Encode application trust boundaries, authorization decisions and business invariants in optional custom RDL packs. Project-specific logic runs alongside the generic scanning rules."
  },
  {
    "title": "Interactive Text and Graph Evidence",
    "tag": "Follow the Evidence",
    "highlight": false,
    "body": "Follow recorded source-to-sink paths in linked Text and Graph views. Source excerpts, file lanes and handoff details make cross-file evidence easier to inspect."
  },
  {
    "title": "Review Lifecycle and Portable Reports",
    "tag": "Review, Resume and Export",
    "highlight": false,
    "body": "Keep scan history, review suppressions and resume interrupted scans. Export HTML, PDF, editable Word and JSON through shared CLI and Web UI reports, with offline evidence navigation where available."
  }
]
  return (
    <section className="help-section">
      <SectionHeading id="distinctive">Distinctive Features</SectionHeading>
      <P>DakshSCRA brings together distinctive capabilities for manual source code review, from file-path areas of interest and effort estimation to software reconnaissance, contextual rules and cross-file analysis.</P>
      <div className="help-distinctive-grid">
        {features.map(({ title, tag, highlight, body }) => (
          <div className={`help-distinctive-card${highlight ? ' feature-highlight' : ''}`} key={title}>
            <div className={`help-distinctive-badge${highlight ? '' : ' help-distinctive-badge-notable'}`}>{tag}</div>
            <div className="help-distinctive-title">{title}</div>
            <div className="help-distinctive-body">{body}</div>
          </div>
        ))}
      </div>
      <div className="help-debut-note">* World's First badges reflect the project's original claims; worldwide priority has not been independently verified.</div>
      <div className="help-debut-note">
        First introduced at <strong>Black Hat USA 2022</strong> and publicly debuted at <strong>Black Hat USA 2023</strong>, Las Vegas.
      </div>
      <details>
        <summary className="help-p">Release history and supporting evidence</summary>
      <SubHeading id="feature-history">Feature History and Evidence</SubHeading>
      <Table headers={["Feature / milestone", "Date", "Release", "Evidence / scope"]} rows={[
        ["Private training release", "2022 (Black Hat USA)", "Private student release", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/blob/fe878be/README.md">Distributed privately to Black Hat USA 2022 training students before the public web release.</a></span>],
        ["Initial beta and file-path rules", "22 October 2022", "v0.1-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.1-beta">Initial release; retained source includes the dedicated file-path rule inventory.</a></span>],
        ["PDF and HTML reports", "23 May 2023", "v0.2-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.2-beta">Release notes list PDF/HTML report generation and scanning-rule updates.</a></span>],
        ["Software reconnaissance (published introduction)", "9 July 2023", "v0.3-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.3-beta">Release notes introduce recon; earlier repository code is separate implementation evidence.</a></span>],
        ["Manual-review effort estimation (implementation)", "29 July 2023", "Implementation commit", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/commit/65d5c6a">Dedicated estimation module added; not the date of the later fix release.</a></span>],
        ["Early Android manifest and Kotlin checks", "27 April 2024", "v0.16-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.16-beta">Introduced Android manifest misconfiguration checks and Kotlin-specific checks; module described as early development, with broader coverage still in progress.</a></span>],
        ["Multi-platform scan flags (initial design)", "4 November 2024", "v0.20-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.20-beta">Added comma-separated platform selection with -r; initial implementation did not yet isolate each platform rule set to its own file types.</a></span>],
        ["Platform-agnostic auto scanning", "10 November 2024 (release listing)", "v0.23-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.23-beta">Automatic platform/rule selection; implementation commit dated 11 November.</a></span>],
        ["PDF rendering upgrade", "21 July 2025", "v0.29-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.29-beta">Migrated PDF export from WeasyPrint to Playwright and Chromium; added HTML-size-based timeouts for large reports and cross-platform setup instructions.</a></span>],
        ["Initial iOS scanning support", "2 March 2026", "v0.31-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.31-beta">Added iOS rules and Swift/Objective-C/configuration file selection; later releases expanded coverage.</a></span>],
        ["Original RDL and inter-file Advanced Analysis", "2 March 2026", "v0.31-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/commit/d90ba51">Conditional rule logic and independent cross-file analysis shipped together. Release display date is 2 March; publication timestamp is 1 March 2026 at 18:39 UTC.</a></span>],
        ["Web UI and Docker rollout", "16 March 2026", "v0.33-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.33-beta">Introduced browser-launched scans, live progress, findings/artifact browsing, OS-aware directory selection and built-in Help; added Docker Compose Web UI/CLI services and portable environment setup.</a></span>],
        ["External RDL architecture and reporting", "22 March 2026", "v0.37-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/commit/5b17d89">External rule logic and revised advanced reports.</a></span>],
        ["RDL v2 semantic services and integrated workflow", "10 October 2026", "v0.39", <span>Typed semantic rules, bounded cross-file evidence and custom packs.</span>],
      ]} />

      </details>
    </section>
  )
}

function InstallationSection() {
  return (
    <section className="help-section">
      <SectionHeading id="installation">Installation</SectionHeading>

      <SubHeading id="install-reqs">Requirements</SubHeading>
      <ul className="help-list">
        <li>Python 3.9 or later</li>
        <li>pip</li>
      </ul>

      <SubHeading id="install-setup">Setup</SubHeading>
      <CodeBlock>{`git clone https://github.com/coffeeandsecurity/DakshSCRA.git
cd DakshSCRA
python3 -m venv venv
source venv/bin/activate          # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
python -m playwright install chromium # Required for native PDF generation`}</CodeBlock>

      <SubHeading id="install-docker">Docker (Web UI)</SubHeading>
      <P>Run from the repository root with Docker running. The host-aware launcher configures source mounts:</P>
      <CodeBlock>{`# Foreground
python3 tools/start_webui.py
# Background
python3 tools/start_webui.py --detach
# Windows: use py instead of python3`}</CodeBlock>
      <P>Open <Code>http://localhost:8080</Code> in a browser.</P>
      <P>To change the port:</P>
      <P>Set <Code>DAKSH_PORT=9090</Code> in <Code>.env</Code>, then restart with the launcher.</P>
      <CodeBlock>{`# Reuse an existing host mount configuration:
docker compose -f docker-compose.yml -f runtime/docker-host.compose.json up -d --build api web
# Baseline Compose without automatic host mounts:
docker compose up -d --build api web
# Docker CLI (target must be mounted in the container):
docker compose -f docker-compose.yml -f runtime/docker-host.compose.json run --rm cli -r auto -t /scan-targets -rpt html,pdf,docx,json`}</CodeBlock>
      <P>Keep the runtime volume to retain accounts and scan history. Stop services with <Code>docker compose stop</Code>. Avoid concurrent Web UI and CLI scans because they share runtime paths.</P>
    </section>
  )
}

function CliUsageSection() {
  return (
    <section className="help-section">
      <SectionHeading id="cli-usage">CLI Usage</SectionHeading>

      <SubHeading id="cli-syntax">Syntax</SubHeading>
      <CodeBlock>{`python dakshscra.py [SCAN OPTIONS] [MODE OPTIONS] [OUTPUT OPTIONS] [ADVANCED OPTIONS]`}</CodeBlock>
      <P>Run with no arguments to see the full help:</P>
      <CodeBlock>{`python dakshscra.py`}</CodeBlock>

      {/* Scan Options */}
      <SubHeading id="cli-scan-options">Scan Options</SubHeading>
      <P>These options control what to scan and how.</P>
      <Table
        headers={['Option', 'Description']}
        rows={[
          [<Code>-r RULES</Code>, 'Platform rules to apply. Comma-separated (e.g. php,java) or auto for automatic detection.'],
          [<Code>-f FILE_TYPES</Code>, 'Override default file extensions for the selected platform.'],
          [<Code>-t TARGET_DIR</Code>, 'Path to the source code directory to scan.'],
          [<Code>-v / -vv / -vvv</Code>, 'Verbosity level. Higher levels show more detail during scanning.'],
        ]}
      />
      <Note type="tip">
        When <Code>-r auto</Code> is used, DakshSCRA detects which languages and frameworks are present,
        then applies the matching platform rules automatically. A good starting point when the codebase is unfamiliar.
      </Note>
      <CodeBlock>{`python dakshscra.py -r auto -t ./codebase`}</CodeBlock>

      {/* Mode Options */}
      <SubHeading id="cli-mode-options">Mode Options</SubHeading>
      <P>Modes change <em>what</em> the tool does during a run. Multiple modes can be combined.</P>
      <Table
        headers={['Option', 'Description']}
        rows={[
          [<Code>--recon</Code>, 'Run technology stack reconnaissance. Detects languages, frameworks, libraries, and infrastructure clues.'],
          [<Code>--rs / --recon-strict</Code>, 'Filter recon output to high-confidence detections only. Use with --recon to reduce noise.'],
          [<Code>--estimate</Code>, 'Scan supplied scope, include recon/LOC and plan review after final findings.'],
          [<Code>--estimate-mode</Code>, 'assisted, targeted, manual or ai review scenario.'],
          [<Code>--estimate-domain</Code>, 'Repeat to select targeted authentication, authorization, taint and other domains.'],
          [<Code>--estimate-calibration</Code>, 'JSON array of measured component, units and hours samples.'],
          [<Code>--pdf-from-json</Code>, 'Generate PDF reports from existing JSON output without re-running a scan.'],
          [<Code>-l {'{R,RF}'}</Code>, 'List available platform rules. R lists rules, RF also lists associated file types.'],
        ]}
      />
      <P>Combining modes:</P>
      <CodeBlock>{`# Recon + scan + estimate in one pass
python dakshscra.py --recon --estimate -r php -t ./app

# Recon only, no scanning
python dakshscra.py --recon -t ./app

# Recon with strict filtering
python dakshscra.py --recon --rs -t ./app

# Scan with auto detection
python dakshscra.py -r auto --recon -t ./app`}</CodeBlock>

      {/* Output Options */}
      <SubHeading id="cli-output-options">Output Options</SubHeading>
      <Table
        headers={['Option', 'Default', 'Description']}
        rows={[
          [<Code>-rpt FORMATS</Code>, 'html', 'CLI report formats: html, pdf, docx, json, or a comma-separated combination. Native PDF requires Playwright/Chromium.'],
          [<Code>--json-input-dir PATH</Code>, './reports/&lt;project-id&gt;/&lt;run-id&gt;/data', 'JSON input directory for --pdf-from-json mode.'],
          [<Code>--pdf-output PATH</Code>, './reports/&lt;project-id&gt;/&lt;run-id&gt;/scan/pdf/report.pdf', 'Custom output path for the single combined PDF.'],
          [<Code>--pdf-multi-dir PATH</Code>, './reports/&lt;project-id&gt;/&lt;run-id&gt;/scan/pdf/multi-file', 'Custom output directory for the per-platform PDF set.'],
          [<Code>--pdf-single-only</Code>, 'off', 'Generate only the combined single PDF; skip the per-platform multi-file set.'],
        ]}
      />
      <Note>
        PDF is not generated by default. At the end of any scan that did not produce a PDF, the tool prints
        a reminder with the command to generate one afterwards.
      </Note>

      {/* Advanced Options */}
      <SubHeading id="cli-advanced-options">Advanced Options</SubHeading>
      <Table
        headers={['Option', 'Description']}
        rows={[
          [<Code>--rdl-engine v1|v2|both</Code>, 'Select RDL engines (default: both). V2 is experimental and records coverage limits separately from the optional analyzer.'],
          [<Code>--skip-analysis</Code>, 'Disable the optional taint analyzer. Selected RDL engines and source/path scanning still run.'],
          [<Code>--loc</Code>, 'Count effective lines of code (may add scan time). Included in effort estimation.'],
          [<Code>--baseline-file PATH</Code>, 'Path to a suppression baseline JSON file.'],
          [<Code>--baseline-generate</Code>, 'Generate a new suppression baseline from current findings.'],
          [<Code>--no-baseline</Code>, 'Ignore the baseline suppression file for this run.'],
          [<Code>--resume-scan</Code>, 'Resume a previously interrupted scan from its last saved checkpoint.'],
          [<Code>--review-config PATH</Code>, 'Apply a findings triage file (JSON). Previously reviewed false positives will be excluded from reports.'],
          [<Code>--state-file PATH</Code>, 'Custom path for the scan state/checkpoint file.'],
          [<Code>--no-state</Code>, 'Disable scan state checkpointing for this run.'],
          [<Code>--state</Code>, 'Force enable scan state checkpointing for this run.'],
        ]}
      />

      {/* Examples */}
      <SubHeading id="cli-examples">Examples</SubHeading>
      <CodeBlock>{`# Basic PHP scan
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

# Full scan with all four report formats
python dakshscra.py -r php -t ./app -rpt html,pdf,docx,json

# Scan with effort estimation
python dakshscra.py --recon --estimate -r php -t ./app

# Generate PDF from a previous scan
python dakshscra.py --pdf-from-json --json-input-dir ./reports/my-project/20260329081500/data

# Generate PDF from a custom JSON directory
python dakshscra.py --pdf-from-json --json-input-dir ./custom/reports/my-project/20260329081500/data

# Single combined PDF only (skip per-platform set)
python dakshscra.py --pdf-from-json --json-input-dir ./reports/my-project/20260329081500/data --pdf-single-only

# Skip taint analysis for faster scan
python dakshscra.py -r php -t ./app --skip-analysis

# List available rules
python dakshscra.py -l R

# List rules with file types
python dakshscra.py -l RF

# Resume an interrupted scan
python dakshscra.py --resume-scan -r php -t ./app`}</CodeBlock>

      {/* Output structure */}
      <SubHeading id="cli-output-structure">Output Structure</SubHeading>
      <P>CLI reports are isolated by project and run. Web scans retain results under runtime and create exports only on request from Reports. Open the CLI HTML summary first and keep its linked folder alongside it.</P>
      <CodeBlock>{`reports/<project-id>/<run-id>/
  scan/
    html/
      report.html            <- Summary and report index (open first)
      report-files/          <- Linked detail pages and saved JSON
      multi-file/
        index.html           <- Multi-file report index
        <platform>/          <- Per-platform HTML pages
    pdf/
      report.pdf             <- Single combined PDF (if pdf requested)
      multi-file/            <- Per-platform PDFs (if pdf requested)
    word/
      report.docx            <- Editable Word report (if requested)
    json/
      report.json            <- Shared report document (if requested)
    recon/
      reconnaissance.html    <- Recon report (if --recon was used)
    estimate/
      estimation.html        <- Effort estimate (if --estimate was used)
  analysis/
    <platform>/
      analysis.html          <- Taint analysis report (themed)
      analysis_xref.html     <- Cross-reference report
      analysis.json          <- Taint flow data
  data/
    areas_of_interest.json   <- Scanner findings
    filepaths_aoi.json       <- File path findings
    summary.json             <- Scan summary metadata
    recon.json               <- Recon results
    analysis.json            <- Taint analysis summary
    estimation.json          <- Effort estimate (when enabled)
runtime/
  scan_summary.json          <- Live scan state (updated during run)
  filepaths.json             <- Discovered file inventory`}</CodeBlock>
    </section>
  )
}

function WebUISection() {
  return (
    <section className="help-section">
      <SectionHeading id="webui-usage">Web UI Usage</SectionHeading>
      <P>The Web UI provides a browser-based interface for running scans, viewing findings, and accessing reports.</P>
      <CodeBlock>{`python3 tools/start_webui.py --detach
# Open http://localhost:8080`}</CodeBlock>
      <P>Sign in with your configured account. Assigned/bootstrap passwords require a password change before using the application. The account menu offers Change password and Log out; Settings controls tool, display, analysis and estimation preferences.</P>

      <SubHeading id="webui-dashboard">Dashboard</SubHeading>
      <P>The Dashboard is the landing page. It shows:</P>
      <ul className="help-list">
        <li><strong>Summary metrics</strong>: total projects, scans run, success/failure counts, and success rate</li>
        <li><strong>Recent scan activity</strong>: a daily bar chart of scan volume</li>
        <li><strong>Project list</strong>: all projects with scan counts and last-scan timestamps</li>
        <li><strong>Quick actions</strong>: navigate directly to a project or start a new scan</li>
      </ul>

      <SubHeading id="webui-projects">Projects</SubHeading>
      <P>
        The Projects section organises scans into named groups. A project is created automatically the first
        time you run a scan with a given project name.
      </P>
      <Table
        headers={['Column', 'Description']}
        rows={[
          ['Project Name', 'The name you assigned when creating the scan'],
          ['Rules', 'Platform rules used'],
          ['Target', 'The scanned source directory'],
          ['Total Scans', 'Number of scans run under this project'],
          ['Running', 'Scans currently in progress'],
          ['Last Scanned', 'Timestamp of the most recent scan'],
        ]}
      />
      <P>Projects uses compact searchable rows. Filter by scan status or removed data and sort by latest scan, name or scan count. Open a project for its complete paginated scan history, with search and status filters including retained removed-data records. View results opens completed scans at Summary; active, queued and stopping scans open telemetry. Project scans returns to the selected history.</P>

      <SubHeading id="webui-scans">Scans &amp; Findings</SubHeading>
      <P>New Scan is a separate page with Setup, Check Classes, Exclusions, Analysis &amp; Output and Custom RDL tabs. Recon and LOC are enabled by default and can be deselected. Active Scans shows queued and running jobs. Jobs run one at a time; queued time is separate from execution duration. Stop a running job or cancel a queued one using its controls.</P>

      <p className="help-p"><strong>New Scan</strong>: Configure and launch a scan:</p>
      <Table
        headers={['Field', 'Description']}
        rows={[
          ['Project Name', 'Groups this scan with previous runs. Leave blank for an unnamed scan.'],
          ['Target Directory', 'Path to the source code. Use the browse button to navigate the filesystem.'],
          ['Platform Rules', 'Which rule set to apply. auto detects the platform automatically.'],
          ['File Types', 'Override the default extensions. auto uses platform defaults.'],
          ['Review mode', 'Comprehensive Review (recommended), Finding Analysis Only, or Areas of Interest Review Only. Results retain the underlying engine selection.'],
          ['Verbosity', 'Output detail level (1–3).'],
          ['Recon', 'Enable technology stack detection.'],
          ['Effort Estimate', 'Plan review from final evidence; includes reconnaissance and LOC.'],
          ['LOC Count', 'Include effective lines of code in the scan summary.'],
          ['Inter-file Analysis', 'Enable the optional native taint analyzer. Its initial value follows Settings. Can be slow on large codebases; independent of RDL engine selection.'],
        ]}
      />

      <P>Open an active job to see Live Scan Telemetry and Log. Telemetry shows stages, elapsed execution time, repository counters, current operation and progress. Completed runs open in the results workspace.</P>

      <p className="help-p"><strong>Completed scan details</strong> include:</p>
      <ul className="help-list">
        <li><strong>Log</strong>: Live streaming output from the scan process.</li>
        <li><strong>Areas of Interest</strong>: RDL v1 rule findings, locations and source context.</li>
        <li><strong>Vulnerability Analysis</strong>: Recorded v2 confirmed rule matches, suppressed false positives, manual-review needs and coverage limits. A rule match does not prove exploitability.</li>
        <li><strong>Advanced Analysis</strong>: Recorded v2 source-to-sink paths, input entry points and symbol cross references, with Text and Graph evidence views where available.</li>
        <li><strong>Insights</strong>: File/path inventory, recon and effort estimation.</li>
        <li><strong>Summary</strong>: Scan configuration and saved execution metrics.</li>
        <li><strong>Suppressed Findings</strong>: Suppressing rule, recorded RDL version, reason, decision trace and source evidence. Inspect an entry or promote it back to findings with review notes.</li>
        <li><strong>Reports</strong>: On-demand exports and available saved artifacts.</li>
      </ul>
      <P>Completed scan data removal deletes saved evidence and reports but keeps a history record. Clear record removes that remaining entry after data removal. Active jobs are protected from deletion.</P>
      <P>Insights → Effort Estimate offers Daksh-assisted manual review, Targeted review, Fully manual review and AI-assisted review. Select authentication, authorization, taint analysis and other domains for targeted plans; overlapping sites and files count once. Generate a report and download HTML or JSON. HTML supports printing to PDF.</P>
      <P>Plans separate inspection, active and suppressed decision review, unresolved investigation, traces and reporting. Defaults are transparent planning assumptions; per-report overrides and observed calibration samples are supported. Ranges are sensitivity bounds, not confidence intervals. Missing LOC withholds a complete total. AI duration requires measurements of the actual model, hardware/service, human validation and rework. Remediation and retesting are separate.</P>

      <SubHeading id="webui-findings">Understanding Findings</SubHeading>
      <p className="help-p"><strong>Scanner Findings</strong></p>
      <P>
        Each scanner finding is a pattern match against a code construct known to be risky or worth reviewing.
        Not every finding is a vulnerability. They are areas of interest that need manual review. Common
        false positives include commented-out code, test fixtures, and safe wrapper functions.
      </P>
      <Table
        headers={['Field', 'Description']}
        rows={[
          ['Rule', 'The rule name (e.g. sql_injection, command_exec)'],
          ['File', 'Source file path'],
          ['Line', 'Line number of the match'],
          ['Snippet', 'Surrounding code context'],
          ['Platform', 'Language/framework platform the rule belongs to'],
        ]}
      />

      <p className="help-p"><strong>Taint Analysis Findings</strong></p>
      <P>Use Text / Graph on a trace story, vulnerability path, attack vector or cross-reference to switch displays. Graph mode provides file lanes, recorded handoffs, a minimap, drag-to-pan, Ctrl + scroll zoom, Overview and Focus step. Select a block for its saved source evidence; use Up/Down, Home/End or Go to step to navigate. Expand workspace gives a larger view. Long traces use 120-step segments; every step stays accessible. SVG export saves the current segment. Graph arrows represent recorded evidence order, rather than proving runtime reachability or inventing missing branches. New HTML report packages include the same explorer for offline use.</P>
      <P>
        Taint findings describe statically inferred paths from sources such as request parameters or environment
        variables to sensitive sinks. Inspect the source evidence, mitigations, assumptions and coverage limits;
        a trace does not by itself prove runtime exploitability.
      </P>
      <Table
        headers={['Confidence', 'Meaning']}
        rows={[
          ['high', 'Stronger recorded tracing evidence; still verify reachability and mitigations.'],
          ['medium', 'Partial tracing or uncertainty requiring additional review.'],
          ['low', 'Limited evidence or fallback inference; verify before treating as a vulnerability.'],
        ]}
      />

      <p className="help-p"><strong>Recon Results</strong></p>
      <P>
        Recon output is grouped by technology type (Framework, Language, Frontend, Backend, etc.). Each
        detection shows the technology name, confidence level, and which files were used as evidence.
        Use <Code>--recon --rs</Code> for high-confidence detections when the output is too noisy.
      </P>

      <SubHeading id="webui-artifacts">Reports &amp; Artifacts</SubHeading>
      <P>
        Open Completed, choose a saved run and select Reports. Use the project and scan selectors to
        browse other retained runs. Web scans save review data without automatically generating report files.
      </P>
      <ul className="help-list">
        <li>Select Full scan, Areas of interest, Advanced analysis or Suppressed findings.</li>
        <li>Select HTML package (.zip), PDF, Word (.docx) or JSON, then click Generate report.</li>
        <li>Follow the animated generation status and Building/Packaging stages, then use Download when ready. Generating from saved results does not rescan source code.</li>
        <li>Full scan includes available findings, recon, estimation, analysis, suppressions, RDL evidence and cross-references.</li>
      </ul>
      <P>Extract the complete HTML ZIP, then open <Code>index.html</Code>. Keep its linked detail pages together for offline navigation. PDF has linked contents and bookmarks; Word is editable; JSON retains saved fields. Existing artifacts below the generator offer Open and Download where available. Large full exports can take time; use a narrower report type when appropriate.</P>

      <P>Open System → Disk info to review storage by project and scan, inspect file sizes and modification dates, and remove generated reports or temporary diagnostics. Select multiple storage items for cleanup, or delete all saved data for a scan or project while retaining history and project configuration. Review the deletion confirmation; removed results cannot be recovered. Cleanup is blocked while a scan or report job is active. Source directories, accounts and settings are preserved.</P>

      <SubHeading id="webui-dirbrowser">Directory Browser</SubHeading>
      <P>
        The directory browser modal lets you navigate the server filesystem to pick a scan target without
        typing a path manually. Only directories under the configured browse roots are accessible - the
        server rejects any request outside those boundaries.
      </P>
      <P>
        Click a folder once to open it, then choose <strong>Select This Folder</strong>.
        Use Up, Quick Access or enter a path and press Enter. Empty folders remain selectable;
        permission failures display an error.
      </P>
      <P>
        For automatic Docker host mounts, start from the repository with the host-aware helper:
      </P>
      <CodeBlock>{`# Linux, macOS or WSL:
python3 tools/start_webui.py --detach
# Windows PowerShell / Command Prompt:
py tools/start_webui.py --detach`}</CodeBlock>
      <P>
        It detects the computer running Docker and mounts its root, available drives and common
        folders read-only. Docker Desktop may ask for file-sharing permission. A browser on another
        computer sees the Docker host's folders, not its own drives. Restart with the helper after
        attaching another drive. Existing accounts and runtime data are preserved.
      </P>
      <Table
        headers={['Host location', 'Container path']}
        rows={[
          ['Filesystem root / Windows system drive', '/host/root'],
          ['Additional Windows / WSL drives', '/host/drives/<letter>'],
          ['Your home folder', '/host/user'],
          ['Common folders', '/host/locations/<name>'],
          ['Repository or DAKSH_SCAN_ROOT', '/scan-targets'],
        ]}
      />
      <P>
        Leave <Code>DAKSH_BROWSE_ROOTS</Code> unset for discovered shortcuts, or restrict it to
        comma-separated container paths. This allow-list does not create mounts.
      </P>
      <CodeBlock>{`DAKSH_BROWSE_ROOTS=/scan-targets,/host/drives/c`}</CodeBlock>
      <P>
        Optional host path overrides in <Code>.env</Code> include <Code>DAKSH_SCAN_ROOT</Code>,
        <Code>DAKSH_HOST_MOUNT</Code>, <Code>DAKSH_HOST_SOURCE</Code> and
        <Code>DAKSH_HOST_&lt;drive letter&gt;</Code>. See <Code>.env.example</Code> for details.
      </P>
      <Note type="tip">
        Only set browse roots to directories you intend to scan. The server enforces the boundary at the
        API level, but keeping the list tight reduces accidental exposure when the UI is accessible on a network.
      </Note>
    </section>
  )
}

function RDLSection() {
  return (
    <section className="help-section">
      <SectionHeading id="rdl">RDL - Rule Description Language</SectionHeading>
      <P>
        RDL is DakshSCRA&apos;s rule logic layer for contextual filtering, suppression, and report
        rationale. In the current engine, RDL lives in external <Code>.rdl</Code> files and is
        attached to XML rules through <Code>&lt;rdl_ref&gt;</Code>. The older inline{' '}
        <Code>&lt;rdl&gt;</Code> form is retired.
      </P>
      <Note type="info">
        XML defines candidate matches and presentation. The external <Code>.rdl</Code> script
        decides whether a candidate stays visible, gets suppressed, and what reason/trace metadata
        should be stored with that decision.
      </Note>

      <SubHeading id="rdl-shadow">Review Modes</SubHeading>
      <P>
        Comprehensive Review (recommended) combines code and path Areas of Interest with
        Areas of Interest Filtering (RDL v1) and Finding Analysis (RDL v2). Finding Analysis Only runs
        v2 findings. Areas of Interest Review Only retains the Areas of Interest and v1 filtering workflow.
      </P>
      <P>
        Areas of Interest Filtering applies conditions to regex-discovered security areas of interest. Finding Analysis runs
        text, source, semantic and supported flow checks. These paths serve different roles;
        the version numbers do not mean one directly replaces the other.
      </P>
      <P>
        RDL v2 adds coverage beyond the regex areas of interest. Semantic rules inspect relevant
        calls and arguments to reduce misleading matches where a protective control is modeled.
        Supported flow checks connect inputs to sensitive operations within a file or across files.
        Recorded locations and handoffs give you evidence to inspect. Rule limits help identify
        what still needs manual review. These benefits depend on the selected rules and language support.
        A rule match does not establish exploitability.
      </P>
      <P>
        Areas of Interest help reviewers read broadly before marking candidates as false positives,
        including security areas of interest that v2 may miss or leave unresolved. Existing filters and exclusions
        still apply; no mode guarantees complete coverage. The optional inter-file analyzer remains
        a separate setting. Historical scans retain their recorded selection.
      </P>
      <CodeBlock>{`# Docker: select engines later in the scan form
python3 tools/start_webui.py --detach

# CLI: both is the default; select v1 or v2 to run just one
python3 dakshscra.py -r auto -t /path/to/source --rdl-engine both
python3 dakshscra.py -r php -t /path/to/source --rdl-engine v1
python3 dakshscra.py -r php -t /path/to/source --rdl-engine v2`}</CodeBlock>
      <Note type="warn">
        A disagreement is a review item, not an automatic vulnerability or engine defect. Inspect
        both outcomes and the v2 evidence. Choose Areas of Interest Review Only for future scans when you need the areas of interest filtering workflow; historical results keep their original selection.
      </Note>

      <SubHeading id="rdl-sequence">Rule Evaluation Sequence</SubHeading>
      <P>RDL v1 evaluates scanner rules in this order. RDL v2 uses its own versioned definitions and records separate evidence and coverage limits:</P>
      <ol className="help-list">
        <li>Recon or explicit CLI selection chooses the active platform/framework rule sets.</li>
        <li>The XML rule is loaded from <Code>rules/scanning/platform/...</Code>.</li>
        <li>
          <Code>&lt;regex&gt;</Code> finds candidate matches.
        </li>
        <li>
          Optional <Code>&lt;exclude&gt;</Code> removes obvious noise for that rule.
        </li>
        <li>
          The external <Code>.rdl</Code> script from <Code>&lt;rdl_ref&gt;</Code> runs against the
          full current file, or against the normalized relative path for file-path rules.
        </li>
        <li>If the RDL script passes, the finding is reported. If it fails, the match is suppressed with the recorded fail reason and trace.</li>
      </ol>

      <SubHeading id="rdl-xml-structure">Rule XML Structure</SubHeading>
      <CodeBlock>{`<rule>
  <name>Rule Name</name>
  <regex><![CDATA[regex_to_match]]></regex>
  <rdl_ref>logic/rdl/v1/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
  <exclude><![CDATA[pattern_to_exclude_lines]]></exclude>  <!-- optional -->
  <scan_config>...</scan_config>                           <!-- optional -->
  <rule_desc>Short description of what the rule detects.</rule_desc>
  <vuln_desc>Why the pattern matters.</vuln_desc>
  <developer>Fix guidance for developers.</developer>
  <reviewer>Manual confirmation guidance for reviewers.</reviewer>
</rule>`}</CodeBlock>

      <P>
        <Code>&lt;regex&gt;</Code> finds candidates. <Code>&lt;rdl_ref&gt;</Code> loads the external
        logic script. <Code>scan_config</Code> controls how the match is scanned, aggregated,
        highlighted, and shown in the report.
      </P>

      <SubHeading id="rdl-file-structure">External RDL File Structure</SubHeading>
      <CodeBlock>{`VERSION 1
WHEN PRESENT /\\b(?:mysql_query|mysqli_query|->query)\\s*\\(/i
WHEN EXPR PRESENT:\\$_(GET|POST|REQUEST|COOKIE) && MISSING:\\b(?:prepare|bindParam|bindValue|PDO::prepare)\\b
REPORT AS area_of_interest
REASON Query execution appears to rely on direct input without parameterisation.
FAIL_REASON Matching query API was found, but prepared-statement indicators also exist in the same file.
TRACE SQLi gate: input source present and mitigation missing.`}</CodeBlock>

      <P>
        RDL is evaluated against the <strong>entire current file</strong>, not only the matched
        line. For file-path analysis, the current file text is the normalized relative path string.
      </P>

      <SubHeading id="rdl-operators">RDL Commands &amp; Operators</SubHeading>
      <Table
        headers={['Command', 'Behaviour', 'When to use']}
        rows={[
          ['WHEN PRESENT <regex>', 'Require a pattern to appear in the current file text.', 'Confirm a risky API or sensitive field exists'],
          ['WHEN MISSING <regex>', 'Require a pattern to be absent from the current file text.', 'Suppress when a mitigation is already present'],
          ['WHEN EXPR <expr>', 'Evaluate a boolean expression using PRESENT:, MISSING:, and EXISTS:.', 'Combine multiple conditions compactly'],
          ['WHEN CURRENT_FILE_MATCHES <regex>', 'Match against the entire current file content.', 'Whole-file config or structure checks'],
          ['WHEN FILE_NAME_IS <name>', 'Require an exact filename.', 'AndroidManifest.xml, Info.plist, web.xml'],
          ['WHEN FILE_PATH_MATCHES <glob>', 'Require the current path to match a glob.', 'Path-specific or framework-specific rules'],
          ['UNLESS PRESENT <regex>', 'Fail if a safe pattern is present.', 'Early mitigation exclusion'],
          ['UNLESS CURRENT_FILE_MATCHES <regex>', 'Fail if the full file matches an exclusion pattern.', 'Skip known-safe structural cases'],
          ['OBSERVE PROJECT_HAS_GLOB <glob> AS <label>', 'Record related files from the project root in trace metadata.', 'Surface supporting config or companion files'],
          ['REPORT AS <outcome>', 'Set the rule outcome.', 'Usually area_of_interest'],
          ['REASON / FAIL_REASON / TRACE', 'Store decision rationale and trace text.', 'Reviewer context and suppression reasons'],
        ]}
      />
      <P>
        <Code>WHEN EXPR</Code> supports <Code>PRESENT:</Code>, <Code>MISSING:</Code>,{' '}
        <Code>EXISTS:</Code>, <Code>&amp;&amp;</Code>, <Code>||</Code>, <Code>!</Code>, and
        parentheses.
      </P>

      <SubHeading id="rdl-examples">Examples</SubHeading>
      <P><strong>Example 1 - PHP SQL injection gating:</strong></P>
      <CodeBlock>{`<rule>
  <name>Possible SQL Injection in Query Execution</name>
  <regex><![CDATA[(?i)\\b(?:mysql_query|mysqli_query|->query)\\s*\\(]]></regex>
  <rdl_ref>logic/rdl/v1/common/core/insecure_sql_query_unsafe_string_concatenation.rdl</rdl_ref>
</rule>

VERSION 1
WHEN PRESENT /\\b(?:mysql_query|mysqli_query|->query)\\s*\\(/i
WHEN EXPR PRESENT:\\$_(GET|POST|REQUEST|COOKIE) && MISSING:\\b(?:prepare|bindParam|bindValue|PDO::prepare)\\b
REPORT AS area_of_interest
REASON Query execution appears to rely on direct input without parameterisation.`}</CodeBlock>
      <P>
        The regex stays broad enough to catch candidate query APIs. The external RDL file then keeps
        only the cases where input sources are present and parameterisation appears absent.
      </P>

      <P><strong>Example 2 - Android manifest rule using filename and full-file checks:</strong></P>
      <CodeBlock>{`<rule>
  <name>Exported Components Without Permission</name>
  <regex><![CDATA[<(?P<component>activity|service|receiver|provider)\\s[^>]*android:name="(?P<name>[^"]+)"[^>]*android:exported="true"[^>]*(?:/>|>)]]></regex>
  <rdl_ref>logic/rdl/v1/mobile/android/core/exported_components.rdl</rdl_ref>
</rule>

VERSION 1
WHEN FILE_NAME_IS AndroidManifest.xml
WHEN CURRENT_FILE_MATCHES /android:exported\\s*=\\s*"true"/i
WHEN MISSING /android:permission\\s*=\\s*"/i
REPORT AS area_of_interest
REASON Exported component appears reachable without a permission guard.`}</CodeBlock>
      <P>
        This is the typical split of responsibilities: <Code>regex</Code> finds candidates,{` `}
        <Code>scan_config</Code> controls presentation, and <Code>rdl_ref</Code> confirms the wider
        file context before the finding survives.
      </P>

      <P><strong>Example 3 - File-path area-of-interest rule:</strong></P>
      <CodeBlock>{`<rule>
  <name>Admin Section File Path</name>
  <regex><![CDATA[(?i)(^|/)(admin|administrator|root)(/|$)]]></regex>
  <rdl_ref>logic/rdl/v1/filepaths/core/admin_section.rdl</rdl_ref>
</rule>

VERSION 1
WHEN CURRENT_FILE_MATCHES /(^|\\/)(admin|administrator|root)(\\/|$)/i
UNLESS CURRENT_FILE_MATCHES /(^|\\/)(tests?|docs?|samples?|examples?)(\\/|$)/i
REPORT AS area_of_interest
REASON File path suggests privileged application functionality.
FAIL_REASON Path matched an excluded documentation or sample location.`}</CodeBlock>
      <P>
        For file-path analysis, the regex and the RDL script operate on the normalized relative path
        string rather than source code text.
      </P>

      <P><strong>Example 4 - Project observation rule:</strong></P>
      <CodeBlock>{`VERSION 1
WHEN FILE_NAME_IS AndroidManifest.xml
WHEN CURRENT_FILE_MATCHES /android:usesCleartextTraffic\\s*=\\s*"true"/i
OBSERVE PROJECT_HAS_GLOB **/network_security_config*.xml AS network_security_configs
REPORT AS area_of_interest
REASON Cleartext traffic is enabled; related network security config files were recorded for reviewer context.`}</CodeBlock>
      <P>
        <Code>OBSERVE</Code> currently records supporting project files in trace metadata. It is
        useful for reviewer context, but it does not by itself gate the rule result.
      </P>

      <SubHeading id="rdl-fp-reduction">How RDL Reduces False Positives</SubHeading>
      <P>
        Without RDL, every regex hit is reported regardless of context. RDL adds the file-aware pass
        that keeps the useful matches and suppresses the obvious false positives:
      </P>
      <Table
        headers={['Pattern', 'Without RDL', 'With RDL']}
        rows={[
          ['getSharedPreferences()', 'Flags every preference access (high FP rate)', 'Only flags when sensitive keys AND no encryption are present'],
          ['loadUrl(someVar)', 'Flags every loadUrl call including hardcoded safe URLs', 'Only flags dynamic/interpolated URLs; suppresses about:blank, android_asset'],
          ['Room.databaseBuilder()', 'Flags DB setup calls - zero injection risk (100% FP)', 'Replaced with @Query interpolation pattern - actual injection risk only'],
          ['addJavascriptInterface()', 'Misses real calls due to wrong argument pattern', 'Simplified regex catches all calls; always flagged for review'],
          ['System.getenv("SECRET")', 'Flags as hardcoded secret (FP - it is a safe read)', 'Suppressed by MISSING:System.getenv condition'],
        ]}
      />
      <Note type="warn">
        <strong>Whole-file limitation:</strong> <Code>WHEN PRESENT</Code>, <Code>WHEN MISSING</Code>,
        and <Code>WHEN EXPR</Code> are evaluated against the <em>entire file</em>, not the matched
        line only. If a mitigation appears anywhere in the file, all candidates in that file can be
        suppressed. That trade-off is intentional: lower noise at the cost of occasionally hiding an
        issue in an otherwise-safe file.
      </Note>

      <SubHeading id="rdl-authoring">Authoring Guidance</SubHeading>
      <ul className="help-list">
        <li>Keep <Code>&lt;regex&gt;</Code> broad enough to catch candidates, then use RDL to filter context.</li>
        <li>Use <Code>&lt;rdl_ref&gt;</Code> for all new rules. Do not add new inline <Code>&lt;rdl&gt;</Code> blocks.</li>
        <li>Prefer <Code>WHEN PRESENT</Code> / <Code>WHEN MISSING</Code> for simple gates and <Code>WHEN EXPR</Code> only when the logic genuinely needs boolean composition.</li>
        <li>Put report-facing intent in <Code>REASON</Code> and suppression-facing intent in <Code>FAIL_REASON</Code>.</li>
        <li>For file-path rules, write regex and RDL conditions against normalized slash-separated relative paths.</li>
      </ul>
    </section>
  )
}

function ScanConfigSection() {
  return (
    <section className="help-section">
      <SectionHeading id="scan-config">scan_config - Rule-Driven Scanning &amp; Reporting</SectionHeading>
      <P>
        <Code>scan_config</Code> is an optional XML block inside any <Code>&lt;rule&gt;</Code> that
        controls how the engine scans for that rule and how matches appear in reports. Rules without
        a <Code>scan_config</Code> block behave exactly as before - the block is fully opt-in and
        every field has a safe default.
      </P>
      <P>
        The default model - regex applied line-by-line, one finding entry per match - works well for
        self-contained code patterns. It falls short for structured / declarative files like
        AndroidManifest.xml and Kubernetes YAML, rules that fire many times in one file for the same
        conceptual issue, multi-line patterns, and cases where the reviewer needs surrounding context
        to triage quickly.
      </P>

      <SubHeading id="scan-config-schema">Full Schema</SubHeading>
      <CodeBlock>{`<scan_config>

    <!-- MATCH MODE -->
    <!-- line : regex applied per line (default - all existing rules) -->
    <!-- file : regex applied to full file content with MULTILINE|    -->
    <!--        DOTALL. Use for structured/declarative files.          -->
    <match_mode>line</match_mode>

    <!-- CONTEXT TYPE -->
    <!-- none         : show only the matched line (default)           -->
    <!-- named_groups : extract named (?P<name>...) capture groups     -->
    <!--               and display them as labelled fields.            -->
    <!-- lines        : include N raw lines before/after the match.    -->
    <!-- backward     : scan backward from match for a secondary       -->
    <!--               pattern - first capture group becomes label.    -->
    <context_type>none</context_type>

    <!-- Used when context_type = lines                                -->
    <!-- Recommended: before + after <= 12 lines                      -->
    <context_lines_before>0</context_lines_before>
    <context_lines_after>0</context_lines_after>

    <!-- Used when context_type = backward                             -->
    <context_pattern></context_pattern>
    <context_depth>10</context_depth>

    <!-- AGGREGATION -->
    <!-- none : each match = one finding entry (default)               -->
    <!-- file : all matches in a file collapse into one entry          -->
    <aggregate>none</aggregate>

    <!-- REPORT FORMAT -->
    <!-- default        : match snippet + context lines (default)      -->
    <!-- component_list : table of named_group captures + line numbers -->
    <!-- secret_list    : compact list, masks long values              -->
    <report_format>default</report_format>

    <!-- HIGHLIGHTING (CLI: ANSI colour, Web: CSS span)               -->
    <highlight_enabled>true</highlight_enabled>

    <!-- Simple highlight (single target)                             -->
    <!-- highlight_target: match | groups | pattern                   -->
    <highlight_target>match</highlight_target>
    <highlight_groups></highlight_groups>    <!-- comma-sep group names -->
    <highlight_pattern></highlight_pattern>  <!-- regex for pattern mode -->

    <!-- Colours: red | yellow | cyan | green | magenta | bold         -->
    <highlight_color>red</highlight_color>

    <!-- Multi highlight (advanced - overrides simple fields above)   -->
    <!-- type values: match | group:<name> | pattern:<regex>          -->
    <marks>
        <mark color="red">match</mark>
        <mark color="cyan">group:component</mark>
        <mark color="yellow">pattern:android:exported="true"</mark>
    </marks>

</scan_config>`}</CodeBlock>

      <SubHeading id="scan-config-profiles">Platform Profiles</SubHeading>
      <P>
        Three profiles cover the vast majority of rule types. Pick the profile that matches your
        file type and adjust fields from there.
      </P>

      <P><strong>Profile A - <Code>structured</Code> (declarative / config files)</strong></P>
      <P>
        Use for: AndroidManifest.xml, Kubernetes YAML, Terraform HCL, Dockerfile, plist, web.xml.
        The regex must use named capture groups - the engine extracts them and displays them as
        labelled columns alongside the line number.
      </P>
      <CodeBlock>{`<scan_config>
    <match_mode>file</match_mode>
    <context_type>named_groups</context_type>
    <aggregate>file</aggregate>
    <report_format>component_list</report_format>
    <highlight_enabled>true</highlight_enabled>
    <marks>
        <mark color="red">match</mark>
    </marks>
</scan_config>`}</CodeBlock>

      <P>Full example - Android exported components rule:</P>
      <CodeBlock>{`<rule>
    <name>Exported Components Without Permission</name>
    <regex><![CDATA[<(?P<component>activity|service|receiver|provider)\\s[^>]*
android:name="(?P<name>[^"]+)"[^>]*android:exported="true"[^>]*(?:/>|>)]]></regex>
    <rdl_ref>logic/rdl/v1/mobile/android/core/exported_components.rdl</rdl_ref>
    <scan_config>
        <match_mode>file</match_mode>
        <context_type>named_groups</context_type>
        <aggregate>file</aggregate>
        <report_format>component_list</report_format>
        <marks>
            <mark color="red">pattern:android:exported\\s*=\\s*"true"</mark>
            <mark color="cyan">pattern:android:name\\s*=\\s*"[^"]+"</mark>
        </marks>
    </scan_config>
    ...
</rule>`}</CodeBlock>

      <P>Report output - one clean table instead of five identical finding entries:</P>
      <CodeBlock>{`Exported Components Without Permission        HIGH    AndroidManifest.xml

  Line  82    activity    .MainActivity
  Line  95    service     .SyncService
  Line 110    receiver    .BootReceiver
  Line 125    activity    .DeepLinkActivity`}</CodeBlock>

      <P><strong>Profile B - <Code>code</Code> (source code files)</strong></P>
      <P>
        Use for: Python, JavaScript, PHP, Java, Go, Kotlin, Ruby, C, C++, .NET, Bash, PowerShell.
        Use <Code>context_lines_before</Code> to show what leads into the vulnerable call.
        Use <Code>context_lines_after</Code> to show what follows (error handling, block contents).
      </P>
      <CodeBlock>{`<scan_config>
    <match_mode>line</match_mode>
    <context_type>lines</context_type>
    <context_lines_before>3</context_lines_before>
    <context_lines_after>0</context_lines_after>
    <aggregate>none</aggregate>
    <report_format>default</report_format>
    <highlight_enabled>true</highlight_enabled>
    <highlight_target>match</highlight_target>
    <highlight_color>red</highlight_color>
</scan_config>`}</CodeBlock>

      <P>Report output - reviewer sees the inadequate sanitisation on line 45 without opening the file:</P>
      <CodeBlock>{`Insecure File Inclusion                       HIGH    controllers/page.php : Line 47

  44 |  $page = $_GET['page'];
  45 |  $page = str_replace('../', '', $page);
  46 |
  47 >  include($page . '.php');`}</CodeBlock>

      <P><strong>Profile C - <Code>config</Code> (flat configuration / secret files)</strong></P>
      <P>
        Use for: <Code>.env</Code>, <Code>.properties</Code>, <Code>appsettings.json</Code>,{' '}
        <Code>*.tfvars</Code>, <Code>*.ini</Code>. The matched line is self-explanatory - no
        surrounding context adds value. <Code>aggregate:file</Code> collapses multiple secrets in
        the same file into one finding entry.
      </P>
      <CodeBlock>{`<scan_config>
    <match_mode>line</match_mode>
    <context_type>none</context_type>
    <aggregate>file</aggregate>
    <report_format>secret_list</report_format>
    <highlight_enabled>true</highlight_enabled>
    <highlight_target>match</highlight_target>
    <highlight_color>red</highlight_color>
</scan_config>`}</CodeBlock>

      <P>Report output:</P>
      <CodeBlock>{`Hardcoded Credentials                         CRITICAL   .env

  Line  3    DB_PASSWORD    = "prod_p@ssw..."
  Line  7    API_KEY        = "sk-live-xK..."
  Line 12    JWT_SECRET     = "mySuperSec..."`}</CodeBlock>

      <SubHeading id="scan-config-highlighting">Highlighting</SubHeading>
      <Table
        headers={['Value', 'CLI (ANSI)', 'Web CSS class', 'Use for']}
        rows={[
          ['red', 'bright red', 'hl-red', 'Dangerous sinks, injections, RCE, hardcoded secrets'],
          ['yellow', 'bright yellow', 'hl-yellow', 'Weak patterns, deprecated, missing flags'],
          ['cyan', 'bright cyan', 'hl-cyan', 'Structural / informational (exports, routes, config)'],
          ['green', 'bright green', 'hl-green', 'Mitigations present ("Mitigation Identified" rules)'],
          ['magenta', 'bright magenta', 'hl-magenta', 'Framework-specific patterns'],
          ['bold', 'bold only', 'hl-bold', 'Emphasis with no colour - safe for monochrome terminals'],
        ]}
      />
      <P><strong>Simple</strong> - one thing to highlight:</P>
      <CodeBlock>{`<highlight_target>match</highlight_target>
<highlight_color>red</highlight_color>`}</CodeBlock>

      <P><strong>Named group</strong> - highlight a specific captured group:</P>
      <CodeBlock>{`<highlight_target>groups</highlight_target>
<highlight_groups>name,component</highlight_groups>
<highlight_color>cyan</highlight_color>`}</CodeBlock>

      <P><strong>Multi</strong> - multiple highlight passes with different colours:</P>
      <CodeBlock>{`<marks>
    <mark color="cyan">pattern:android:name\\s*=\\s*"[^"]+"</mark>
    <mark color="red">pattern:android:exported\\s*=\\s*"true"</mark>
</marks>`}</CodeBlock>
      <Note type="info">
        Max 3 marks per rule. Beyond that, the snippet becomes visually noisy. If you need more than
        3 highlights, the rule is probably doing too much - consider splitting it.
      </Note>

      <SubHeading id="scan-config-authoring">Rule Authoring Guide</SubHeading>
      <P>Answer these questions before writing <Code>scan_config</Code> values:</P>

      <P><strong>Q1 - What type of file does this rule target?</strong></P>
      <Table
        headers={['File type', 'Profile', 'match_mode']}
        rows={[
          ['AndroidManifest.xml, plist, web.xml', 'structured', 'file'],
          ['Kubernetes YAML, Helm charts', 'structured', 'file'],
          ['Terraform HCL, .tfvars', 'structured', 'file'],
          ['Dockerfile', 'structured', 'file'],
          ['Python, JS, PHP, Java, Go, Kotlin, Ruby, C/C++, .NET', 'code', 'line'],
          ['Bash, PowerShell', 'code', 'line'],
          ['.env, .properties, appsettings.json, config files', 'config', 'line'],
        ]}
      />

      <P><strong>Q2 - Does the matched line tell the full story?</strong></P>
      <Table
        headers={['Situation', 'Setting']}
        rows={[
          ['Match is self-explanatory', 'context_type: none'],
          ['Setup / source is above the match', 'context_lines_before: 3–5, context_lines_after: 0'],
          ['Match opens a block, need to see inside', 'context_lines_before: 0, context_lines_after: 5–8'],
          ['Both sides needed', 'Set both - keep before + after ≤ 12'],
        ]}
      />

      <P><strong>Q3 - Can this rule fire many times in one file for the same issue?</strong></P>
      <Table
        headers={['Situation', 'Setting']}
        rows={[
          ['Yes - all instances are the same issue', 'aggregate: file'],
          ['No - each instance is distinct', 'aggregate: none'],
        ]}
      />

      <P><strong>Q4 - Which report_format?</strong></P>
      <Table
        headers={['Situation', 'Format']}
        rows={[
          ['context_type: named_groups', 'component_list'],
          ['Detecting secrets / credentials', 'secret_list'],
          ['Everything else', 'default'],
        ]}
      />

      <P><strong>Q5 - What to highlight?</strong></P>
      <Table
        headers={['Situation', 'Config']}
        rows={[
          ['One clear dangerous element', 'highlight_target: match, color: red'],
          ['Dangerous pattern within a wider match', 'highlight_target: pattern + tighter regex, color: red'],
          ['Match has identity + dangerous attribute', '<marks> with cyan for identity, red for risk'],
          ['Rule detects absence (missing flag)', 'Highlight what IS there in yellow'],
          ['Mitigation Identified rule', 'color: green'],
          ['Deprecated / weak, not directly exploitable', 'color: yellow'],
        ]}
      />

      <P><strong>Pre-submission checklist:</strong></P>
      <CodeBlock>{`[ ] scan_config block present (even if using all defaults)
[ ] match_mode appropriate for the file type
[ ] If match_mode=file, regex uses named groups for all meaningful captures
[ ] context_lines_before + context_lines_after <= 12
[ ] aggregate setting is justified
[ ] report_format matches context_type
[ ] highlight colour follows the semantic palette above
[ ] Rule tested on at least one real sample file
[ ] Report output reviewed manually for clarity`}</CodeBlock>
    </section>
  )
}

function PlatformsSection() {
  return (
    <section className="help-section">
      <SectionHeading id="platforms">Platforms &amp; Rules</SectionHeading>
      <P>DakshSCRA includes built-in rules for the following platforms:</P>
      <Table
        headers={['Platform', '-r value', 'Default extensions']}
        rows={[
          ['PHP', 'php', '.php'],
          ['Java', 'java', '.java'],
          ['.NET / C#', 'dotnet', '.cs, .aspx, .cshtml'],
          ['Python', 'python', '.py'],
          ['JavaScript / Node', 'javascript', '.js, .ts, .jsx, .tsx'],
          ['Go', 'go', '.go'],
          ['Ruby / Rails', 'ruby', '.rb'],
          ['Kotlin', 'kotlin', '.kt, .kts'],
          ['C', 'c', '.c, .h'],
          ['C++', 'cpp', '.cpp, .cc, .cxx, .hpp'],
          ['Rust', 'rust', '.rs'],
          ['Android', 'android', '.java, .kt, AndroidManifest.xml, Gradle and XML'],
          ['iOS', 'ios', '.swift, .m, .mm, plist and entitlements'],
          ['React Native', 'reactnative', '.js, .jsx, .ts, .tsx and native mobile files'],
          ['Flutter', 'flutter', '.dart, pubspec.yaml and native mobile files'],
          ['Xamarin', 'xamarin', '.cs, .csproj and mobile configuration'],
          ['.NET MAUI', 'maui', '.cs, .csproj, .xaml and mobile configuration'],
          ['Kotlin Multiplatform', 'kmp', '.kt, .kts, Gradle and native mobile files'],
          ['Ionic / Capacitor', 'ionic', '.ts, .js, .html and mobile configuration'],
          ['NativeScript', 'nativescript', '.js, .ts and native mobile files'],
          ['Cordova', 'cordova', 'config.xml, .js, .ts, .html and native mobile files'],
          ['Bash', 'bash', '.sh, .bash, .bsh'],
          ['PowerShell', 'powershell', '.ps1, .psm1, .psd1, .ps1xml'],
          ['Dockerfile', 'dockerfile', 'Dockerfile, Dockerfile.*, .dockerfile'],
          ['Terraform', 'terraform', '.tf, .tfvars, .tf.json'],
          ['Kubernetes', 'kubernetes', '.yaml, .yml'],
          ['Common patterns', 'common', 'Shared source/configuration patterns across platforms'],
        ]}
      />
      <P>Combine multiple platforms with commas:</P>
      <CodeBlock>{`python dakshscra.py -r php,java,javascript -t ./app`}</CodeBlock>
      <P>The extensions above are representative. Automatic detection also selects applicable framework packs. Use the live registry for the complete platform/framework and file-type list:</P>
      <CodeBlock>{`python dakshscra.py -l RF`}</CodeBlock>
    </section>
  )
}

function FindingsReferenceSection() {
  return (
    <section className="help-section">
      <SectionHeading id="findings-reference">Findings Reference</SectionHeading>
      <P>Common rule categories and the types of code patterns they match:</P>
      <Table
        headers={['Category', 'Examples']}
        rows={[
          ['Injection', 'SQL, command, LDAP, XPath, template injection'],
          ['File operations', 'Path traversal, arbitrary file read/write, include/require'],
          ['Authentication', 'Hardcoded credentials, weak hashing, session mismanagement'],
          ['Cryptography', 'Weak algorithms, insecure random, hardcoded keys'],
          ['Deserialization', 'Unsafe object deserialization'],
          ['SSRF / Open redirect', 'Unvalidated URL construction'],
          ['Information disclosure', 'Debug output, error exposure, sensitive data logging'],
          ['Configuration', 'Dangerous settings, debug mode enabled'],
        ]}
      />
    </section>
  )
}

function PdfReportsSection() {
  return (
    <section className="help-section">
      <SectionHeading id="pdf-reports">Report Formats &amp; PDF</SectionHeading>
      <P>CLI and Web UI share report content and four export formats. HTML provides a summary with linked detail pages, PDF a consolidated printable report, Word an editable document, and JSON saved structured evidence. Choose reports on demand in the Web UI Reports tab; CLI formats are selected with <Code>-rpt</Code>.</P>
      <CodeBlock>{`python dakshscra.py -r auto -t ./app -rpt html,pdf,docx,json`}</CodeBlock>
      <P>Native PDF generation requires Playwright's Chromium browser. The Docker application image already includes Chromium and its system dependencies:</P>
      <CodeBlock>{`python -m playwright install chromium`}</CodeBlock>

      <SubHeading id="pdf-during">Generate PDF during a scan</SubHeading>
      <CodeBlock>{`python dakshscra.py -r php -t ./app -rpt html,pdf`}</CodeBlock>

      <SubHeading id="pdf-after">Generate PDF after a scan</SubHeading>
      <CodeBlock>{`# Both single and multi-file PDFs
python dakshscra.py --pdf-from-json --json-input-dir ./reports/my-project/20260329081500/data

# Single combined PDF only
python dakshscra.py --pdf-from-json --json-input-dir ./reports/my-project/20260329081500/data --pdf-single-only

# From a custom JSON directory
python dakshscra.py --pdf-from-json --json-input-dir ./custom/reports/my-project/20260329081500/data`}</CodeBlock>
      <Note>
        PDF is not generated by default to keep scans fast. The JSON output is always saved and can be used
        to generate PDFs at any time after the scan.
      </Note>
    </section>
  )
}

function TipsSection() {
  return (
    <section className="help-section">
      <SectionHeading id="tips">Tips &amp; Common Patterns</SectionHeading>

      <SubHeading id="tips-first-scan">Starting with an unknown codebase</SubHeading>
      <CodeBlock>{`python dakshscra.py -r auto --recon --estimate -t ./target`}</CodeBlock>
      <P>
        Detects the technology stack, picks the right rules, and produces an effort estimate in one pass.
      </P>

      <SubHeading id="tips-large">Faster pass on large codebases</SubHeading>
      <CodeBlock>{`python dakshscra.py -r auto --skip-analysis -t ./large_app`}</CodeBlock>
      <P>
        Skipping the optional native analyzer reduces work while preserving the selected RDL engines.
        To include native analysis later, run a new scan with analysis enabled. Report generation uses only saved results.
      </P>

      <SubHeading id="tips-resume">Resuming an interrupted scan</SubHeading>
      <CodeBlock>{`python dakshscra.py --resume-scan -r php -t ./app`}</CodeBlock>
      <P>
        Checkpointing can be controlled with <Code>--state</Code>, <Code>--no-state</Code> and <Code>--state-file</Code>.
        Resume using the same target, rules and checkpoint; inspect the configured state settings before relying on recovery.
      </P>

      <SubHeading id="tips-baseline">Suppressing known false positives</SubHeading>
      <P>Generate a baseline from current findings:</P>
      <CodeBlock>{`python dakshscra.py -r php -t ./app --baseline-generate`}</CodeBlock>
      <P>
        On subsequent scans, the baseline is loaded automatically and those findings are excluded from reports.
        Use <Code>--no-baseline</Code> to run without it temporarily.
      </P>

      <SubHeading id="tips-rules">Checking what rules exist</SubHeading>
      <CodeBlock>{`# List rule names
python dakshscra.py -l R

# List rules with associated file types
python dakshscra.py -l RF`}</CodeBlock>
    </section>
  )
}

/* ─── Main HelpPanel component ──────────────────────────────── */
export default function HelpPanel() {
  const [activeId, setActiveId] = useState('what-is')
  const contentRef = useRef(null)
  const observerRef = useRef(null)

  useEffect(() => {
    const el = contentRef.current
    if (!el) return

    const ids = TOC.map((t) => t.id)
    const headings = ids.map((id) => document.getElementById(id)).filter(Boolean)

    observerRef.current = new IntersectionObserver(
      (entries) => {
        // Find the topmost visible heading
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)
        if (visible.length > 0) {
          setActiveId(visible[0].target.id)
        }
      },
      { root: el, rootMargin: '0px 0px -70% 0px', threshold: 0 }
    )

    headings.forEach((h) => observerRef.current.observe(h))
    return () => observerRef.current?.disconnect()
  }, [])

  function scrollTo(id) {
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })
      setActiveId(id)
    }
  }

  return (
    <div className="help-shell">
      {/* TOC sidebar */}
      <aside className="help-toc">
        <div className="help-toc-title">Contents</div>
        <nav>
          {TOC.map((item) => (
            <button
              key={item.id}
              className={`help-toc-item${item.indent ? ' indent' : ''}${activeId === item.id ? ' active' : ''}`}
              onClick={() => scrollTo(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </aside>

      {/* Scrollable content area */}
      <div className="help-content" ref={contentRef}>
        <div className="help-content-inner">
          <div className="help-header">
            <h1 className="help-title">DakshSCRA Usage Guide</h1>
            <p className="help-subtitle">
              Reference for CLI and Web UI usage, RDL engines, review workflows, platforms, and HTML/PDF/Word/JSON reports.
            </p>
          </div>
          <WhatIsSection />
          <DistinctiveSection />
          <InstallationSection />
          <CliUsageSection />
          <WebUISection />
          <RDLSection />
          <ScanConfigSection />
          <PlatformsSection />
          <FindingsReferenceSection />
          <PdfReportsSection />
          <TipsSection />
        </div>
      </div>
    </div>
  )
}
