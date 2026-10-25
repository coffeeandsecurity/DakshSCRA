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
  { id: 'rdl', label: 'Pattern and Semantic Rules' },
  { id: 'rdl-shadow', label: '↳ Review Modes', indent: true },
  { id: 'rdl-outcomes', label: '↳ Evidence and Outcomes', indent: true },
  { id: 'rdl-authoring', label: '↳ Pattern Rule Authoring', indent: true },
  { id: 'rdl-validation', label: '↳ Validation and Migration', indent: true },
  { id: 'scan-config', label: 'Evidence and Presentation' },
  { id: 'scan-config-schema', label: '↳ Supported Settings', indent: true },
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
          ['Effort estimation', 'Estimates manual review time based on codebase size, complexity, and finding volume'],
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
      "tag": "World's First*",
      "highlight": true,
      "body": "Produces a quantified estimate of manual-review effort based on codebase size and project signals. Configurable assumptions make engagement planning explicit and repeatable."
    },
    {
      "title": "Software Reconnaissance",
      "tag": "World's Second*",
      "highlight": true,
      "body": "Detects languages, frameworks and infrastructure from file contents and project structure before scanning. Connects the technology inventory to automatic rule selection, semantic analysis and review planning."
    },
    {
      "title": "Advanced Semantic and Cross-File Analysis",
      "tag": "Most Advanced Open Source at Release*",
      "highlight": false,
      "body": "Traces user-controlled data from source to sink across supported file boundaries using purpose-built analysis. Advanced Analysis shipped alongside the original RDL in March 2026; RDL v2 extends semantic rule evaluation across files."
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
      <div className="help-debut-note">* Based on general searches at the time each feature was introduced. No similar feature was found in open source security code review tools. For effort estimation, no similar approach was found in commercial tools either. Recon came second after Microsoft Application Inspector. Cross-file analysis was the most advanced among open source code review tools at the time of its release.</div>
      <div className="help-debut-note">
        First introduced at <strong>Black Hat USA 2022</strong> and publicly debuted at <strong>Black Hat USA 2023</strong>, Las Vegas.
      </div>
      <details>
        <summary className="help-p">Release history and supporting evidence</summary>
      <SubHeading id="feature-history">Feature History and Evidence</SubHeading>
      <Table headers={["Feature / milestone", "Date", "Release", "Evidence / scope"]} rows={[
        ["Initial beta and file-path rules", "22 October 2022", "v0.1-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.1-beta">Initial release; retained source includes the dedicated file-path rule inventory.</a></span>],
        ["Software reconnaissance (published introduction)", "9 July 2023", "v0.3-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/releases/tag/v0.3-beta">Release notes introduce recon; earlier repository code is separate implementation evidence.</a></span>],
        ["Manual-review effort estimation (implementation)", "29 July 2023", "Implementation commit", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/commit/65d5c6a">Dedicated estimation module added; not the date of the later fix release.</a></span>],
        ["Original RDL and inter-file Advanced Analysis", "2 March 2026", "v0.31-beta", <span><a href="https://github.com/coffeeandsecurity/DakshSCRA/commit/d90ba51">Conditional rule logic and independent cross-file analysis shipped together. Release display date is 2 March; publication timestamp is 1 March 2026 at 18:39 UTC.</a></span>],
      ]} />
      <SubHeading>Comparative Evidence</SubHeading>
      <ul className="help-list">
        <li><strong>Recon predecessor:</strong> <a href="https://www.microsoft.com/en-us/security/blog/2020/01/16/introducing-microsoft-application-inspector/">Microsoft Application Inspector</a> (16 January 2020) documents an earlier source-characteristics tool. Daksh SCRA recon is placed second after it.</li>
      </ul>
      <div className="help-debut-note">Dates identify repository or release milestones.</div>

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
      <P>Open <Code>http://localhost:3030</Code> in a browser.</P>
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
          [<Code>--estimate</Code>, 'Generate a manual review effort estimation report.'],
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
          [<Code>--rule-mode pattern|semantic|both</Code>, 'Select Pattern Rules, Semantic Rules, or both (default). Evidence still requires reviewer confirmation.'],
          [<Code>--rdl-engine v1|v2|both</Code>, 'Compatibility option for existing scripts; legacy v2 includes native pattern baselines.'],
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
# Open http://localhost:3030`}</CodeBlock>
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
          ['Review mode', 'Pattern + Semantic Rules (recommended), Semantic Rules, or Pattern Rules. Results retain the recorded selection.'],
          ['Verbosity', 'Output detail level (1–3).'],
          ['Recon', 'Enable technology stack detection.'],
          ['Effort Estimate', 'Generate a review effort estimation report.'],
          ['LOC Count', 'Include effective lines of code in the scan summary.'],
          ['Inter-file Analysis', 'Enable the optional native taint analyzer. Its initial value follows Settings. Can be slow on large codebases; independent of RDL engine selection.'],
        ]}
      />

      <P>Open an active job to see Live Scan Telemetry and Log. Telemetry shows stages, elapsed execution time, repository counters, current operation and progress. Completed runs open in the results workspace.</P>

      <p className="help-p"><strong>Completed scan details</strong> include:</p>
      <ul className="help-list">
        <li><strong>Log</strong>: Live streaming output from the scan process.</li>
        <li><strong>Areas of Interest</strong>: Pattern Rule areas of interest, locations and source context.</li>
        <li><strong>Vulnerability Analysis</strong>: Recorded supported findings, suppression decisions, unresolved evidence and coverage limits. A rule match does not prove exploitability.</li>
        <li><strong>Advanced Analysis</strong>: Recorded v2 source-to-sink paths, input entry points and symbol cross references, with Text and Graph evidence views where available.</li>
        <li><strong>Insights</strong>: File/path inventory, recon and effort estimation.</li>
        <li><strong>Summary</strong>: Scan configuration and saved execution metrics.</li>
        <li><strong>Suppressed Areas of Interests (under Areas of Interest)</strong>: Suppressing rule, recorded RDL version, reason, decision trace and source evidence. Inspect an entry or promote it back to findings with review notes.</li>
        <li><strong>Reports</strong>: On-demand exports and available saved artifacts.</li>
      </ul>
      <P>Completed scan data removal deletes saved evidence and reports but keeps a history record. Clear record removes that remaining entry after data removal. Active jobs are protected from deletion.</P>

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
  return <section className="help-section">
    <SectionHeading id="rdl">Pattern Rules and Semantic Rules</SectionHeading>
    <P>Pattern Rules identify areas of interest using patterns and contextual conditions. A reviewer investigates whether they represent actual security issues.</P>
    <P>Semantic Rules provide stronger evidence by analyzing code relationships, input propagation and modeled protections. They can support a finding or suppression, but incomplete modeling, deployment settings and runtime behavior can still affect the conclusion.</P>
    <SubHeading id="rdl-shadow">Review Modes</SubHeading>
    <ul className="help-list">
      <li><strong>Pattern + Semantic Rules</strong>: areas of interest with supported semantic evidence; the default.</li>
      <li><strong>Pattern Rules</strong>: patterns and contextual conditions for manual investigation.</li>
      <li><strong>Semantic Rules</strong>: code relationships and supported input/flow properties; native text baseline packs are skipped.</li>
    </ul>
    <CodeBlock>{`python3 dakshscra.py -r auto -t /path/to/source --rule-mode both
python3 dakshscra.py -r javascript -t /path/to/source --rule-mode pattern
python3 dakshscra.py -r java -t /path/to/source --rule-mode semantic`}</CodeBlock>
    <P>Legacy <Code>--rdl-engine v1|v2|both</Code> remains compatible. Legacy v2 includes text baselines and is not equivalent to semantic-only mode. Existing scan results retain their recorded selections.</P>
    <SubHeading id="rdl-outcomes">Evidence and Outcomes</SubHeading>
    <P>A supported finding satisfies modeled conditions; a suppression satisfies a defined suppression condition; unresolved means evidence or coverage is insufficient. Reviewer-confirmed is reserved for human verification. Neither a match nor a complete path proves exploitability, and suppression does not establish overall safety.</P>
    <SubHeading id="rdl-authoring">Authoring a Pattern Rule</SubHeading>
    <P>Each check is one YAML file under the existing platform or framework directory. Java uses <Code>java/java.rules/*.yaml</Code>; Spring uses <Code>java/framework/spring.rules/*.yaml</Code>. Add a file with a globally unique stable ID to the owning pack. No XML or separate RDL v1 file is required. The catalog and scanner discover it automatically.</P>
    <CodeBlock>{"format: daksh-pattern-rule/v1\nid: javascript.core.dynamic_evaluation_review\ntitle: Dynamic Evaluation Review\ncategory: Code Execution\ndetection:\n  pattern: '\\beval\\s*\\('\n  conditions:\n    - WHEN PRESENT ${pattern}\nreporting:\n  type: area_of_interest\n  reason: Review whether externally influenced text reaches eval.\n  description: Dynamic evaluation requires investigation of its inputs.\n  remediation: Prefer fixed operations and data-only inputs.\n  reviewer: Verify callers, input origins and the execution context.\nscan_config:\n  match_mode: line\n  aggregate: file\n  context_lines_before: 3\n  context_lines_after: 2\n  highlight_enabled: true\n  highlight_color: red"}</CodeBlock>
    <P>Conditions are optional for regex-only rules. The pattern placeholder reuses the candidate expression. WHEN PRESENT, WHEN MISSING, WHEN EXPR, filename/path conditions and project observations remain supported. Whole-file conditions can be affected by protection elsewhere in the file; use Semantic Rules for call-local and flow-specific decisions.</P>
    <P>Imported descriptions, impact, developer guidance and reviewer guidance are retained in reporting.description, impact, remediation and reviewer. Add review_steps and recommendations as lists of concrete investigation and correction steps; they appear alongside the original text in results and reports, including new suppressed source matches.</P>
    <P>Context counts, aggregation, capture-group highlighting, colors and multiple marks are preserved. New saved evidence includes exact token highlights; disabled highlighting stays disabled, and grouped matches keep their surrounding source context.</P>
    <P>Legacy per-rule XML filters are retired and are not recreated in Pattern Rules. Pattern matches remain available for investigation. Semantic Rules assess modeled protections separately. Use scan Exclusions for intentional keyword, path and file-type restrictions. The importer rejects legacy per-rule filters for explicit review.</P>
    <SubHeading id="rdl-validation">Validation and Migration</SubHeading>
    <CodeBlock>{`python3 tools/rdl_lint.py rules/scanning/platform --json
python3 tools/rdl_migrate.py /path/to/old-pack.xml --pattern --logic-root /path/to/scanning --output /path/to/imported.rules`}</CodeBlock>
    <P>Validate positive and negative examples, retained source locations and suppression reasons. The importer requires an empty destination and preserves its inputs. Linting validates structure rather than vulnerability accuracy.</P>
    <P>Semantic Rules remain versioned RDL v2 definitions. Their native text-based baselines remain Pattern Rules and are derived from unified YAML; edit the YAML source rather than compatibility copies. Custom semantic packs still use <Code>--custom-rdl PACK.json</Code>.</P>
  </section>
}

function ScanConfigSection() {
  return <section className="help-section">
    <SectionHeading id="scan-config">Evidence and Presentation Settings</SectionHeading>
    <P>The optional <Code>scan_config</Code> mapping belongs in the same Pattern Rule. It controls matching, grouping, source context and highlighting; it does not establish that an issue is confirmed.</P>
    <SubHeading id="scan-config-schema">Supported Settings</SubHeading>
    <ul className="help-list">
      <li>Matching and grouping: match_mode, aggregate.</li>
      <li>Context: context_type, context_lines_before, context_lines_after, context_pattern, context_depth.</li>
      <li>Presentation: report_format, highlight_enabled, highlight_target, highlight_groups, highlight_pattern, highlight_color.</li>
      <li>Multiple highlights: marks, a list of color/spec mappings.</li>
    </ul>
    <P>Omitted fields use scanner defaults. Keep context bounded and inspect the rendered evidence on representative files. The usage guide contains the full authoring workflow.</P>
  </section>
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
              Reference for CLI and Web UI usage, Pattern and Semantic Rules, review workflows, platforms, and HTML/PDF/Word/JSON reports.
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
