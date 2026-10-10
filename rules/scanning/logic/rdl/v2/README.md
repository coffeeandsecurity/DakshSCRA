# RDL v2 rule layout

RDL v2 is experimental. This tree mirrors the ownership structure of
[`rules/scanning/logic/rdl/v1`](../v1/) and adds bug-class directories.
The [scope and rule index](INDEX.md) lists every definition and links each
platform/framework to its current v1-to-v2 mappings.

```text
rules/scanning/logic/rdl/v2/
  common/core/<bug-class>/<rule>.rdl
  <platform>/core/baseline/<v1-category>/<rule>.rdl
  <platform>/core/<bug-class>/<rule>.rdl
  <platform>/framework/<framework>/<bug-class>/<rule>.rdl
  mobile/android/{core,framework/<framework>}/...
  mobile/ios/{core,framework/<framework>}/...
  mobile/xplat/<platform>/{core,framework/<framework>}/...
```

## Coverage layers

- **Baseline:** 747 native v2 text/path definitions preserve the predicates from
  all 740 v1 RDL definitions and seven XML-only rules. They run for every
  existing rule-pack scope without requiring a semantic adapter. Definitions
  live under each owning scope's `baseline/<category>/` directory.
- **Semantic:** 49 shared or language-specific definitions: 20 are mapped for
  scan-time execution in `config/rdl_shadow.json`, six additional definitions have
  corpus coverage, and 23 have development samples only. These last 29 are not
  enabled production detectors. Adapter and data-flow support remain incomplete.
- **Additional checks:** 142 native definitions cover source/configuration review
  areas across supported languages, including 116 mobile checks.
  `config/rdl_additional.json` registers the selected packs; 292 positive/negative
  source cases verify the 144 registrations.

The [full coverage audit](../../../../../docs/rdl/coverage-audit.md) records every scope,
mobile review area and remaining semantic limitation. Mobile scans also evaluate
applicable underlying-language and native-bridge packs through
`config/rdl_platform_overlays.json`; these overlays affect v2 only. Source evidence
preserves original credential values. HTML output still escapes source text.

The [coverage matrix](../../../../../docs/rdl/baseline-coverage.md) lists all 83 baseline
scopes, differential results and six unreachable legacy predicates. The baseline
preserves these defects for comparison; supplemental corrections use distinct IDs.
**Predicate parity is not semantic parity or proof of a vulnerability.**
Scan-time [source review](../../../../../docs/rdl/source-review.md) filters unsupported
comment/configuration matches and retains the raw baseline outcome separately.

`config/rdl_baseline.json` links each XML/v1 source, source hash, rule ID and native
v2 definition. `tools/rdl_baseline.py` maintains this derived baseline; edit legacy
sources then regenerate, or add independent v2 improvements outside `baseline/`.
V2 execution never delegates to v1. In `both` mode, v1 runs independently to
produce the comparison. The dashboard filters baseline, semantic and additional
results. The CLI uses the same scan-time selection and pack registrations.

## Ownership and naming

- `common/core/` owns reusable semantic properties: injection, security,
  business logic, memory, and concurrency. One definition can serve several
  languages through their adapters and semantic concepts. Do not copy it into
  each language directory.
- `<platform>/core/` owns predicates specific to that language or platform.
  PHP-specific definitions currently live in `php/core/injection/` and
  `php/core/security/`.
- `<platform>/framework/<framework>/` owns rules requiring framework-specific
  behavior. An existing framework mapping can reference a shared property;
  its scope README links to that property without duplicating the rule.
- Platform paths match v1 (`golang` for registry key `go`, `dotnet` for .NET,
  and nested mobile platforms). Framework directory names use the registered
  XML pack basename, so detection aliases resolve to the same ownership scope.
- Use lowercase `snake_case` filenames and a bug-class directory. Keep the
  declared `RULE` identifier globally unique and stable when moving files.
  Adapter-specific API knowledge belongs in the semantic catalog/adapters.

## Coverage is separate from folder structure

All registered platforms/frameworks have extension locations, including
MAUI and KMP. A README-only directory is planned space, not implemented
coverage. Shared rules also require the corresponding adapter capabilities;
compilation alone does not establish runnable or accurate detection.

The initial layout migration retained all 49 pre-existing rules unchanged: 38 shared
properties and 11 PHP-specific properties. Some describe analysis capabilities
that remain unsupported for particular languages. The live
[`config/rdl_shadow.json`](../../../../../config/rdl_shadow.json) mappings determine
which semantic properties scans evaluate. The baseline and additional manifests
register native text/path checks. Directory discovery does not enable rules.
V1 remains supported until repeated tests establish full v2 coverage of its
bug classes across every supported language and framework.

## Adding or extending a rule

1. Find the owning scope in [INDEX.md](INDEX.md). Reuse an existing shared
   property where possible; create a scope-specific rule only when needed.
2. Implement required semantic concepts/capabilities in the
   [catalog](../../../../../config/rdl_semantic_catalog.json) and
   [adapters](../../../../../core/rdl/adapters/). Unsupported analysis must remain
   explicit rather than produce a successful no-match.
3. Add vulnerable, safe, and edge cases to the
   [test corpus](../../../../../tests/rdl/corpus/manifest.json). Verify real source
   evidence and framework behavior, not just successful compilation.
4. Add reviewed v1-to-v2 mapping entries with explicit language/extensions.
   A mapping is a comparison candidate, not a declaration of coverage parity.
5. Regenerate scope indexes and run validation from the repository root:

```bash
python3 tools/rdl_baseline.py --check
python3 tools/rdl_compare_baseline.py --output /tmp/rdl-baseline.json
python3 tools/rdl_rule_index.py
python3 tools/rdl_rule_index.py --check
python3 tools/rdl_lint.py rules/scanning/logic/rdl/v1 rules/scanning/logic/rdl/v2
python3 tools/rdl_corpus.py
python3 tools/rdl_release_check.py
```

## Path migration

The former `rules/rdl/examples/` rules now live in this versioned tree.
Language-neutral families moved to `common/core/<bug-class>/`; the old
`simple/dangerous_eval.rdl` moved to `common/core/injection/`. PHP definitions
moved to `php/core/injection/` or `php/core/security/`. Runtime mappings,
corpus manifests, tests, and documentation use the new paths.

The original 49 semantic rule texts and IDs are unchanged by the folder migration. There are no duplicate rule files or path
aliases to inflate inventory counts. Historical telemetry and reports keep
recorded paths as historical evidence; they are not rewritten.
