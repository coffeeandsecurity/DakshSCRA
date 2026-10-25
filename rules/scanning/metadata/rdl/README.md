# RDL data layout

Global tool defaults live in `config/tool.yaml`. Rule definitions remain under
`rules/scanning/logic/rdl/`. Supporting data is grouped by responsibility:

| Path (from repository root) | Purpose | Primary consumers / maintenance |
| --- | --- | --- |
| `rules/scanning/metadata/rdl/baseline.json` | Generated legacy-to-native rule inventory | `core/rdl/baseline_runtime.py`, `core/rdl/narratives.py`; regenerate with local `tools/rdl_baseline.py` |
| `rules/scanning/metadata/rdl/additional.json` | Supplemental native rule registrations and paired examples | Baseline runtime, coverage audit and rule-index generator; maintain with the owning rule |
| `rules/scanning/metadata/rdl/platform-overlays.json` | Additional platform-to-pack dispatch | Baseline runtime and coverage audit |
| `rules/scanning/metadata/rdl/shadow-mappings.json` | Legacy/native comparison mappings and project-flow dispatch | `core/rdl/shadow.py`, scan catalog and rule-index generator |
| `rules/scanning/semantics/rdl/catalog.json` | Language APIs mapped to semantic concepts | `core/rdl/catalog.py` |
| `resources/guidance/rdl/semantic.json` | Semantic finding descriptions, impact and remediation | `core/rdl/narratives.py` |
| `resources/guidance/rdl/mitigations.json` | Mitigation pattern reference data | Retained reference inventory; no current runtime loader |
| `resources/guidance/analysis/findings.json` | Advanced-analysis finding guidance | `core/rdl/narratives.py` |
| `tests/rdl/data/baseline-exceptions.json` | Local baseline comparison exceptions | Local `tools/rdl_compare_baseline.py` |
| `tests/rdl/data/release-gates.json` | Local validation thresholds | `core/rdl/release.py`, invoked by local release checks |

The `tests/` directory and non-public validation tools stay local and excluded
from published archives. Runtime scans do not depend on the validation data.

`rdl.shadow_enabled` in `config/tool.yaml` supplies the default comparison
enablement. Explicit review selection and `DAKSH_RDL_V2_SHADOW` retain their
existing precedence. The mapping file retains schema and authoritative-engine
constraints; these describe the comparison protocol rather than user defaults.
Explicit custom mapping files may still supply their own `enabled` value.

Keep rule IDs, XML pack paths and native rule paths stable when moving supporting
data. Update loaders, generators, tests and documentation together. Do not keep
duplicate copies or fall back to obsolete `config/rdl_*.json` paths.
