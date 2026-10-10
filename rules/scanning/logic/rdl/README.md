# RDL rule inventories

- [RDL v1](v1/): existing text and path rule logic.
- [RDL v2](v2/README.md): baseline, semantic and additional rules.
- [V2 scope and rule index](v2/INDEX.md): definitions and v1-to-v2 mappings.

Both versions live under `rules/scanning/logic/rdl/`. XML rule packs remain under
`rules/scanning/platform/` and reference v1 rules using
`<rdl_ref>logic/rdl/v1/<platform>/<scope>/<rule>.rdl</rdl_ref>`.
Older `logic/...` and `rdl/logic/v1/...` XML references remain supported by the scanner resolver.
Historical scan reports retain their recorded paths.
