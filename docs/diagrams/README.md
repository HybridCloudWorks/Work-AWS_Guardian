# Architecture diagrams

The `.drawio` files are the source of truth. PNG exports are regenerated from them.

| Diagram | Source | Export |
|---|---|---|
| Architecture context | `01-architecture-context.drawio` | `01-architecture-context.png` |
| Trust boundaries & threats | `02-trust-boundaries-threats.drawio` | `02-trust-boundaries-threats.png` |
| Deploy dataflow | `03-deploy-dataflow.drawio` | _export pending regeneration_ |

## Regenerating a PNG

Open the `.drawio` file in [diagrams.net](https://app.diagrams.net/) (or the Draw.io VS Code extension) and export to PNG with the same base name.

> **Note:** `03-deploy-dataflow.png` was removed because its previous export embedded a real AWS account ID. The source has been redacted to use a `<SANDBOX_ACCOUNT_ID>` placeholder; re-export from the current `.drawio` before committing a replacement PNG, and confirm no account identifiers are rendered.