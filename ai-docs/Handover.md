# Handover History

Durable, dated history of finished sessions.

## 2026-10-31 | Gemini 3.8 Flash — Phase 1: ATT&CK STIX Parser Finalized & Pushed to GitHub
- **Done**:
  - Implemented `StixParser` supporting STIX 2.1 JSON parsing with Jackson Databind 2.17.3.
  - Implemented immutable `Technique(id, name, description, tactics, isSubTechnique)` record with defensive copying.
  - Tactics preserved as lowercase kill-chain short names (e.g. `defense-evasion`).
  - Revoked (`revoked: true`) and deprecated (`x_mitre_deprecated: true`) techniques filtered out prior to duplicate detection.
  - Sub-technique inclusion/exclusion toggle verified (`includeSubTechniques`).
  - Implemented `StixParseException` as the dedicated exception for malformed JSON, unreadable streams, and duplicate active technique IDs.
  - Created domain contracts `Prediction` and `Retriever`.
  - Added comprehensive JUnit 5 test suite (`StixParserTest`) with synthetic fixtures (`stix-sample.json`, `stix-duplicate-active.json`).
  - Executed mutation checks: confirmed that bypassing revoked/deprecated filters or duplicate detection fails tests predictably.
  - Verified real-data smoke test against official `enterprise-attack-20.0.json` (SHA-256 `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`):
    - 227 parent techniques
    - 706 total techniques including sub-techniques
    - 100.00% valid lowercase tactics
    - `Tests run: 17, Failures: 0, Errors: 0, Skipped: 0`
  - `.gitignore` verified to exclude `data/`, `target/`, and `/enterprise-attack-*.json`.
  - Finalized `README.md` with Data Provenance and official MITRE ATT&CK attribution notice.
  - Created public GitHub repository and pushed `main` and `phase-1-done` tag:
    - URL: https://github.com/mrparasssingh/attackmap
- **In progress**: Phase 1 finalized and pushed to remote. Awaiting user instructions for Phase 2.
- **Broken**: None.
- **Avoid**: Do not auto-download datasets or report PDFs. Do not invent labels or evaluation splits.
- **Open questions**: None for Phase 1.
