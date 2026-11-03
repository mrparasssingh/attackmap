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
- **In progress**: None. Phase 1 and Phase 2 completed.
- **Broken**: None.
- **Avoid**: Do not auto-download datasets or report PDFs. Do not invent labels or evaluation splits.
- **Open questions**: None for Phase 1.

## 2026-11-01 | Gemini 3.8 Flash — Phase 2: KeywordRetriever Baseline Completed
- **Done**:
  - Implemented `TextTokenizer` supporting Unicode-aware letter/digit splitting, lowercase normalization with `Locale.ROOT`, short-token filtering (< 2 chars), and stopword filtering.
  - Added `stopwords.txt` under `src/main/resources/` with standard English stopwords, strictly preserving security-relevant tokens (`run`, `execute`, `remote`, `file`, `access`, `use`).
  - Added retrieval weights (`NAME_WEIGHT = 3.0`, `DESC_WEIGHT = 1.0`, `ID_MATCH_BONUS = 100.0`) in `Config.java`.
  - Implemented `KeywordRetriever` conforming to `Retriever` interface with immutable index construction and thread safety.
  - Enforced scoring contract: sum over unique query tokens of name/desc weights + explicit-ID regex bonus (`\bT\d{4}(\.\d{3})?\b`).
  - Implemented tie-breaking on ascending technique ID and zero-score exclusion contract.
  - Implemented comprehensive JUnit 5 tests covering all 23 scenarios in `KeywordRetrieverTest` and 9 in `TextTokenizerTest`.
  - Added paper-verifiable hand-calculated scoring test with exact arithmetic commented in code.
  - Verified clean compilation with `-Xlint:all` (zero warnings, zero errors) and green test suite (`Tests run: 49, Failures: 0, Errors: 0, Skipped: 1`).
  - Updated `README.md` with scoring formula, ranking contract, and known limitations.
- **In progress**: Phase 2 completed. Ready for review.
- **Broken**: None.
- **Avoid**: Do not introduce stemming in this phase without approval. No new dependencies.
- **Open questions**: See Phase 2 report.
