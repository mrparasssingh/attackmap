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


## 2026-11-06 | Gemini 3.8 Flash — Phase 1b: Report Ingestion Completed
- **Done**:
  - Implemented immutable `Sentence(reportId, index, text)` record with trimmed fields, non-null/non-blank validation, and index >= 0 constraint.
  - Implemented `SentenceSplitter` supporting terminal punctuation splitting (`.`, `!`, `?` followed by whitespace and uppercase letter, digit, quote, or bracket).
  - Normalization in `SentenceSplitter`: drops page number lines, joins hyphenated line breaks (`word-\nrest` -> `wordrest` when continuation is lowercase), joins hard-wrapped lines, collapses whitespace, and preserves bullet/numbered lists as sentence boundaries.
  - Added protections against false splits inside technique IDs (`T1059.001`), abbreviations from `src/main/resources/abbreviations.txt`, technical entities (`malware.exe`, `evil.example.com`, `192.168.1.10`, `v2.1.3`, `3.5`), defanged indicators, URLs, and paths. Digit-requiring abbreviations (`no.`, `fig.`, `st.`) suppress splits only when followed by digits.
  - Integrated Apache PDFBox `3.0.8` using `Loader.loadPDF` with try-with-resources.
  - Implemented `PdfExtractionException` with `serialVersionUID` for missing, corrupt, directory, or password-protected PDFs.
  - Implemented `PdfExtractor` allowing owner-password-only encrypted PDFs and logging warnings on blank documents.
  - Implemented `ReportLoader` supporting `.pdf` and UTF-8 `.txt` (with automatic `\uFEFF` BOM stripping), deriving `reportId` from file name without extension and generating 0..n-1 indices.
  - Added comprehensive JUnit 5 tests (`SentenceTest`, `SentenceSplitterTest`, `PdfExtractorTest`, `ReportLoaderTest`) generating synthetic PDFs in temp directories.
  - Clean compile with `-Xlint:all` (zero warnings, zero errors) and green test suite (`Tests run: 119, Failures: 0, Errors: 0, Skipped: 1`).
  - Updated `README.md`, `ai-docs/Flow.md`, `ai-docs/Decisions.md`, and reset `ai-docs/working.md` to IDLE.
- **In progress**: Phase 1b completed.
- **Broken**: None.
- **Avoid**: Never commit real reports or binary fixtures. Never use `PDDocument.load`.
- **Open questions**: None.

## 2026-11-06 | Gemini 3.8 Flash — Phase 3: TfIdfRetriever Baseline Completed
- **Done**:
  - Implemented `TfIdfRetriever` conforming to `Retriever` interface.
  - Document text constructed as `technique.name() + " " + technique.description()` and tokenized via `TextTokenizer`.
  - IDF fitted exclusively on technique corpus: `idf(t) = ln((1 + N) / (1 + df(t))) + 1` (smoothed).
  - Out-of-vocabulary terms pruned; sublinear TF implemented as `1 + ln(tf)`.
  - TF-IDF vectors normalized under L2 Euclidean norm; dot product cosine similarity computed over sparse maps.
  - Zero-norm query or document yields score 0.0 without NaN or division by zero.
  - Explicit-ID regex bonus (+100.0) applied with parent/child specificity for indexed technique IDs.
  - Ranking contract strictly enforced: score > 0, descending sort, ties broken by ascending technique ID, at most k results, immutable list, exact unmodified evidenceSentence.
  - Created 20 comprehensive unit tests in `TfIdfRetrieverTest` covering unique matches, rare vs common weighting, zero-norm queries/documents, OOV queries, ties by ID, k handling, null/blank inputs, empty corpus, parent/child ID bonus, non-ASCII Unicode, determinism, unmodifiability, defensive copying, null constructor argument, and two paper-derived hand-calculated tests (`handCalculatedToyCorpusCosine` and `sublinearTfQueryWeighting`).
  - Clean compile with `-Xlint:all -Werror` (zero warnings, zero errors).
  - Test suite green: `Tests run: 139, Failures: 0, Errors: 0, Skipped: 1`.
  - Updated `README.md` with Phase 3 formulas, ranking contract, and limitations; updated `ai-docs/Flow.md`, `ai-docs/Decisions.md`, and `tracking/phase-3-tfidf-retriever.md`.
- **In progress**: None. Phase 3 completed.
- **Broken**: None.
- **Avoid**: Never update IDF weights dynamically from query/report sentences.
- **Open questions**: None.

## 2026-11-07 | Gemini 3.8 Flash — Phase 4 Step A: Gold Standard Loader Completed
- **Done**:
  - Implemented `LabelType` enum (`EXPLICIT`, `AMBIGUOUS`, `INFERRED`, `NONE`).
  - Implemented `GoldFormatException` unchecked exception carrying 1-based `lineNumber`.
  - Implemented immutable `GoldRecord` record with defensive copying, trimming, and validation.
  - Implemented `GoldCsvLoader` with RFC 4180 parsing, strict UTF-8 decoding without replacement characters, leading BOM stripping, multi-line quoted record line tracking, flexible header matching, and complete validation.
  - Created 43 unit tests in `GoldCsvLoaderTest` covering all format constraints, error conditions, edge cases, and unmodifiability.
  - Clean compile with `-Xlint:all -Werror` (zero warnings, zero errors).
  - Test suite green: `Tests run: 182, Failures: 0, Errors: 0, Skipped: 1`.
- **In progress**: Phase 4 Step B (RetrievalMetrics).
- **Broken**: None.
- **Avoid**: Never use loose CSV parsing that ignores RFC 4180 quotes or silently replaces invalid UTF-8 bytes.
- **Open questions**: None.

## 2026-11-18 | Gemini 3.8 Flash — Session Handoff to Shambhavi
- **Done**:
  - Full audit of codebase, security, and test suite: green (`Tests run: 182, Failures: 0, Errors: 0, Skipped: 1`).
  - Pushed all completed commits up to `e04a054` to GitHub `origin/main`.
  - Phase 1, Phase 1b, Phase 2, Phase 3, and Phase 4 Step A are completed and committed.
- **In progress**:
  - Phase 4 Step B: `RetrievalMetrics` static functions, metric records (`topK`, `MRR`, detection `P/R/F1` at threshold `t`), and unit tests with paper-calculated cases.
- **Broken**: None.
- **Avoid**:
  - No new external dependencies (CSV parsing and evaluation metrics must be pure Java).
  - No magic numbers outside `Config.java`.
  - Never weaken tests; always follow TDD (tests first, show failing, then implement).
- **Open questions**: None.
