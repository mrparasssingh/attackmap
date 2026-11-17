# Test Checklist

Concrete commands to run and expected output before any change counts as done.

## Phase 1 Checks

1. **Clean Test Execution**:
   - Command: `mvn -q test`
   - Expected Output: Exit code 0, 0 failures, 0 errors.

2. **Parser Coverage Checks (JUnit 5)**:
   - `StixParserTest`:
     - Parses standard `attack-pattern` objects into `Technique`.
     - Extracts MITRE ID (`T1059`, `T1059.001`), name, description, tactics from `kill_chain_phases`.
     - Skips objects where `type != "attack-pattern"`.
     - Skips objects marked `revoked: true`.
     - Skips objects marked `x_mitre_deprecated: true`.
     - Includes sub-techniques when `includeSubTechniques = true`.
     - Excludes sub-techniques when `includeSubTechniques = false`.
     - Edge Cases:
       - Empty JSON / empty bundle objects list (`[]`).
       - Malformed JSON handling (throws descriptive parsing exception).
       - Attack pattern missing description or tactics (graceful defaults: empty list / empty string, never null pointer crash).
       - Non-ASCII / Unicode characters in description and names (e.g. smart quotes, em-dashes, accented characters).
       - Objects with unknown external references or missing `mitre-attack` source (skipped safely).

3. **Compiler & Warnings Check**:
   - Command: `mvn clean test-compile`
   - Expected: Compiles cleanly with no warnings or errors.

## Phase 2 Checks

1. **Clean Test Execution**:
   - Command: `mvn -q test`
   - Expected Output: Exit code 0, 0 failures, 0 errors.

2. **Tokenizer Coverage Checks (JUnit 5)**:
   - `TextTokenizerTest`:
     - Splits on non-alphanumeric punctuation and Unicode delimiters.
     - Drops single-character tokens (< 2 characters).
     - Retains numeric digit tokens >= 2 characters.
     - Filters stopwords from `stopwords.txt`.
     - Preserves security-critical vocabulary (`run`, `execute`, `remote`, `file`, `access`, `use`).
     - Safely parses Unicode (Cyrillic, smart quotes, em-dashes).
     - Fails clearly if stopwords file is missing (`IllegalStateException`).

3. **Keyword Retriever Coverage Checks (JUnit 5)**:
   - `KeywordRetrieverTest`:
     - Exact technique name match ranks first.
     - Technique name matches outrank description matches (3.0 vs 1.0).
     - No overlapping tokens returns an empty list.
     - Repeated query tokens are deduplicated and do not inflate score.
     - Ties broken deterministically by ascending technique ID.
     - Truncation by parameter k works properly for all bounds (k <= 0, k < matches, k > matches).
     - Null or blank sentences return empty lists.
     - Empty technique list returns empty lists.
     - Explicit ID bonus triggers for matching IDs, but lowercase IDs do not.
     - Explicit sub-technique IDs bonus only the sub-technique, not the parent, and vice-versa.
     - Hand-calculated scoring test matches manual arithmetic exactly.
     - Returned prediction list is unmodifiable and defensively copied.



## Phase 1b Checks (Report Ingestion)

1. **Clean Test Execution**:
   - Command: `mvn -q test`
   - Expected Output: Exit code 0, 0 failures, 0 errors (`Tests run: 119, Failures: 0, Errors: 0, Skipped: 1`).

2. **Sentence Model & Splitter Checks (JUnit 5)**:
   - `SentenceTest`:
     - Trims reportId and text.
     - Validates non-null, non-blank strings and index >= 0.
     - Record equality, hashCode, and property accessors verified.
   - `SentenceSplitterTest`:
     - Normalization drops standalone page number lines and `Page N [of M]` patterns.
     - Joins hyphenated line breaks when continuation begins lowercase.
     - Retains hyphen and space when continuation begins uppercase.
     - Joins hard-wrapped lines and collapses multiple whitespace characters.
     - Treats bullet lines (`-`, `*`, `•`) and numbered list items as distinct sentence boundaries.
     - Terminal punctuation splitting (`.`, `!`, `?`) followed by whitespace and uppercase letter, digit, quotation mark, or bracket.
     - Guards against false splits in technical entities (`T1059.001`, `malware.exe`, `evil.example.com`, `evil[.]example[.]com`, `192.168.1.10`, `v2.1.3`, `3.5`, URLs, paths).
     - Suppresses splitting on registered abbreviations; digit-requiring abbreviations (`no.`, `fig.`, `st.`) suppress splits only when followed by digits.
     - Full Unicode / non-ASCII support and verified determinism.

3. **PDF Extractor & Report Loader Checks (JUnit 5)**:
   - `PdfExtractorTest`:
     - Try-with-resources resource management verified (PDF file deletable immediately on Windows).
     - Throws `PdfExtractionException` for null path, missing file, directory path, corrupt file, and user-password-protected PDF.
     - Extracts text from PDFs protected solely by owner password with empty user password.
     - Returns empty string and logs warning for blank PDFs.
     - Preserves multi-page text extraction order.
   - `ReportLoaderTest`:
     - Dispatches `.pdf` to `PdfExtractor` and `.txt` to UTF-8 reader.
     - Strips leading UTF-8 BOM (`\uFEFF`) from text files.
     - Throws `IllegalArgumentException` for unsupported file extensions.
     - Derives `reportId` from file name without extension.
     - Assigns sequential 0-based indices `0..n-1`.
     - Returns unmodifiable sentence list.

## Phase 3 Checks (TfIdfRetriever)

1. **Clean Test Execution**:
   - Command: `mvn -q test`
   - Expected Output: Exit code 0, 0 failures, 0 errors (`Tests run: 139, Failures: 0, Errors: 0, Skipped: 1`).

2. **TF-IDF Retriever Coverage Checks (JUnit 5)**:
   - `TfIdfRetrieverTest`:
     - Unique-term match ranks matching technique first.
     - Rare term outweighs common term across candidate corpus.
     - Zero-norm query produces empty prediction list without NaN or division by zero.
     - Out-of-vocabulary-only query returns empty prediction list.
     - Ties in score are broken by ascending technique ID.
     - Parameter k bounds handling (k = 1, k = 3, k = 100, k = 0, k = -1).
     - Null or blank sentences return empty unmodifiable list.
     - Empty candidate technique list allowed without error.
     - Explicit ID regex bonus (+100.0) applied with parent/child specificity; lowercase IDs and unknown IDs do not bonus.
     - Non-ASCII / Unicode characters handled cleanly.
     - Determinism verified across repeated invocations.
     - Result list is unmodifiable.
     - Constructor defensively copies candidate technique list.
     - Null constructor argument throws `NullPointerException`.
     - Zero-norm candidate document scores 0.0 and is excluded from predictions.
     - `evidenceSentence` strictly equals the original input string.
     - Sentence with only valid technique ID returns that technique via ID bonus.
     - Sublinear TF query weighting test (`alpha alpha beta`) confirms `1 + ln(2)` weighting vs `2.0` within `1e-9`.
     - Stopwords-only query returns empty list.
     - Paper-derived hand-calculated test on 3-document corpus confirms cosine similarities within `1e-9`.

3. **Compiler & Warnings Check**:
   - Command: `mvn clean test-compile -DcompilerArgument="-Xlint:all -Werror"`
   - Expected: Clean compilation with 0 warnings and 0 errors.
