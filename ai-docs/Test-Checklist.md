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


