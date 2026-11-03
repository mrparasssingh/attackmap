# Tracking: Phase 2 - KeywordRetriever Baseline

## Goal
Implement a keyword and regex-based baseline retriever that:
- Tokenizes sentences and technique names/descriptions
- Scores techniques by keyword overlap with configurable weights
- Adds an explicit-ID regex bonus for technique IDs found in the sentence
- Returns ranked predictions with score > 0, ties broken by ascending technique ID

## Implemented Files
- `src/main/resources/stopwords.txt`: English stopword list, omitting security domain terms.
- `src/main/java/com/team/attackmap/util/TextTokenizer.java`: Tokenizer handling lowercase, Unicode non-alphanumeric splitting, length filtering, stopword exclusion.
- `src/main/java/com/team/attackmap/util/Config.java`: Added `NAME_WEIGHT = 3.0`, `DESC_WEIGHT = 1.0`, `ID_MATCH_BONUS = 100.0`.
- `src/main/java/com/team/attackmap/retrieval/KeywordRetriever.java`: Immutable baseline retriever implementing `Retriever`.
- `src/test/java/com/team/attackmap/util/TextTokenizerTest.java`: 9 unit tests for tokenizer behavior.
- `src/test/java/com/team/attackmap/retrieval/KeywordRetrieverTest.java`: 23 unit tests covering all required cases.
- `README.md`: Added Phase 2 documentation section with scoring formula, ranking contract, and known limitations.

## Status
Completed and verified. Tests pass with 0 failures, 0 errors.
