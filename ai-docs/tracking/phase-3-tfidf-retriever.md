# Tracking: Phase 3 - TfIdfRetriever Baseline

## Goal
Implement a Term Frequency-Inverse Document Frequency (TF-IDF) retriever that:
- Fits smoothed IDF weights exclusively on candidate technique documents:
  `idf(t) = ln((1 + N) / (1 + df(t))) + 1`
- Computes sublinear term frequency: `1 + ln(tf)`
- Computes L2-normalized sparse vector dot products for cosine similarity
- Adds explicit-ID regex bonus for mentioned technique IDs (`+100.0`)
- Ranks predictions with `score > 0`, breaking ties by ascending technique ID

## Implemented Files
- `src/main/java/com/team/attackmap/retrieval/TfIdfRetriever.java`: Full TF-IDF engine with smoothed IDF, sublinear TF, sparse vector cosine, explicit-ID bonus, and ranking contract.
- `src/test/java/com/team/attackmap/retrieval/TfIdfRetrieverTest.java`: 20 unit tests covering all required scenarios, zero-norm edge cases, ID bonuses, and two paper-derived hand-calculated tests (`handCalculatedToyCorpusCosine` and `sublinearTfQueryWeighting`).
- `README.md`: Added Phase 3 section with mathematical formulation, ranking contract, and limitations.

## Status
Completed and verified.
- Compilation with `-Xlint:all -Werror`: clean (0 warnings, 0 errors).
- All 139 tests pass cleanly (1 skipped for optional local STIX file).

