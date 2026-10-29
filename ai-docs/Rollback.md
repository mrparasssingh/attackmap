# Rollback Plan

## Phase 1: STIX ATT&CK Parsing
- **Initial Baseline Commit**: `git rev-parse HEAD` (empty repository initialization).
- **Files introduced in Phase 1**:
  - `pom.xml`
  - `src/main/java/com/team/attackmap/model/Technique.java`
  - `src/main/java/com/team/attackmap/model/Prediction.java`
  - `src/main/java/com/team/attackmap/retrieval/Retriever.java`
  - `src/main/java/com/team/attackmap/util/Config.java`
  - `src/main/java/com/team/attackmap/data/StixParser.java`
  - `src/test/java/com/team/attackmap/data/StixParserTest.java`
  - `src/test/resources/fixtures/stix-sample.json`
- **Reversion Procedure**:
  - Reset to baseline commit via `git reset --hard <baseline_hash>` or delete generated phase 1 files.
  - Re-verify clean status with `git status`.

