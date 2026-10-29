# Handover History

Durable, dated history of finished sessions.

## 2026-10-29 | Gemini 3.8 Flash — Phase 1: ATT&CK STIX Parser Complete
- **Done**:
  - Implemented `StixParser` supporting STIX 2.1 JSON parsing with Jackson Databind 2.17.3.
  - Implemented immutable `Technique(id, name, description, tactics, isSubTechnique)` record with defensive copying.
  - Tactics preserved as lowercase kill-chain short names (e.g. `defense-evasion`).
  - Revoked (`revoked: true`) and deprecated (`x_mitre_deprecated: true`) techniques filtered out prior to duplicate detection.
  - Sub-technique inclusion/exclusion toggle verified (`includeSubTechniques`).
  - Implemented `StixParseException` as the dedicated exception for malformed JSON, unreadable streams, and duplicate active technique IDs.
  - Created domain contracts `Prediction` and `Retriever`.
  - Added comprehensive JUnit 5 test suite (`StixParserTest`) with synthetic fixtures (`stix-sample.json`, `stix-duplicate-active.json`).
  - Added skippable real-data smoke test with range bounds (`[180, 400]` parents, `[550, 1200]` total), SHA-256 calculation, and bundle version validation against `Config.ATTACK_VERSION`.
  - Configured `pom.xml` with Java 17 release, Jackson 2.17.3, SLF4J 2.0.13, JUnit 5.10.2, Surefire 3.2.5 with zero compiler warnings.
  - Added `README.md` with Phase 1 documentation, build instructions, and ATT&CK Terms of Use link.
  - Verified `mvn -q test` and `mvn clean test` (16 passing tests, 1 skipped smoke test, 0 failures, 0 errors).
- **In progress**: Phase 1 complete. Awaiting user direction on Phase 2.
- **Broken**: None.
- **Avoid**: Do not auto-download full datasets over network. Never fabricate metrics or labels.
- **Open questions**: Attribution text to be pasted into README by user.
