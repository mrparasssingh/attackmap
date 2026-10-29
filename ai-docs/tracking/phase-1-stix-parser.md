# Tracking: Phase 1 - STIX ATT&CK Parser

## Goal
Implement a STIX JSON parser for MITRE ATT&CK Enterprise to extract `Technique` objects with the following rules:
- Extract `attack-pattern` objects only.
- Skip revoked objects (`revoked: true`).
- Skip deprecated objects (`x_mitre_deprecated: true`).
- Extract:
  - `id`: MITRE technique ID from `external_references` with `source_name: "mitre-attack"` (e.g. `T1059`, `T1059.001`).
  - `name`: Technique name.
  - `description`: Technique description (handling null/empty safely).
  - `tactics`: List of tactic names from `kill_chain_phases` where `kill_chain_name: "mitre-attack"`.
  - `isSubTechnique`: Boolean from `x_mitre_is_subtechnique`.
- Provide a configurable flag to include or exclude sub-techniques.
- Test strictly on a small fixture file (`stix-sample.json`), never downloading the full dataset.

## Proposed Files
- `pom.xml`: Project setup with Java 17 release, Jackson 2.17.3, JUnit 5.10.2, SLF4J 2.0.13.
- `src/main/java/com/team/attackmap/model/Technique.java`: Immutable domain record/class.
- `src/main/java/com/team/attackmap/model/Prediction.java`: Core model `(techniqueId, score, evidenceSentence)`.
- `src/main/java/com/team/attackmap/retrieval/Retriever.java`: Interface `List<Prediction> rank(String sentence, int k)`.
- `src/main/java/com/team/attackmap/util/Config.java`: Configuration constants (pinned ATT&CK version `v15.1`, random seed `42`).
- `src/main/java/com/team/attackmap/data/StixParser.java`: Core parser implementation.
- `src/test/resources/fixtures/stix-sample.json`: Diverse fixture representing edge cases.
- `src/test/java/com/team/attackmap/data/StixParserTest.java`: JUnit 5 test suite.
- `README.md`: Phase 1 documentation.

## Status
Awaiting user approval on plan.

