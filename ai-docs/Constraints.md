# Constraints

This file records hard rules and constraints that must never be violated in this project.

## Technical Constraints
1. **Language & Tooling**: Java 17, Apache Maven, JUnit 5.
2. **Package Root**: `com.team.attackmap`.
3. **Module Packages**:
   - `data` (parsers, dataset loaders, STIX parsing)
   - `model` (domain entities: Technique, Prediction, etc.)
   - `retrieval` (retrieval algorithms implementing `Retriever`)
   - `eval` (metrics, report-level evaluation)
   - `cli` (command line interface)
   - `util` (configuration, constants, text utilities)
4. **Retriever Contract**: All retrievers must implement:
   `interface Retriever { List<Prediction> rank(String sentence, int k); }`
5. **Prediction Contract**: `techniqueId`, `score`, `evidenceSentence`.
6. **ATT&CK Versioning**: Pin exactly one ATT&CK Enterprise version in configuration (e.g. `v15.1`); never change it silently.
7. **Reproducibility**: Fix all random seeds (e.g., `SEED = 42`). Log library and model versions.
8. **Dependencies**: Check current Maven Central versions before adding any dependency. Never guess versions. Always provide rationale to the user before adding a dependency.

## Hard Research & Data Rules
1. **No Data Fabrication**: NEVER invent annotations, labels, dataset contents, or metric results. If data is missing, stop and request it.
2. **Train/Test Integrity**: NEVER let test data influence tuning. Splits are strictly by REPORT, not by sentence. The test set stays untouched until the final evaluation.
3. **No Unsanctioned Operations**: Do not run network downloads, delete files, or change code outside the current phase without explicit asking/approval.
4. **Threat Report Ethics & Copyright**: Do not copy or redistribute report PDFs. Record source and license.
5. **Defensive Research Only**: This is a defensive-research system. Do not write or include attack/exploitation tooling.
6. **Production & Runbooks**: No runtime runbooks until there is an actual production deployment.

