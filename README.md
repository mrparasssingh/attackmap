# Automatic MITRE ATT&CK Technique Extraction from Threat Reports

A university defensive-research system that ingests unstructured cyber threat intelligence (CTI) reports, identifies sentences describing adversary behavior, and maps them to MITRE ATT&CK technique IDs with supporting evidence sentences.

---

## Technical Architecture & Constraints
- **Java Version**: 17
- **Build System**: Apache Maven
- **Test Framework**: JUnit 5 (Jupiter 5.10.2)
- **JSON Engine**: Jackson Databind 2.17.3
- **Root Package**: `com.team.attackmap`
  - `data`: STIX 2.1 JSON parser, dataset loaders
  - `model`: Immutable domain entities (`Technique`, `Prediction`)
  - `retrieval`: Retrieval engines implementing `Retriever`
  - `eval`: Report-level evaluation and metrics
  - `cli`: Command-line interface
  - `util`: Global configuration, pinned versions, reproducible random seeds

---

## Phase 1: MITRE ATT&CK STIX 2.1 Parser

### Behavior & Parsing Rules
1. **Object Filtering**:
   - Only processes objects of type `attack-pattern`.
   - Excludes non-attack-pattern objects (e.g. `malware`, `intrusion-set`, `relationship`).
2. **Revocation & Deprecation**:
   - Skips objects marked with `revoked: true`.
   - Skips objects marked with `x_mitre_deprecated: true`.
   - Filtering occurs **before** duplicate detection, ensuring older revoked revisions sharing an ID with an active technique do not trigger collision errors.
3. **Technique ID Extraction**:
   - Extracts technique IDs (e.g., `T1059`, `T1059.001`) from `external_references` where `source_name == "mitre-attack"`.
4. **Sub-Technique Handling**:
   - Supports a boolean parameter `includeSubTechniques`:
     - `true`: Parses both parent techniques and sub-techniques.
     - `false`: Excludes all sub-techniques (`x_mitre_is_subtechnique: true`), returning only parent techniques.
5. **Tactics Format**:
   - Extracted from `kill_chain_phases` where `kill_chain_name == "mitre-attack"`.
   - Preserved as lowercase kill-chain short names (e.g., `defense-evasion`, `lateral-movement`, `privilege-escalation`, `execution`).
6. **Error Handling & Data Integrity**:
   - Malformed JSON syntax, invalid STIX structures, or duplicate active technique IDs throw `com.team.attackmap.data.StixParseException`.
   - `parseToMap(...)` produces an immutable, keyed map (`Map<String, Technique>`).

### Pinned Framework Version
- **MITRE ATT&CK Enterprise Release**: `v20.0` (pinned in `com.team.attackmap.util.Config.ATTACK_VERSION`).
- **Canonical Dataset File**: `enterprise-attack-20.0.json` (from `mitre-attack/attack-stix-data`).

---

## Build & Test Instructions

### Running Standard Unit Tests
Standard builds and unit tests execute strictly against synthetic fixtures in `src/test/resources/fixtures/`:
```bash
mvn clean test
```
Or quietly:
```bash
mvn -q test
```

### Running the Real-Data Smoke Test
The real-data smoke test is skipped by default to prevent unauthorized network downloads and avoid large binary bloat.
Once `enterprise-attack-20.0.json` has been downloaded manually and verified, execute:
```bash
mvn test -Dattack.stix.path="/path/to/enterprise-attack-20.0.json"
```
The smoke test verifies:
- Pinned bundle version matches `Config.ATTACK_VERSION` (`20.0`).
- Active parent techniques fall within expected bounds: `[180, 400]`.
- Total active techniques (including sub-techniques) fall within expected bounds: `[550, 1200]`.
- At least 95% of techniques contain non-empty lowercase tactics without spaces.
- Logs the local file's SHA-256 hash and file timestamp.

---

## MITRE ATT&CK® Terms of Use & Attribution

This project uses data from the MITRE ATT&CK® knowledge base.

- **MITRE ATT&CK Terms of Use**: [https://attack.mitre.org/resources/terms-of-use/](https://attack.mitre.org/resources/terms-of-use/)

### Attribution
*(Attribution text to be pasted here by user)*
