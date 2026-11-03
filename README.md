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

## Phase 2: KeywordRetriever Baseline

A keyword- and regular-expression-based retriever baseline implementing `Retriever`. It constructs an in-memory index of tokenized technique names and descriptions during initialization, scoring input sentences against indexed techniques.

### Tokenization
- Text is converted to lowercase using `Locale.ROOT`.
- Tokens are split on any character that is not a Unicode letter or digit (`[^\p{L}\p{N}]+`).
- Tokens shorter than 2 characters and stopwords from `src/main/resources/stopwords.txt` are discarded.
- Security-relevant words (`run`, `execute`, `remote`, `file`, `access`, `use`, etc.) are explicitly excluded from the stopwords list to preserve domain indicators.
- *Future Improvement*: Stemming (e.g. Porter or Snowball stemmer) is not implemented in this phase and is planned as a future enhancement.

### Scoring Formula
Let $Q$ be the set of unique query tokens (each word counted once). For each indexed technique $t$:

$$\text{score}(t) = \sum_{q \in Q} \Bigl( \mathbf{1}_{q \in \text{NameTokens}(t)} \cdot W_{\text{name}} + \mathbf{1}_{q \in \text{DescTokens}(t)} \cdot W_{\text{desc}} \Bigr) + \mathbf{1}_{\text{sentence contains } t.\text{id}()} \cdot B_{\text{id}}$$

- $W_{\text{name}} = 3.0$ (`Config.NAME_WEIGHT`)
- $W_{\text{desc}} = 1.0$ (`Config.DESC_WEIGHT`)
- $B_{\text{id}} = 100.0$ (`Config.ID_MATCH_BONUS`)
- If a query token is present in both name and description, both weights contribute ($3.0 + 1.0 = 4.0$).
- Explicit ID bonus uses case-sensitive regex `\bT\d{4}(\.\d{3})?\b`. An explicit mention of sub-technique `T1059.001` boosts only `T1059.001` (not `T1059`). An explicit mention of `T1059` boosts only `T1059` (not sub-techniques). IDs not present in the indexed list are safely ignored.

### Ranking Contract
1. Only techniques with $\text{score} > 0.0$ are returned; zero-score techniques are omitted because they represent no evidence.
2. Returned list is sorted in descending score order. Ties are broken deterministically by ascending technique ID (`String.compareTo`).
3. Binary-friendly floating-point weights ensure accumulated scores behave like exact integers, allowing exact score comparisons via `Double.compare`.
4. Returns at most $k$ predictions.
5. Returns an empty unmodifiable list if sentence is null or blank, if $k \le 0$, or if the technique index is empty.
6. The returned list is immutable (`Collections.unmodifiableList`).
7. Each `Prediction` contains `(techniqueId, score, evidenceSentence)` where `evidenceSentence` is the unmodified input string.

### Known Limitations
1. **Exact-Match Sensitivity (No Stemming/Lemmatization)**: Variations such as "executes", "executing", or "execution" are treated as distinct words unless explicitly listed in the description or name.
2. **Lack of Semantic Understanding (Vocabulary Mismatch)**: Synonyms and paraphrased attacker activities (e.g. "dumped LSASS memory" vs. "OS Credential Dumping") cannot match unless overlapping keyword tokens exist.
3. **No Term Frequency Inverted Document Frequency (TF-IDF)**: Common non-stopword words across many techniques (e.g., "system", "information") have the same weight as highly discriminative words (e.g., "powershell").

---

## Data provenance

- Source: mitre-attack/attack-stix-data, enterprise-attack/enterprise-attack-20.0.json
- Downloaded: 2026-10-30
- SHA-256: 81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352 (verified independently with PowerShell Get-FileHash)
- Parsed (active, non-revoked, non-deprecated): 227 parent techniques, 706 total including sub-techniques
- The real file is NOT committed. Download it yourself and run:
  mvn test "-Dattack.stix.path=<path to enterprise-attack-20.0.json>"
- Without the property, the real-data smoke test is skipped (Skipped: 1); with it, expect Tests run: 17, Failures: 0, Skipped: 0.

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

This project uses data from the MITRE ATT&CK® knowledge base
(ATT&CK version: 20.0, downloaded: 31 October 2026).

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or cover full categories of techniques will not guarantee full defensive coverage as there may be undisclosed techniques or variations on existing techniques not documented by ATT&CK.

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

See our FAQ for more information on how to use and represent the ATT&CK name.

ATT&CK® Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

