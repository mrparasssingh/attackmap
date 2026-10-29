# Architecture

High-level system map for "Automatic MITRE ATT&CK Technique Extraction from Threat Reports".

## System Overview
The system reads threat-report text, detects sentences describing attacker behavior, and predicts the matching MITRE ATT&CK technique ID along with the supporting evidence sentence.

```
+-----------------------------------------------------------------------------------+
|                                Threat Report Text                                 |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------+      +-----------------------+      +--------------------+
|  com.team.attackmap   |      |  com.team.attackmap   |      | com.team.attackmap |
|        .data          | ---> |        .model         | <--- |       .util        |
| - StixParser          |      | - Technique           |      | - Config           |
| - ThreatReportParser  |      | - Prediction          |      |   (pinned ATT&CK   |
|   (JSON STIX 2.1)     |      |                       |      |    version, seeds) |
+-----------------------+      +-----------------------+      +--------------------+
                                          |
                                          v
                               +-----------------------+
                               |  com.team.attackmap   |
                               |      .retrieval       |
                               | - Retriever interface |
                               |   (rank sentence, k)  |
                               +-----------------------+
                                          |
                                          v
                               +-----------------------+
                               |  com.team.attackmap   |
                               |     .eval / .cli      |
                               | - Report-level eval   |
                               | - CLI entry points    |
                               +-----------------------+
```

## Packages
1. `com.team.attackmap.data`: STIX 2.1 JSON parser, dataset loader, fixture loaders.
2. `com.team.attackmap.model`: Core entities (`Technique`, `Prediction`).
3. `com.team.attackmap.retrieval`: Retrieval engines implementing `Retriever`.
4. `com.team.attackmap.eval`: Evaluation harness, report-based splitting, metrics calculation.
5. `com.team.attackmap.cli`: User-facing commands and workflow triggers.
6. `com.team.attackmap.util`: App configuration (`Config`), fixed random seeds, logging helpers.

## Phase 1 Scope
Parse MITRE ATT&CK STIX JSON (`attack-pattern` objects only). Skip revoked and deprecated entries. Produce `Technique(id, name, description, tactics, isSubTechnique)`. Provide a flag to include or exclude sub-techniques. Test strictly on a small fixture file without full dataset download.

