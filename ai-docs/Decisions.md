# Decisions Log

Append-only, dated log of meaningful architectural and design decisions.

## 2026-10-29 | Gemini 3.8 Flash
- **Decision**: Use `com.fasterxml.jackson.core:jackson-databind:2.17.3` for STIX JSON parsing.
  - **Why**: Jackson is the standard, battle-tested, high-performance streaming and tree-model JSON parser in Java. STIX JSON objects have varying optional fields and custom extensions (`x_mitre_*`), which Jackson's `JsonNode` tree model handles cleanly without fragile tight coupling to incomplete schemas.
  - **Alternatives considered**: Google Gson (less flexible for complex polymorphic STIX trees), org.json (minimalist, poor performance, lacks streaming).
- **Decision**: Use `org.junit.jupiter:junit-jupiter:5.10.2` and `maven-surefire-plugin:3.2.5` for test execution.
  - **Why**: JUnit 5 is explicitly required by project constraints. Version 5.10.2 is verified stable on Maven Central.
- **Decision**: Pinned ATT&CK Enterprise candidate identified: `v20.0` (enterprise-attack-20.0.json).
  - **Why**: Verified from `attack.mitre.org/resources/versions` as the newest official release (October 13, 2026). Awaiting user confirmation before pinning.
- **Decision**: Define dedicated unchecked exception `com.team.attackmap.data.StixParseException`.
  - **Why**: Abstracts Jackson's checked parsing exceptions and STIX structural/duplicate errors into a single coherent domain exception.
- **Decision**: Tactics are stored as lowercase kill-chain short names (e.g. `defense-evasion`).
  - **Why**: Directly matches ATT&CK STIX `phase_name` for the `mitre-attack` kill chain without ambiguous display transformations.
- **Decision**: Directory junction `college-ka-java-ka-project` created.
  - **Why**: The project root folder is held in use by the IDE; creating an NTFS directory junction eliminates spaces for CLI/Maven paths while preserving workspace integrity.
