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

## 2026-11-01 | Gemini 3.8 Flash
- **Decision**: Filter out zero-score techniques in `KeywordRetriever.rank(sentence, k)` (return only techniques with score > 0).

  - **Why**: Zero-score techniques share no keyword overlap or explicit ID references with the input sentence and do not constitute evidence. Omitting them eliminates noise, keeps predictions focused on actionable findings, and maintains an honest representation of model retrieval confidence.
  - **Alternatives considered**: Padding the top-k list with arbitrary zero-score techniques (rejected: misleading to analysts and harms downstream evaluation precision).
- **Decision**: Use an explicit ID bonus `ID_MATCH_BONUS = 100.0` with case-sensitive regex `\bT\d{4}(\.\d{3})?\b`.
  - **Why**: When a CTI author explicitly writes a technique ID in the threat sentence (e.g. "T1059.001"), this is an unambiguous, high-confidence signal that should dominate general keyword overlap. Setting the bonus to 100.0 guarantees that the referenced technique outranks purely incidental keyword matches while preserving deterministic tie-breaking. Sub-technique IDs match specifically to the sub-technique and do not boost parent techniques, preventing cross-level pollution.
  - **Alternatives considered**: Case-insensitive matching (rejected: causes false positives on words starting with t like "t1000" or arbitrary tokens), fuzzy ID matching (rejected: fragile and unverified).
- **Decision**: Use binary-friendly floating-point constants (`NAME_WEIGHT = 3.0`, `DESC_WEIGHT = 1.0`, `ID_MATCH_BONUS = 100.0`) and `Double.compare` for sorting.
  - **Why**: Standard IEEE-754 representation represents exact integers losslessly, avoiding subtle precision drift in keyword scoring and ensuring deterministic tie detection across JVM platforms.
  - **Alternatives considered**: Integer scores (rejected: future retrievers like TF-IDF or dense embeddings will need floating-point similarity scores in `Prediction.score`).
- **Decision**: Implement `TextTokenizer` as a separate reusable utility class in `com.team.attackmap.util`.
  - **Why**: Clean separation of concerns; enables independent testing of token normalization, punctuation handling, and stopword loading without coupling directly to retriever indexing state.
  - **Alternatives considered**: Inlining tokenization logic into `KeywordRetriever` (rejected: duplicates code when subsequent retrievers or evaluators tokenize text).



## 2026-11-06 | Gemini 3.8 Flash
- **Decision**: Use `org.apache.pdfbox:pdfbox:3.0.8` for PDF text extraction.
  - **Why**: Apache PDFBox is the standard, production-grade open-source Java library for PDF manipulation. Version 3.0.8 is the latest stable 3.x release on Maven Central, using `Loader.loadPDF` for secure and modernized resource loading.
  - **Allowed transitive dependencies**: `org.apache.pdfbox:pdfbox-io:3.0.8`, `org.apache.pdfbox:fontbox:3.0.8`, `commons-logging:commons-logging:1.3.5`.
  - **Alternatives considered**: Apache Tika (too heavyweight, pulls unwanted dependencies), PDFBox 2.x (legacy branch, requires older `PDDocument.load` APIs).
