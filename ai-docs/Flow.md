# Execution Flow

## Phase 1: STIX ATT&CK Parsing Flow

```
STIX JSON Input (File / InputStream / Reader)
     |
     v
StixParser.parse(InputStream in, StixParserOptions options)
     |
     |--> Jackson ObjectMapper parses JSON tree (objects array)
     |
     |--> Filter: object.type == "attack-pattern"
     |       |
     |       |--> Check "revoked" is true? If so, SKIP
     |       |--> Check "x_mitre_deprecated" is true? If so, SKIP
     |
     |--> Extract external_references with source_name == "mitre-attack"
     |       |--> external_id is technique ID (e.g. "T1059", "T1059.001")
     |       |--> (If absent, skip or handle invalid object)
     |
     |--> Extract x_mitre_is_subtechnique (boolean flag)
     |       |--> If !options.includeSubTechniques() && isSubTechnique -> SKIP
     |
     |--> Extract name, description
     |--> Extract tactics from kill_chain_phases (where kill_chain_name == "mitre-attack", phase_name)
     |
     v
Technique(id, name, description, tactics, isSubTechnique)
     |
     v
List<Technique> / Map<String, Technique>
```



## Phase 1b: Report Ingestion & Sentence Splitting Flow

```
Report File (.pdf or .txt)
     |
     v
ReportLoader.load(Path path)
     |
     |--> Extract file extension (.pdf or .txt) & reportId (filename without extension)
     |--> If unsupported extension -> throw IllegalArgumentException
     |
     |--> If .pdf:
     |       |--> PdfExtractor.extractText(path)
     |       |       |--> Pre-checks: null, exists, isDirectory -> throw PdfExtractionException
     |       |       |--> try (PDDocument doc = Loader.loadPDF(path.toFile()))
     |       |       |       |--> If encrypted (real password / isEncrypted) -> throw PdfExtractionException
     |       |       |       |--> PDFTextStripper.getText(doc)
     |       |       |       |--> If empty -> log WARN and return ""
     |
     |--> If .txt:
     |       |--> Files.readString(path, StandardCharsets.UTF_8)
     |
     v
Raw Report Text (String)
     |
     v
SentenceSplitter.split(String text)
     |
     |--> Normalize line endings (\r\n -> \n)
     |
     |--> Drop page lines (regex: standalone digits or "Page N [of M]")
     |
     |--> Join hyphenated line breaks ("word-\nrest" -> "wordrest" if rest starts lowercase)
     |
     |--> Group into blocks (separate on list prefixes "- ", "* ", "• ", "\d+[.)] " or blank lines)
     |       |--> Join hard-wrapped lines within blocks
     |       |--> Collapse redundant horizontal whitespace into single spaces
     |
     |--> For each block, scan terminal punctuation ('.', '!', '?')
     |       |--> Attach trailing closing quotes or brackets (e.g. '."', '!]')
     |       |--> Check lookahead: whitespace + [A-Z0-9"'([...]
     |       |--> If period:
     |       |       |--> Is abbreviation from abbreviations.txt? -> DO NOT SPLIT
     |       |       |--> Is numbered list prefix (e.g. "1.") at sentence start? -> DO NOT SPLIT
     |       |--> Split sentence and trim
     |
     v
Unmodifiable List<String> of clean sentences
     |
     v
Sentence(reportId, index, text)
```

## Phase 3: TfIdfRetriever Flow

```
1. Index Construction:
List<Technique>
     |
     v
TfIdfRetriever(List<Technique> techniques)
     |
     |--> Defensive copy: List.copyOf(techniques)
     |--> For each technique:
     |       |--> docText = tech.name() + " " + tech.description()
     |       |--> tokens = TextTokenizer.tokenize(docText)
     |       |--> Compute term frequencies tf(t, d)
     |       |--> Update document frequencies df(t)
     |
     |--> Fit smoothed IDF on technique vocabulary:
     |       idf(t) = ln((1 + N) / (1 + df(t))) + 1
     |
     |--> For each technique document:
     |       |--> Unnormalized weight w(t, d) = (1 + ln(tf(t, d))) * idf(t)
     |       |--> Euclidean norm ||v_d||_2 = sqrt(sum_t w(t, d)^2)
     |       |--> Normalized vector v_hat_d(t) = w(t, d) / ||v_d||_2
     |
     v
Immutable IndexedTechnique list & idfMap

2. Query Execution:
Threat sentence + k
     |
     v
TfIdfRetriever.rank(String sentence, int k)
     |
     |--> Guard check: null/blank sentence, k <= 0, or empty index -> return Collections.emptyList()
     |
     |--> Tokenize sentence via TextTokenizer; filter to vocabulary terms:
     |       |--> Compute query tf(t, q) for t in vocabulary
     |       |--> Unnormalized query weight w(t, q) = (1 + ln(tf(t, q))) * idf(t)
     |       |--> Euclidean norm ||v_q||_2 = sqrt(sum_t w(t, q)^2)
     |       |--> Normalized query vector q_hat(t) = w(t, q) / ||v_q||_2
     |
     |--> Extract explicit technique IDs matching \bT\d{4}(?:\.\d{3})?\b
     |
     |--> For each IndexedTechnique:
     |       |--> If ||v_q||_2 > 0 and ||v_d||_2 > 0:
     |       |       cosine = sum_{t in q_hat} q_hat(t) * d_hat(t)
     |       |    else:
     |       |       cosine = 0.0
     |       |--> score = cosine + (ID_MATCH_BONUS if explicit ID matches else 0.0)
     |       |--> If score > 0.0 -> add to candidate predictions
     |
     |--> Sort descending by score, ascending by techniqueId on ties
     |--> Truncate to at most k entries
     |
     v
Unmodifiable List<Prediction(techniqueId, score, evidenceSentence)>
```
