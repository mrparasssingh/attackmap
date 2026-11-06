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
