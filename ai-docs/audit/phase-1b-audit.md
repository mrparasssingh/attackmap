# Phase 1b Code Audit Report

**Project**: Automatic MITRE ATT&CK Technique Extraction from Threat Reports  
**Auditor**: Independent Code Auditor  
**Audit Date**: 2026-10-31  
**Scope**: Verification of Phase 1b (Sentence Model, PDF Extraction, Sentence Splitting, Report Loader)  
**Operating Mode**: Read-Only Audit  

---

## 1. Audit Verdict

### **VERDICT: NOT IMPLEMENTED**

**Executive Summary**:  
Phase 1b was **never implemented**. The repository contains the completed Phase 1 implementation (STIX 2.1 parser in `StixParser.java`, `Technique.java`, `StixParseException.java`, and `Config.java`), but **zero code, zero dependencies, and zero tests** exist for Phase 1b:
- No `Sentence` model exists.
- No PDF extractor exists (and Apache PDFBox is not declared in `pom.xml`).
- No sentence splitter exists.
- No report loader exists.

Furthermore, project tracking in `ai-docs/working.md` skipped Phase 1b entirely, jumping directly from Phase 1 to Phase 2 (`KeywordRetriever`). While the repository builds and passes its 17 Phase 1 tests cleanly, every requirement specific to Phase 1b is completely unaddressed in the codebase.

---

## 2. Baseline Build & Repository State

### 2.1 Build Execution: `mvn -q test`
- **Exit Code**: `0`
- **Output**: Clean (no warnings or errors).

### 2.2 Build Execution: `mvn test`
```text
[INFO] Scanning for projects...
[INFO] 
[INFO] -------------------------< com.team:attackmap >-------------------------
[INFO] Building Automatic MITRE ATT&CK Technique Extraction 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[INFO] --- resources:3.4.0:resources (default-resources) @ attackmap ---
[INFO] skip non existing resourceDirectory D:\Padh leee...!!!\college ka java ka project\src\main\resources
[INFO] 
[INFO] --- compiler:3.13.0:compile (default-compile) @ attackmap ---
[INFO] Nothing to compile - all classes are up to date.
[INFO] 
[INFO] --- resources:3.4.0:testResources (default-testResources) @ attackmap ---
[INFO] Copying 2 resources from src\test\resources to target\test-classes
[INFO] 
[INFO] --- compiler:3.13.0:testCompile (default-testCompile) @ attackmap ---
[INFO] Nothing to compile - all classes are up to date.
[INFO] 
[INFO] --- surefire:3.2.5:test (default-test) @ attackmap ---
[INFO] Using auto detected provider org.apache.maven.surefire.junitplatform.JUnitPlatformProvider
[INFO] 
[INFO] -------------------------------------------------------
[INFO]  T E S T S
[INFO] -------------------------------------------------------
[INFO] Running com.team.attackmap.data.StixParserTest
[WARNING] Tests run: 17, Failures: 0, Errors: 0, Skipped: 1, Time elapsed: 0.220 s -- in com.team.attackmap.data.StixParserTest
[INFO] 
[INFO] Results:
[INFO] 
[WARNING] Tests run: 17, Failures: 0, Errors: 0, Skipped: 1
[INFO] 
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  1.851 s
[INFO] Finished at: 2026-10-31T00:39:11+05:30
[INFO] ------------------------------------------------------------------------
```

*Note on Skipped Test*: 1 test (`StixParserTest.testRealDataSmokeTest`) is conditionally skipped when `-Dattack.stix.path` is not passed on the CLI, as designed in Phase 1 to prevent mandatory massive file downloads.

### 2.3 Repository Status: `git status`
```text
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   ai-docs/working.md

Untracked files:
  (use "git add <file>..." to include in what will be committed)
	ai-docs/tracking/phase-2-keyword-retriever.md

no changes added to commit (use "git add" and/or "git commit -a")
```

### 2.4 Recent Commit History: `git log --oneline -10`
```text
46da157 docs: record remote github repository in handover
d95f480 docs: finalize phase 1 handover in ai-docs
1802cb0 Phase 1: STIX parser with real-data smoke test
2b8c2b1 docs: mark attribution section as TODO in README
5aaaf85 Phase 1: STIX parser with real-data smoke test
19d921b docs: update ai-docs handover and idle state for phase 1 completion
f46c781 feat(phase-1): implement MITRE ATT&CK STIX parser, models, and JUnit 5 test suite
```

---

## 3. Existence and Wiring Analysis

| Expected Class / Component | File Exists? | Non-Trivial? | Wired & Called? | Dead Code / Placeholder Notes |
| :--- | :---: | :---: | :---: | :--- |
| **Sentence Model** (`Sentence.java`) | **NO** | N/A | **NO** | Missing entirely from `src/main/java/com/team/attackmap/model/`. |
| **PDF Extractor** (`PdfExtractor.java`) | **NO** | N/A | **NO** | Missing entirely; Apache PDFBox missing from `pom.xml`. |
| **Sentence Splitter** (`SentenceSplitter.java`) | **NO** | N/A | **NO** | Missing entirely from `src/main/java/com/team/attackmap/util/` or `data/`. |
| **Report Loader** (`ReportLoader.java` / `ThreatReportParser.java`) | **NO** | N/A | **NO** | Missing entirely; claimed in `Architecture.md:18` but unwritten. |
| **StixParser** (`StixParser.java`) | **YES** | YES (271 lines) | **YES** | Implemented for Phase 1; tested by `StixParserTest`. |
| **Technique** (`Technique.java`) | **YES** | YES (46 lines) | **YES** | Immutable record for Phase 1; tested by `StixParserTest`. |
| **StixParseException** (`StixParseException.java`) | **YES** | YES (29 lines) | **YES** | Runtime exception for Phase 1; tested by `StixParserTest`. |
| **Config** (`Config.java`) | **YES** | YES (53 lines) | **YES** | Static constants for Phase 1; tested by `StixParserTest`. |
| **Prediction** (`Prediction.java`) | **YES** | YES (25 lines) | **NO** | **Dead Code**: Contract record exists, but zero callers in code or tests. |
| **Retriever** (`Retriever.java`) | **YES** | YES (21 lines) | **NO** | **Dead Code**: Interface contract exists, but zero implementations or callers. |

---

## 4. Behavior Checks Table

| Item | Requirement Description | Status | Evidence / Citations |
| :---: | :--- | :---: | :--- |
| **a** | Ordinary sentences ending in `.`, `!`, `?` | **NO TEST / FAIL** | No sentence splitter exists (`src/main/java/com/team/attackmap/`). No tests in `src/test/java/com/team/attackmap/`. |
| **b** | Abbreviations ("e.g.", "i.e.", "U.S.", "Dr.", "vs.", "etc.") | **NO TEST / FAIL** | No sentence splitter exists. No abbreviation handling logic implemented. |
| **c** | ATT&CK IDs with dots (e.g. `T1059.001`) must NOT be split | **NO TEST / FAIL** | No sentence splitter exists. |
| **d** | File names, domains, IPs (`malware.exe`, `evil.example.com`, `192.168.1.10`) must NOT be split | **NO TEST / FAIL** | No sentence splitter exists. |
| **e** | Line breaks inside a sentence (PDF hard wraps) are joined | **NO TEST / FAIL** | No sentence splitter or text normalization exists. |
| **f** | Hyphenated line-break words ("exfil-\ntration") handled or documented as limitation | **NO TEST / FAIL** | No hyphen de-breaking code exists; not documented in `ai-docs/Architecture.md` or `README.md`. |
| **g** | Bullet lists, headings, page numbers, or headers/footers | **NO TEST / FAIL** | No filtering or structural parsing implemented for PDF text. |
| **h** | Very long sentences and empty or whitespace-only input | **NO TEST / FAIL** | No sentence splitter exists. |
| **i** | Non-ASCII text (curly quotes, em-dash, Cyrillic) | **NO TEST / FAIL** | No sentence splitter exists. (Note: `StixParserTest.java:188-213` tests non-ASCII in STIX JSON, but zero tests exist for sentence splitting). |
| **j** | Normal text PDF returns text in reading order | **NO TEST / FAIL** | No PDF extractor exists. No PDFBox dependency in `pom.xml:23-51`. |
| **k** | Empty PDF, image-only PDF, corrupt PDF, encrypted PDF produce clear specific errors or empty results | **NO TEST / FAIL** | No PDF extractor or PDF-specific error handling exists. |
| **l** | Missing file path produces a clear error | **NO TEST / FAIL** | No report loader or PDF extractor exists. (`StixParser.java:140-142` validates STIX path, but not report PDFs). |
| **m** | Resources closed (try-with-resources on PDF document) | **NO TEST / FAIL** | No PDF document loading code exists. |
| **n** | Test PDFs are synthetic; no real 3rd-party report PDF committed | **PASS** | Verified via `git ls-files *.pdf` and workspace scan: 0 PDF files committed to the repository. |
| **o** | Deterministic output for identical input | **NO TEST / FAIL** | Cannot verify determinism because Phase 1b code does not exist. |
| **p** | Sentence indices stable and start at documented base | **NO TEST / FAIL** | No `Sentence` model or index generator exists. |
| **q** | No nulls returned; returned lists unmodifiable or documented | **NO TEST / FAIL** | No sentence splitting or report loading methods exist. |
| **r** | No magic numbers outside `Config`; Javadoc on public methods | **NO TEST / FAIL** | Phase 1b code does not exist. (Phase 1 code adheres, but Phase 1b is absent). |
| **s** | No new dependency added without being listed in pom and Decisions.md | **PASS** | `pom.xml:23-51` lists Jackson 2.17.3, SLF4J 2.0.13, and JUnit 5.10.2, all documented in `ai-docs/Decisions.md:5-10`. No unapproved dependencies were introduced. |

---

## 5. Constraint Check (Step 5)

1. **Phase 1 Files Unchanged**:
   - `git diff HEAD src/` produces zero output. All Phase 1 source files (`StixParser.java`, `StixParseException.java`, `Technique.java`, `Prediction.java`, `Retriever.java`, `Config.java`) and test fixtures are 100% untouched.
2. **Phase 2 Status**:
   - Phase 2 files have not been implemented. Only an untracked tracking document (`ai-docs/tracking/phase-2-keyword-retriever.md`) and unstaged edits in `ai-docs/working.md` exist.
3. **`.gitignore` Coverage**:
   - `target/`: Covered (`.gitignore:1`).
   - `data/`: Covered (`.gitignore:7`).
   - `/enterprise-attack-*.json`: Covered (`.gitignore:8`).
4. **Committed Dataset / STIX Files**:
   - Verified via `git ls-files "*.json"`: Only synthetic test fixtures (`stix-sample.json` [5.8 KB] and `stix-duplicate-active.json` [0.9 KB]) are tracked. No canonical STIX dataset (`enterprise-attack-20.0.json`) or threat report dataset is committed.

---

## 6. Discrepancies and Unsupported Claims in `ai-docs/`

1. **Claim: `ThreatReportParser` exists in `com.team.attackmap.data`**:
   - *Citation*: `ai-docs/Architecture.md:18` depicts `ThreatReportParser (JSON STIX 2.1)` under `com.team.attackmap.data`.
   - *Reality*: No `ThreatReportParser` class or interface exists anywhere in the repository.
2. **Claim: "dataset loader" in `com.team.attackmap.data`**:
   - *Citation*: `ai-docs/Architecture.md:40` states `1. com.team.attackmap.data: STIX 2.1 JSON parser, dataset loader, fixture loaders.`
   - *Reality*: Only `StixParser` exists. There is no dataset loader or threat report loader.
3. **Claim: System ingests threat reports**:
   - *Citation*: `README.md:2-3` and `ai-docs/Architecture.md:6` claim the system reads threat-report text and extracts sentences describing attacker behavior.
   - *Reality*: The system currently only ingests STIX 2.1 JSON attack pattern bundles; no threat report ingestion capability exists.
4. **Premature Phase Leap in `working.md`**:
   - *Citation*: `ai-docs/working.md:4-6` sets the active task to "Phase 2: Implement KeywordRetriever baseline".
   - *Reality*: Phase 2 assumes input sentences extracted from threat reports, but Phase 1b was never scheduled, tracked, or implemented.

---

## 7. Findings Sorted by Severity

### Blocker Severity
1. **Missing Phase 1b Implementation**:
   - **Location**: `src/main/java/com/team/attackmap/`
   - **Finding**: None of the core Phase 1b classes (`Sentence` model, `PdfExtractor`, `SentenceSplitter`, `ReportLoader`) exist.
   - **Suggested Fix**: Implement `com.team.attackmap.model.Sentence`, a PDFBox-based extractor, a rule-based sentence splitter, and a report loader.
2. **Missing PDF Processing Dependency**:
   - **Location**: `pom.xml:23-51`
   - **Finding**: `pom.xml` contains no PDF parsing library dependency (such as `org.apache.pdfbox:pdfbox`).
   - **Suggested Fix**: Add `org.apache.pdfbox:pdfbox:3.0.3` (or verified stable version) to `pom.xml` and document the architectural rationale in `ai-docs/Decisions.md`.
3. **Complete Absence of Phase 1b Tests**:
   - **Location**: `src/test/java/com/team/attackmap/`
   - **Finding**: No test suite exists for sentence splitting or PDF extraction; `StixParserTest.java` is the sole test file in the project.
   - **Suggested Fix**: Author comprehensive JUnit 5 test classes (`SentenceSplitterTest`, `PdfExtractorTest`, `ReportLoaderTest`) with synthetic fixtures covering abbreviations, line wraps, dots in IDs/domains, and corrupted/empty PDFs.

### Major Severity
4. **Architectural Specification Mismatch**:
   - **Location**: `ai-docs/Architecture.md:18, 40`
   - **Finding**: Architecture diagram references `ThreatReportParser` and "dataset loader", which do not exist in code.
   - **Suggested Fix**: Update `Architecture.md` to define the exact classes intended for Phase 1b (`Sentence`, `PdfExtractor`, `SentenceSplitter`, `ReportLoader`).
5. **Phase Skipping in Workflow Continuity**:
   - **Location**: `ai-docs/working.md:4-6` and `ai-docs/tracking/phase-2-keyword-retriever.md:1-12`
   - **Finding**: Active planning moved to Phase 2 (retrieval) without implementing the data ingestion pipeline (Phase 1b) that supplies sentences to the retriever.
   - **Suggested Fix**: Update `ai-docs/working.md` to establish Phase 1b tracking and obtain user approval for Phase 1b implementation before proceeding to Phase 2.
6. **Unused / Dead Domain Contracts**:
   - **Location**: `src/main/java/com/team/attackmap/model/Prediction.java:12-25`, `src/main/java/com/team/attackmap/retrieval/Retriever.java:11-21`
   - **Finding**: `Prediction` and `Retriever` exist as stub contracts with zero callers or implementations.
   - **Suggested Fix**: Keep as target contracts, but add contract verification tests and ensure downstream Phase 1b and Phase 2 components integrate with them.

### Minor Severity
7. **Uncommitted and Untracked Working State**:
   - **Location**: `ai-docs/working.md` and `ai-docs/tracking/phase-2-keyword-retriever.md`
   - **Finding**: Git status shows modified `working.md` and untracked `phase-2-keyword-retriever.md`.
   - **Suggested Fix**: Clean or commit working state tracking files once the project roadmap order is settled.

---

## 8. Manual Verification Recommendations for the User

1. **Verify Project Phase Scope with Team/Instructor**:
   - Check course syllabus or project specification: Was Phase 1b intended as a separate milestone before Phase 2, or was report loading deferred to an end-to-end integration phase?
2. **Verify In-Flight Work in `working.md`**:
   - `working.md` shows another agent began drafting a plan for Phase 2 (`KeywordRetriever`). Determine whether to pause that plan and implement Phase 1b first.
3. **Verify Apache PDFBox Version Compatibility**:
   - When approving dependencies for Phase 1b, evaluate PDFBox 2.x vs 3.x API differences (especially regarding memory management, `Loader.loadPDF`, and thread safety under Java 17).
4. **Decide on Sentence Splitting Strategy**:
   - Evaluate whether rule-based regex splitting or a library (such as Apache OpenNLP or ICU4J) is required to meet edge case requirements (c: ATT&CK IDs with dots, d: IPs/domains, b: abbreviations).

