package com.team.attackmap.eval;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class GoldCsvLoaderTest {

    private static final Set<String> KNOWN_IDS = Set.of(
            "T1059", "T1059.001", "T1059.003", "T1078", "T1082", "T1083"
    );

    @TempDir
    Path tempDir;

    private Path writeCsv(String filename, String content) throws IOException {
        Path p = tempDir.resolve(filename);
        Files.writeString(p, content, StandardCharsets.UTF_8);
        return p;
    }

    private Path writeCsvBytes(String filename, byte[] content) throws IOException {
        Path p = tempDir.resolve(filename);
        Files.write(p, content);
        return p;
    }

    // ---- Happy path tests ----

    @Test
    @DisplayName("Parses valid CSV with multiple rows and returns unmodifiable list")
    void parsesValidCsvMultipleRows() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,The actor ran powershell.,T1059;T1059.001,explicit
                report1,1,They also used valid accounts.,T1078,inferred
                report1,2,No technique here.,,none
                """;
        Path p = writeCsv("valid.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);

        assertEquals(3, records.size());

        GoldRecord r0 = records.get(0);
        assertEquals("report1", r0.reportId());
        assertEquals(0, r0.sentenceId());
        assertEquals("The actor ran powershell.", r0.text());
        assertEquals(Set.of("T1059", "T1059.001"), r0.techniqueIds());
        assertEquals(LabelType.EXPLICIT, r0.labelType());

        GoldRecord r1 = records.get(1);
        assertEquals(Set.of("T1078"), r1.techniqueIds());
        assertEquals(LabelType.INFERRED, r1.labelType());

        GoldRecord r2 = records.get(2);
        assertTrue(r2.techniqueIds().isEmpty());
        assertEquals(LabelType.NONE, r2.labelType());

        assertThrows(UnsupportedOperationException.class, () -> records.add(r0));
    }

    @Test
    @DisplayName("Header-only file returns empty list")
    void headerOnlyFileReturnsEmptyList() throws IOException {
        String csv = "report_id,sentence_id,sentence_text,technique_ids,label_type\n";
        Path p = writeCsv("header_only.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertTrue(records.isEmpty());
    }

    @Test
    @DisplayName("Strips leading UTF-8 BOM")
    void stripsLeadingBom() throws IOException {
        byte[] bom = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        String rest = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Hello world.,T1059,explicit
                """;
        byte[] content = new byte[bom.length + rest.getBytes(StandardCharsets.UTF_8).length];
        System.arraycopy(bom, 0, content, 0, bom.length);
        System.arraycopy(rest.getBytes(StandardCharsets.UTF_8), 0, content, bom.length, rest.getBytes(StandardCharsets.UTF_8).length);
        Path p = writeCsvBytes("bom.csv", content);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals("report1", records.get(0).reportId());
    }

    @Test
    @DisplayName("Supports embedded commas in quoted fields")
    void embeddedCommasInQuotedFields() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,"Actor used powershell, cmd, and more.",T1059,explicit
                """;
        Path p = writeCsv("commas.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals("Actor used powershell, cmd, and more.", records.get(0).text());
    }

    @Test
    @DisplayName("Supports doubled quotes inside quoted fields")
    void doubledQuotesInFields() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,"Actor said ""hello"" to victim.",T1059,explicit
                """;
        Path p = writeCsv("quotes.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals("Actor said \"hello\" to victim.", records.get(0).text());
    }

    @Test
    @DisplayName("Supports newlines inside quoted fields")
    void newlinesInsideQuotedFields() throws IOException {
        // Manually construct to ensure literal newline inside quotes
        String csv = "report_id,sentence_id,sentence_text,technique_ids,label_type\n"
                + "report1,0,\"Line one.\nLine two.\",T1059,explicit\n";
        Path p = writeCsv("newlines.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals("Line one.\nLine two.", records.get(0).text());
    }

    @Test
    @DisplayName("Supports CRLF line endings")
    void supportsCrlfLineEndings() throws IOException {
        String csv = "report_id,sentence_id,sentence_text,technique_ids,label_type\r\n"
                + "report1,0,Hello world.,T1059,explicit\r\n";
        Path p = writeCsv("crlf.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
    }

    @Test
    @DisplayName("All four label types parse correctly")
    void allFourLabelTypes() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Sentence A.,T1059,explicit
                r,1,Sentence B.,T1078,ambiguous
                r,2,Sentence C.,T1082,inferred
                r,3,Sentence D.,,none
                """;
        Path p = writeCsv("labels.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(LabelType.EXPLICIT, records.get(0).labelType());
        assertEquals(LabelType.AMBIGUOUS, records.get(1).labelType());
        assertEquals(LabelType.INFERRED, records.get(2).labelType());
        assertEquals(LabelType.NONE, records.get(3).labelType());
    }

    // ---- Error tests ----

    @Test
    @DisplayName("Throws GoldFormatException on missing header")
    void throwsOnMissingHeader() throws IOException {
        Path p = writeCsv("no_header.csv", "");
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(1, ex.getLineNumber());
    }

    @Test
    @DisplayName("Zero-byte file throws GoldFormatException on line 1")
    void zeroByteFileThrowsGoldFormatException() throws IOException {
        Path p = writeCsv("zero_byte.csv", "");
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(1, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on wrong header columns")
    void throwsOnWrongHeaderColumns() throws IOException {
        String csv = "report_id,sentence_id,text,technique_ids,label_type\n";
        Path p = writeCsv("wrong_header.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(1, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on missing column in data row")
    void throwsOnMissingColumn() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Hello world.,T1059
                """;
        Path p = writeCsv("missing_col.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on bad sentence_id (not a number)")
    void throwsOnBadSentenceIdNaN() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,abc,Hello world.,T1059,explicit
                """;
        Path p = writeCsv("bad_sid.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on negative sentence_id")
    void throwsOnNegativeSentenceId() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,-1,Hello world.,T1059,explicit
                """;
        Path p = writeCsv("neg_sid.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on unknown technique ID (typo like T1059.01)")
    void throwsOnUnknownTechniqueId() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Hello world.,T1059.01,explicit
                """;
        Path p = writeCsv("unknown_id.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on duplicate (report_id, sentence_id)")
    void throwsOnDuplicateReportSentence() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,First sentence.,T1059,explicit
                report1,0,Duplicate sentence.,T1078,inferred
                """;
        Path p = writeCsv("dup.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(3, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on invalid label_type")
    void throwsOnInvalidLabelType() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Hello world.,T1059,unknown_type
                """;
        Path p = writeCsv("bad_label.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on label_type 'none' with technique IDs")
    void throwsOnNoneWithIds() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Hello world.,T1059,none
                """;
        Path p = writeCsv("none_with_ids.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on non-none label_type with empty IDs")
    void throwsOnNonNoneWithoutIds() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Hello world.,,explicit
                """;
        Path p = writeCsv("explicit_no_ids.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on blank sentence text")
    void throwsOnBlankText() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,  ,T1059,explicit
                """;
        Path p = writeCsv("blank_text.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Throws GoldFormatException on unterminated quote")
    void throwsOnUnterminatedQuote() throws IOException {
        String csv = "report_id,sentence_id,sentence_text,technique_ids,label_type\n"
                + "report1,0,\"unterminated text,T1059,explicit\n";
        Path p = writeCsv("unterminated.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertTrue(ex.getLineNumber() >= 2);
    }

    @Test
    @DisplayName("Multiple technique IDs separated by semicolon are parsed into a Set")
    void multipleTechniqueIdsParsedIntoSet() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Complex attack.,T1059;T1078;T1082,explicit
                """;
        Path p = writeCsv("multi_ids.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals(Set.of("T1059", "T1078", "T1082"), records.get(0).techniqueIds());
    }

    @Test
    @DisplayName("Technique IDs set in GoldRecord is unmodifiable")
    void techniqueIdsSetIsUnmodifiable() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Attack.,T1059,explicit
                """;
        Path p = writeCsv("unmod_ids.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertThrows(UnsupportedOperationException.class,
                () -> records.get(0).techniqueIds().add("T9999"));
    }

    @Test
    @DisplayName("Case-insensitive label_type parsing (EXPLICIT, Explicit, explicit all valid)")
    void caseInsensitiveLabelType() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,S0.,T1059,EXPLICIT
                r,1,S1.,T1078,Inferred
                """;
        Path p = writeCsv("case_label.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(LabelType.EXPLICIT, records.get(0).labelType());
        assertEquals(LabelType.INFERRED, records.get(1).labelType());
    }

    @Test
    @DisplayName("Same sentence_id across different reports is allowed")
    void sameSentenceIdDifferentReports() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Sentence A.,T1059,explicit
                report2,0,Sentence B.,T1078,explicit
                """;
        Path p = writeCsv("diff_reports.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(2, records.size());
    }

    // ---- Additional edge-case tests ----

    @Test
    @DisplayName("IDs with spaces around ';' are trimmed")
    void idsWithSpacesAroundSemicolonAreTrimmed() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Attack., T1059 ; T1078 ,explicit
                """;
        Path p = writeCsv("spaces_ids.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals(Set.of("T1059", "T1078"), records.get(0).techniqueIds());
    }

    @Test
    @DisplayName("Trailing ';' produces empty trailing segment which is ignored")
    void trailingSemicolonIgnored() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Attack.,T1059;,explicit
                """;
        Path p = writeCsv("trailing_semi.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals(Set.of("T1059"), records.get(0).techniqueIds());
    }

    @Test
    @DisplayName("Duplicate technique ID within a single row is deduplicated silently")
    void duplicateIdWithinRowDeduplicated() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Attack.,T1059;T1059,explicit
                """;
        Path p = writeCsv("dup_id_row.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals(Set.of("T1059"), records.get(0).techniqueIds());
    }

    @Test
    @DisplayName("Lowercase technique ID 't1059' is rejected as unknown")
    void lowercaseTechniqueIdRejected() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Attack.,t1059,explicit
                """;
        Path p = writeCsv("lower_id.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }

    @Test
    @DisplayName("Label type is trimmed before case-insensitive parsing")
    void labelTypeTrimmedAndCaseInsensitive() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Attack.,T1059, Explicit
                r,1,Attack B.,T1078, INFERRED
                """;
        Path p = writeCsv("trimmed_label.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(LabelType.EXPLICIT, records.get(0).labelType());
        assertEquals(LabelType.INFERRED, records.get(1).labelType());
    }

    @Test
    @DisplayName("Extra columns beyond the required 5 are silently ignored")
    void extraColumnsIgnored() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type,notes,extra
                r,0,Attack.,T1059,explicit,some note,blah
                """;
        Path p = writeCsv("extra_cols.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals("T1059", records.get(0).techniqueIds().iterator().next());
    }

    @Test
    @DisplayName("Header matched by name case-insensitively and in any order")
    void headerMatchedByNameCaseInsensitiveAnyOrder() throws IOException {
        String csv = """
                Label_Type,Technique_Ids,Sentence_Text,Report_Id,Sentence_Id
                explicit,T1059,Attack.,r,0
                """;
        Path p = writeCsv("reordered_header.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals("r", records.get(0).reportId());
        assertEquals(0, records.get(0).sentenceId());
        assertEquals("Attack.", records.get(0).text());
        assertEquals(Set.of("T1059"), records.get(0).techniqueIds());
        assertEquals(LabelType.EXPLICIT, records.get(0).labelType());
    }

    @Test
    @DisplayName("Wrong field count reports the correct line number")
    void wrongFieldCountReportsCorrectLineNumber() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Good row.,T1059,explicit
                r,1,Bad row.,T1078
                """;
        Path p = writeCsv("wrong_count.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(3, ex.getLineNumber());
    }

    @Test
    @DisplayName("Trailing blank lines are ignored")
    void trailingBlankLinesIgnored() throws IOException {
        String csv = "report_id,sentence_id,sentence_text,technique_ids,label_type\n"
                + "r,0,Attack.,T1059,explicit\n"
                + "\n"
                + "\n";
        Path p = writeCsv("trailing_blanks.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
    }

    @Test
    @DisplayName("Line number of a multi-line quoted record = line where it starts")
    void lineNumberOfMultiLineQuotedRecordIsStartLine() throws IOException {
        // Row starts at line 2, then error on line 3 (but reported as line 2 where the record starts)
        String csv = "report_id,sentence_id,sentence_text,technique_ids,label_type\n"
                + "r,0,\"Line one.\nLine two.\",,none\n"
                + "r,0,Duplicate.,T1059,explicit\n";
        Path p = writeCsv("multiline_linenum.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        // The duplicate (r,0) is on physical line 4 but logical record starting at line 4
        assertEquals(4, ex.getLineNumber());
    }

    @Test
    @DisplayName("Invalid UTF-8 bytes throw GoldFormatException (no replacement characters)")
    void invalidUtf8BytesThrowGoldFormatException() throws IOException {
        byte[] header = "report_id,sentence_id,sentence_text,technique_ids,label_type\n"
                .getBytes(StandardCharsets.UTF_8);
        // 0xFE 0xFF are invalid UTF-8 continuation bytes
        byte[] badRow = new byte[]{'r', ',', '0', ',', (byte) 0xFE, (byte) 0xFF, ',', 'T', '1', '0', '5', '9', ',', 'e', 'x', 'p', 'l', 'i', 'c', 'i', 't', '\n'};
        byte[] content = new byte[header.length + badRow.length];
        System.arraycopy(header, 0, content, 0, header.length);
        System.arraycopy(badRow, 0, content, header.length, badRow.length);
        Path p = writeCsvBytes("bad_utf8.csv", content);
        assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
    }

    @Test
    @DisplayName("Missing file throws GoldFormatException on line 1")
    void missingFileThrows() {
        Path missing = tempDir.resolve("nonexistent.csv");
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(missing, KNOWN_IDS));
        assertEquals(1, ex.getLineNumber());
    }

    @Test
    @DisplayName("Returned list is unmodifiable (add and remove throw)")
    void returnedListIsUnmodifiable() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                report1,0,Attack.,T1059,explicit
                """;
        Path p = writeCsv("unmod_list.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertFalse(records.isEmpty());
        GoldRecord r0 = records.get(0);
        assertThrows(UnsupportedOperationException.class, () -> records.add(r0));
        assertThrows(UnsupportedOperationException.class, () -> records.remove(0));
    }

    @Test
    @DisplayName("Null path throws NullPointerException")
    void nullPathThrows() {
        assertThrows(NullPointerException.class,
                () -> GoldCsvLoader.load(null, KNOWN_IDS));
    }

    @Test
    @DisplayName("Null knownTechniqueIds throws NullPointerException")
    void nullKnownIdsThrows() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Attack.,T1059,explicit
                """;
        Path p = writeCsv("null_known.csv", csv);
        assertThrows(NullPointerException.class,
                () -> GoldCsvLoader.load(p, null));
    }

    @Test
    @DisplayName("Non-ASCII text (Unicode) is preserved in sentence_text")
    void nonAsciiTextPreserved() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                r,0,Überwachung der Datenübertragung.,T1059,explicit
                """;
        Path p = writeCsv("unicode.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(1, records.size());
        assertEquals("Überwachung der Datenübertragung.", records.get(0).text());
    }

    @Test
    @DisplayName("Result list is in file order")
    void resultListInFileOrder() throws IOException {
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                z_report,0,Z sentence.,T1059,explicit
                a_report,0,A sentence.,T1078,inferred
                m_report,0,M sentence.,,none
                """;
        Path p = writeCsv("order.csv", csv);
        List<GoldRecord> records = GoldCsvLoader.load(p, KNOWN_IDS);
        assertEquals(3, records.size());
        assertEquals("z_report", records.get(0).reportId());
        assertEquals("a_report", records.get(1).reportId());
        assertEquals("m_report", records.get(2).reportId());
    }

    @Test
    @DisplayName("GoldRecord constructor failure surfaces as GoldFormatException with line number")
    void goldRecordConstructorFailureSurfacesAsGoldFormatException() throws IOException {
        // blank report_id triggers GoldRecord constructor's IllegalArgumentException
        String csv = """
                report_id,sentence_id,sentence_text,technique_ids,label_type
                  ,0,Some text.,T1059,explicit
                """;
        Path p = writeCsv("blank_report_id.csv", csv);
        GoldFormatException ex = assertThrows(GoldFormatException.class,
                () -> GoldCsvLoader.load(p, KNOWN_IDS));
        assertEquals(2, ex.getLineNumber());
    }
}

