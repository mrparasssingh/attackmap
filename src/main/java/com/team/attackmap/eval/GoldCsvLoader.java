package com.team.attackmap.eval;

import com.team.attackmap.util.Config;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Parses a gold-standard CSV file into an unmodifiable list of {@link GoldRecord}s.
 *
 * <h3>CSV Format</h3>
 * <p>UTF-8 encoding (optional leading BOM stripped). RFC 4180 quoting: fields may be
 * enclosed in double-quotes; doubled quotes ({@code ""}) represent a literal quote;
 * embedded commas and newlines are allowed inside quoted fields.</p>
 *
 * <p>Required header columns (matched case-insensitively, any order; extra columns ignored):
 * {@code report_id, sentence_id, sentence_text, technique_ids, label_type}.</p>
 *
 * <h3>Field Parsing Decisions</h3>
 * <ul>
 *   <li><b>technique_ids</b>: semicolon-separated; each ID is trimmed of whitespace.
 *       A trailing semicolon produces an empty trailing segment which is silently ignored
 *       (e.g. {@code "T1059;"} is equivalent to {@code "T1059"}).
 *       Duplicate IDs within a single row are deduplicated silently into a Set.
 *       IDs are case-sensitive: {@code "t1059"} is rejected as unknown.</li>
 *   <li><b>label_type</b>: parsed case-insensitively after trimming whitespace
 *       (e.g. {@code " Explicit "}, {@code "INFERRED"}, {@code "none"} are all valid).</li>
 *   <li><b>Trailing blank lines</b>: ignored silently.</li>
 *   <li><b>Line numbers</b>: reported as the 1-based physical line where the logical
 *       CSV record starts (relevant for multi-line quoted fields).</li>
 * </ul>
 *
 * <h3>Validation</h3>
 * <p>Throws {@link GoldFormatException} with the 1-based line number for: missing or
 * unrecognized header columns, wrong field count, non-numeric or negative sentence_id,
 * unknown technique ID (not in {@code knownTechniqueIds}), duplicate
 * {@code (report_id, sentence_id)}, invalid label_type, label_type {@code NONE} with
 * non-empty IDs, non-{@code NONE} label with empty IDs, blank sentence text,
 * unterminated quote, or invalid UTF-8 bytes.</p>
 */
public final class GoldCsvLoader {

    private static final String COL_REPORT_ID = "report_id";
    private static final String COL_SENTENCE_ID = "sentence_id";
    private static final String COL_SENTENCE_TEXT = "sentence_text";
    private static final String COL_TECHNIQUE_IDS = "technique_ids";
    private static final String COL_LABEL_TYPE = "label_type";
    private static final String BOM = "\uFEFF";
    private static final String SEMICOLON = ";";
    private static final String ID_DELIMITER_KEY = "\0";

    private GoldCsvLoader() {
        // utility class
    }

    private static final class RawRow {
        private final int startLine;
        private final List<String> fields;

        private RawRow(int startLine, List<String> fields) {
            this.startLine = startLine;
            this.fields = fields;
        }
    }

    /**
     * Loads and validates a gold-standard CSV file.
     *
     * @param path              Path to the CSV file (UTF-8, optional BOM).
     * @param knownTechniqueIds The set of valid technique IDs (used to reject typos).
     * @return An unmodifiable list of validated gold records in file order.
     * @throws GoldFormatException If any structural or semantic error is found.
     * @throws NullPointerException If {@code path} or {@code knownTechniqueIds} is null.
     */
    public static List<GoldRecord> load(Path path, Set<String> knownTechniqueIds) {
        Objects.requireNonNull(path, "path cannot be null");
        Objects.requireNonNull(knownTechniqueIds, "knownTechniqueIds cannot be null");

        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            throw new GoldFormatException("File not found or not a regular file: " + path, Config.ONE);
        }

        byte[] rawBytes;
        try {
            rawBytes = Files.readAllBytes(path);
        } catch (IOException e) {
            throw new GoldFormatException("Failed to read file: " + path, Config.ONE, e);
        }

        String fullContent;
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            CharBuffer buffer = decoder.decode(ByteBuffer.wrap(rawBytes));
            fullContent = buffer.toString();
        } catch (CharacterCodingException e) {
            throw new GoldFormatException("Invalid UTF-8 byte sequence in file: " + path, Config.ONE, e);
        }

        if (fullContent.startsWith(BOM)) {
            fullContent = fullContent.substring(Config.ONE);
        }

        List<RawRow> rawRows = parseCsvRows(fullContent);
        if (rawRows.isEmpty()) {
            throw new GoldFormatException("Missing header row in CSV file", Config.ONE);
        }

        RawRow headerRow = rawRows.get(Config.ZERO);
        List<String> headerFields = headerRow.fields;
        int expectedColumns = headerFields.size();

        int reportIdCol = -1;
        int sentenceIdCol = -1;
        int sentenceTextCol = -1;
        int techniqueIdsCol = -1;
        int labelTypeCol = -1;

        for (int i = Config.ZERO; i < headerFields.size(); i++) {
            String colName = headerFields.get(i).trim().toLowerCase(Locale.ROOT);
            if (COL_REPORT_ID.equals(colName)) {
                reportIdCol = i;
            } else if (COL_SENTENCE_ID.equals(colName)) {
                sentenceIdCol = i;
            } else if (COL_SENTENCE_TEXT.equals(colName)) {
                sentenceTextCol = i;
            } else if (COL_TECHNIQUE_IDS.equals(colName)) {
                techniqueIdsCol = i;
            } else if (COL_LABEL_TYPE.equals(colName)) {
                labelTypeCol = i;
            }
        }

        if (reportIdCol < Config.ZERO || sentenceIdCol < Config.ZERO || sentenceTextCol < Config.ZERO
                || techniqueIdsCol < Config.ZERO || labelTypeCol < Config.ZERO) {
            throw new GoldFormatException("Missing required header columns in CSV header", headerRow.startLine);
        }

        if (rawRows.size() == Config.ONE) {
            return Collections.emptyList();
        }

        List<GoldRecord> resultRecords = new ArrayList<>(rawRows.size() - Config.ONE);
        Set<String> seenReportSentenceIds = new HashSet<>(rawRows.size());

        for (int r = Config.ONE; r < rawRows.size(); r++) {
            RawRow row = rawRows.get(r);
            if (row.fields.size() != expectedColumns) {
                throw new GoldFormatException("Row field count mismatch: expected " + expectedColumns
                        + " but found " + row.fields.size(), row.startLine);
            }

            String sentenceText = row.fields.get(sentenceTextCol);
            if (sentenceText.isBlank()) {
                throw new GoldFormatException("sentence_text cannot be blank", row.startLine);
            }

            String reportId = row.fields.get(reportIdCol).trim();
            String sentenceIdStr = row.fields.get(sentenceIdCol).trim();
            int sentenceId;
            try {
                sentenceId = Integer.parseInt(sentenceIdStr);
            } catch (NumberFormatException e) {
                throw new GoldFormatException("Invalid sentence_id (integer required): " + sentenceIdStr, row.startLine, e);
            }
            if (sentenceId < Config.ZERO) {
                throw new GoldFormatException("sentence_id must be >= 0: " + sentenceId, row.startLine);
            }

            String uniquenessKey = reportId + ID_DELIMITER_KEY + sentenceId;
            if (!seenReportSentenceIds.add(uniquenessKey)) {
                throw new GoldFormatException("Duplicate (report_id, sentence_id): (" + reportId + ", " + sentenceId + ")", row.startLine);
            }

            String rawTechniqueIds = row.fields.get(techniqueIdsCol);
            Set<String> parsedIds = new LinkedHashSet<>();
            if (rawTechniqueIds != null && !rawTechniqueIds.isBlank()) {
                String[] idTokens = rawTechniqueIds.split(SEMICOLON);
                for (String token : idTokens) {
                    String trimmedId = token.trim();
                    if (trimmedId.isEmpty()) {
                        continue;
                    }
                    if (!knownTechniqueIds.contains(trimmedId)) {
                        throw new GoldFormatException("Unknown technique ID: " + trimmedId, row.startLine);
                    }
                    parsedIds.add(trimmedId);
                }
            }

            String labelTypeStr = row.fields.get(labelTypeCol).trim();
            LabelType labelType;
            try {
                labelType = LabelType.valueOf(labelTypeStr.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new GoldFormatException("Invalid label_type: " + labelTypeStr, row.startLine, e);
            }

            if (labelType == LabelType.NONE && !parsedIds.isEmpty()) {
                throw new GoldFormatException("label_type 'none' cannot have associated technique IDs", row.startLine);
            }
            if (labelType != LabelType.NONE && parsedIds.isEmpty()) {
                throw new GoldFormatException("label_type '" + labelTypeStr + "' requires at least one technique ID", row.startLine);
            }

            GoldRecord record;
            try {
                record = new GoldRecord(reportId, sentenceId, sentenceText, parsedIds, labelType);
            } catch (IllegalArgumentException e) {
                throw new GoldFormatException(e.getMessage(), row.startLine, e);
            }
            resultRecords.add(record);
        }

        return Collections.unmodifiableList(resultRecords);
    }

    private static List<RawRow> parseCsvRows(String content) {
        List<RawRow> rows = new ArrayList<>();
        int len = content.length();
        int currentLine = Config.ONE;
        int recordStartLine = Config.ONE;

        List<String> currentFields = new ArrayList<>();
        StringBuilder currentField = new StringBuilder();
        boolean inQuotes = false;
        boolean hasContentInRow = false;

        int i = Config.ZERO;
        while (i < len) {
            char c = content.charAt(i);

            if (inQuotes) {
                if (c == '"') {
                    if (i + Config.ONE < len && content.charAt(i + Config.ONE) == '"') {
                        currentField.append('"');
                        i += Config.ONE;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    currentField.append(c);
                    if (c == '\n') {
                        currentLine += Config.ONE;
                    } else if (c == '\r' && (i + Config.ONE >= len || content.charAt(i + Config.ONE) != '\n')) {
                        currentLine += Config.ONE;
                    }
                }
            } else {
                if (c == '"') {
                    inQuotes = true;
                    hasContentInRow = true;
                } else if (c == ',') {
                    currentFields.add(currentField.toString());
                    currentField.setLength(Config.ZERO);
                    hasContentInRow = true;
                } else if (c == '\r' || c == '\n') {
                    if (c == '\r' && i + Config.ONE < len && content.charAt(i + Config.ONE) == '\n') {
                        i += Config.ONE;
                    }
                    currentFields.add(currentField.toString());
                    currentField.setLength(Config.ZERO);

                    boolean isBlankLine = currentFields.size() == Config.ONE
                            && currentFields.get(Config.ZERO).isBlank()
                            && !hasContentInRow;

                    if (!isBlankLine) {
                        rows.add(new RawRow(recordStartLine, currentFields));
                    }

                    currentFields = new ArrayList<>();
                    hasContentInRow = false;
                    currentLine += Config.ONE;
                    recordStartLine = currentLine;
                } else {
                    currentField.append(c);
                    hasContentInRow = true;
                }
            }
            i += Config.ONE;
        }

        if (inQuotes) {
            throw new GoldFormatException("Unterminated quote in CSV row starting at line " + recordStartLine, recordStartLine);
        }

        if (hasContentInRow || !currentFields.isEmpty() || currentField.length() > Config.ZERO) {
            currentFields.add(currentField.toString());
            boolean isBlankLine = currentFields.size() == Config.ONE
                    && currentFields.get(Config.ZERO).isBlank()
                    && !hasContentInRow;
            if (!isBlankLine) {
                rows.add(new RawRow(recordStartLine, currentFields));
            }
        }

        return rows;
    }
}
