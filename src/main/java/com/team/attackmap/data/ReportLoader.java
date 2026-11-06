package com.team.attackmap.data;

import com.team.attackmap.model.Sentence;
import com.team.attackmap.util.Config;
import com.team.attackmap.util.SentenceSplitter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Loads threat intelligence reports (.pdf or .txt) and segments them into ordered Sentence records.
 */
public final class ReportLoader {

    private static final String PDF_EXTENSION = ".pdf";
    private static final String TXT_EXTENSION = ".txt";

    private ReportLoader() {
        // Utility class; prevent instantiation
    }

    /**
     * Loads a report file (.pdf or .txt), extracts sentences via {@link SentenceSplitter},
     * and assigns sequential 0-based indices. Strips a leading UTF-8 byte order mark (\uFEFF)
     * if present in text reports.
     * <p>
     * Note on missing files: A missing .txt report throws {@link IllegalArgumentException},
     * while a missing .pdf report throws {@link PdfExtractionException}.
     *
     * @param path File system path to the report document.
     * @return Unmodifiable ordered list of extracted Sentence records.
     * @throws IllegalArgumentException If path is null, missing (for .txt), is a directory, or has an unsupported extension.
     * @throws PdfExtractionException   If path is missing (for .pdf), or if PDF reading, parsing, or password validation fails.
     */
    public static List<Sentence> load(Path path) {
        if (path == null) {
            throw new IllegalArgumentException("Report file path cannot be null");
        }

        Path fileNamePath = path.getFileName();
        if (fileNamePath == null) {
            throw new IllegalArgumentException("Invalid report file path: " + path);
        }

        String fileName = fileNamePath.toString();
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex < Config.ZERO) {
            throw new IllegalArgumentException("File does not contain an extension: " + fileName);
        }

        String extension = fileName.substring(lastDotIndex).toLowerCase(Locale.ROOT);
        String reportId = fileName.substring(Config.ZERO, lastDotIndex);

        String rawText;
        if (PDF_EXTENSION.equals(extension)) {
            rawText = PdfExtractor.extractText(path);
        } else if (TXT_EXTENSION.equals(extension)) {
            if (!Files.exists(path)) {
                throw new IllegalArgumentException("Text report file does not exist: " + path);
            }
            if (Files.isDirectory(path)) {
                throw new IllegalArgumentException("Expected text report file but path is a directory: " + path);
            }
            try {
                rawText = Files.readString(path, StandardCharsets.UTF_8);
                if (rawText.startsWith("\uFEFF")) {
                    rawText = rawText.substring(Config.ONE);
                }
            } catch (IOException e) {
                throw new IllegalArgumentException("Failed to read text report: " + path, e);
            }
        } else {
            throw new IllegalArgumentException("Unsupported report file format: " + extension + " (expected .pdf or .txt)");
        }

        List<String> rawSentences = SentenceSplitter.split(rawText);
        if (rawSentences.isEmpty()) {
            return Collections.emptyList();
        }

        List<Sentence> sentences = new ArrayList<>(rawSentences.size());
        for (int idx = Config.ZERO; idx < rawSentences.size(); idx++) {
            sentences.add(new Sentence(reportId, idx, rawSentences.get(idx)));
        }

        return Collections.unmodifiableList(sentences);
    }
}
