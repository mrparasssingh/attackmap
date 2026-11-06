package com.team.attackmap.data;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.text.PDFTextStripper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Extracts plain text from PDF documents using Apache PDFBox 3.x.
 */
public final class PdfExtractor {

    private static final Logger logger = LoggerFactory.getLogger(PdfExtractor.class);

    private PdfExtractor() {
        // Utility class; prevent instantiation
    }

    /**
     * Extracts plain text from a PDF document at the specified path using try-with-resources.
     *
     * @param path File system path to the PDF document.
     * @return Extracted plain text string, or empty string if document contains no text.
     * @throws PdfExtractionException If the path is null, missing, a directory, corrupt, or password-protected.
     */
    public static String extractText(Path path) {
        if (path == null) {
            throw new PdfExtractionException("PDF file path cannot be null");
        }
        if (!Files.exists(path)) {
            throw new PdfExtractionException("PDF file does not exist: " + path);
        }
        if (Files.isDirectory(path)) {
            throw new PdfExtractionException("Expected PDF file but path is a directory: " + path);
        }

        try (PDDocument document = Loader.loadPDF(path.toFile())) {
            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(document);

            if (text == null || text.isBlank()) {
                logger.warn("PDF document contains no extractable text: {}", path);
                return "";
            }

            return text;
        } catch (InvalidPasswordException e) {
            throw new PdfExtractionException("PDF is password-protected: " + path, e);
        } catch (PdfExtractionException e) {
            throw e;
        } catch (IOException e) {
            throw new PdfExtractionException("Failed to load or parse PDF document: " + path, e);
        }
    }
}

