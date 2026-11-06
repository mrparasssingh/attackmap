package com.team.attackmap.data;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("PdfExtractor Contract and Resilience Tests")
class PdfExtractorTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Null path throws PdfExtractionException")
    void nullPathThrows() {
        assertThrows(PdfExtractionException.class, () -> PdfExtractor.extractText(null));
    }

    @Test
    @DisplayName("Missing file throws PdfExtractionException")
    void missingFileThrows() {
        Path missing = tempDir.resolve("non_existent_report.pdf");
        assertThrows(PdfExtractionException.class, () -> PdfExtractor.extractText(missing));
    }

    @Test
    @DisplayName("Directory path throws PdfExtractionException")
    void directoryPathThrows() {
        assertThrows(PdfExtractionException.class, () -> PdfExtractor.extractText(tempDir));
    }

    @Test
    @DisplayName("Corrupt file throws PdfExtractionException")
    void corruptFileThrows() throws IOException {
        Path corrupt = tempDir.resolve("corrupt.pdf");
        Files.write(corrupt, new byte[]{0x25, 0x50, 0x44, 0x46, 0x00, 0x11, 0x22, 0x33});
        assertThrows(PdfExtractionException.class, () -> PdfExtractor.extractText(corrupt));
    }

    @Test
    @DisplayName("Encrypted PDF protected by real non-empty user password throws PdfExtractionException")
    void encryptedPdfThrows() throws IOException {
        Path encryptedPdf = tempDir.resolve("encrypted_report.pdf");
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            AccessPermission permission = new AccessPermission();
            StandardProtectionPolicy policy = new StandardProtectionPolicy("ownerSecretPass", "userSecretPass", permission);
            policy.setEncryptionKeyLength(128);
            document.protect(policy);
            document.save(encryptedPdf.toFile());
        }

        assertThrows(PdfExtractionException.class, () -> PdfExtractor.extractText(encryptedPdf));
    }

    @Test
    @DisplayName("PDF with no text returns empty string")
    void emptyPdfReturnsEmptyString() throws IOException {
        Path emptyPdf = tempDir.resolve("empty_report.pdf");
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            document.save(emptyPdf.toFile());
        }

        String extracted = PdfExtractor.extractText(emptyPdf);
        assertNotNull(extracted);
        assertEquals("", extracted);
    }

    @Test
    @DisplayName("Extracts Latin text from valid synthetic PDF")
    void validPdfExtractsLatinText() throws IOException {
        Path validPdf = tempDir.resolve("sample_threat_report.pdf");
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream stream = new PDPageContentStream(document, page)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("Adversary executed T1059.001 to run malicious scripts.");
                stream.endText();
            }
            document.save(validPdf.toFile());
        }

        String extracted = PdfExtractor.extractText(validPdf);
        assertNotNull(extracted);
        assertTrue(extracted.contains("Adversary executed T1059.001 to run malicious scripts."));
    }

    @Test
    @DisplayName("Multi-page PDF preserves page text extraction order")
    void multiPageOrder() throws IOException {
        Path multiPagePdf = tempDir.resolve("multipage_report.pdf");
        try (PDDocument document = new PDDocument()) {
            PDPage page1 = new PDPage();
            document.addPage(page1);
            try (PDPageContentStream stream = new PDPageContentStream(document, page1)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("First page intelligence summary.");
                stream.endText();
            }

            PDPage page2 = new PDPage();
            document.addPage(page2);
            try (PDPageContentStream stream = new PDPageContentStream(document, page2)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("Second page technical analysis.");
                stream.endText();
            }
            document.save(multiPagePdf.toFile());
        }

        String text = PdfExtractor.extractText(multiPagePdf);
        int pos1 = text.indexOf("First page intelligence summary.");
        int pos2 = text.indexOf("Second page technical analysis.");
        assertTrue(pos1 >= 0, "Page 1 text should be present");
        assertTrue(pos2 >= 0, "Page 2 text should be present");
        assertTrue(pos1 < pos2, "Page 1 text must appear before Page 2 text");
    }

    @Test
    @DisplayName("Underlying PDF resource is closed so file is deletable immediately on Windows")
    void resourceClosedFileDeletable() throws IOException {
        Path deletablePdf = tempDir.resolve("deletable_report.pdf");
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);
            try (PDPageContentStream stream = new PDPageContentStream(document, page)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("Temporary text.");
                stream.endText();
            }
            document.save(deletablePdf.toFile());
        }

        PdfExtractor.extractText(deletablePdf);
        // On Windows, if the file handle is leaked / not closed, Files.delete will throw FileSystemException
        assertDoesNotThrow(() -> Files.delete(deletablePdf));
        assertFalse(Files.exists(deletablePdf));
    }

    @Test
    @DisplayName("PDF with owner password and empty user password extracts its text")
    void ownerPasswordEmptyUserPasswordExtractsText() throws IOException {
        Path pdfPath = tempDir.resolve("owner_pass_only.pdf");
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            AccessPermission permission = new AccessPermission();
            StandardProtectionPolicy policy = new StandardProtectionPolicy("ownerSecretPass", "", permission);
            policy.setEncryptionKeyLength(128);
            document.protect(policy);

            try (PDPageContentStream stream = new PDPageContentStream(document, page)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("Text protected by owner password only.");
                stream.endText();
            }
            document.save(pdfPath.toFile());
        }

        String text = PdfExtractor.extractText(pdfPath);
        assertNotNull(text);
        assertTrue(text.contains("Text protected by owner password only."));
    }
}
