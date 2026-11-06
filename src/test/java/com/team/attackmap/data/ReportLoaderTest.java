package com.team.attackmap.data;

import com.team.attackmap.model.Sentence;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ReportLoader Contract and Format Tests")
class ReportLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Null path throws IllegalArgumentException")
    void nullPathThrows() {
        assertThrows(IllegalArgumentException.class, () -> ReportLoader.load(null));
    }

    @Test
    @DisplayName("Missing report file throws PdfExtractionException for PDF and IllegalArgumentException for TXT")
    void loaderMissingFileThrows() {
        Path missingPdf = tempDir.resolve("non_existent_report.pdf");
        assertThrows(PdfExtractionException.class, () -> ReportLoader.load(missingPdf));

        Path missingTxt = tempDir.resolve("non_existent_report.txt");
        assertThrows(IllegalArgumentException.class, () -> ReportLoader.load(missingTxt));
    }

    @ParameterizedTest
    @ValueSource(strings = {"report.docx", "data.json", "report.csv", "archive.zip", "notes.md"})
    @DisplayName("Unsupported file extensions throw IllegalArgumentException")
    void unsupportedExtensionsThrow(String filename) throws IOException {
        Path unsupported = tempDir.resolve(filename);
        Files.writeString(unsupported, "Some sample content.");
        assertThrows(IllegalArgumentException.class, () -> ReportLoader.load(unsupported));
    }

    @Test
    @DisplayName("ReportId derived from file name without extension")
    void reportIdDerivedFromFileName() throws IOException {
        Path txtPath = tempDir.resolve("campaign-alpha_2026.txt");
        Files.writeString(txtPath, "Threat actor conducted reconnaissance.", StandardCharsets.UTF_8);

        List<Sentence> sentences = ReportLoader.load(txtPath);
        assertFalse(sentences.isEmpty());
        for (Sentence s : sentences) {
            assertEquals("campaign-alpha_2026", s.reportId());
        }
    }

    @Test
    @DisplayName("Sequential 0-based sentence indices 0..n-1 in order")
    void loaderIndicesZeroToNMinusOne() throws IOException {
        Path txtPath = tempDir.resolve("multi_sentence.txt");
        Files.writeString(txtPath, "First sentence here. Second sentence follows. Third sentence concludes.", StandardCharsets.UTF_8);

        List<Sentence> sentences = ReportLoader.load(txtPath);
        assertEquals(3, sentences.size());
        for (int i = 0; i < sentences.size(); i++) {
            assertEquals(i, sentences.get(i).index());
        }
    }

    @Test
    @DisplayName("Loads UTF-8 .txt report into ordered Sentence records")
    void loadTxtReport() throws IOException {
        Path txtPath = tempDir.resolve("apt29_incident.txt");
        String content = "Adversary infiltrated network. Malware executed via T1059.001! Did alerts fire? Yes, they did.";
        Files.writeString(txtPath, content, StandardCharsets.UTF_8);

        List<Sentence> sentences = ReportLoader.load(txtPath);
        assertNotNull(sentences);
        assertEquals(4, sentences.size());

        assertEquals("apt29_incident", sentences.get(0).reportId());
        assertEquals(0, sentences.get(0).index());
        assertEquals("Adversary infiltrated network.", sentences.get(0).text());

        assertEquals("apt29_incident", sentences.get(1).reportId());
        assertEquals(1, sentences.get(1).index());
        assertEquals("Malware executed via T1059.001!", sentences.get(1).text());

        assertEquals("apt29_incident", sentences.get(2).reportId());
        assertEquals(2, sentences.get(2).index());
        assertEquals("Did alerts fire?", sentences.get(2).text());

        assertEquals("apt29_incident", sentences.get(3).reportId());
        assertEquals(3, sentences.get(3).index());
        assertEquals("Yes, they did.", sentences.get(3).text());
    }

    @Test
    @DisplayName("Loads .pdf report into ordered Sentence records via PdfExtractor")
    void loadPdfReport() throws IOException {
        Path pdfPath = tempDir.resolve("fin7_campaign.pdf");
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream stream = new PDPageContentStream(document, page)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("Spearphishing attachment delivered payload. Persistence was established.");
                stream.endText();
            }
            document.save(pdfPath.toFile());
        }

        List<Sentence> sentences = ReportLoader.load(pdfPath);
        assertNotNull(sentences);
        assertEquals(2, sentences.size());

        assertEquals("fin7_campaign", sentences.get(0).reportId());
        assertEquals(0, sentences.get(0).index());
        assertEquals("Spearphishing attachment delivered payload.", sentences.get(0).text());

        assertEquals("fin7_campaign", sentences.get(1).reportId());
        assertEquals(1, sentences.get(1).index());
        assertEquals("Persistence was established.", sentences.get(1).text());
    }

    @Test
    @DisplayName("Returned sentence list is unmodifiable")
    void returnedListIsUnmodifiable() throws IOException {
        Path txtPath = tempDir.resolve("sample.txt");
        Files.writeString(txtPath, "Single sentence report.", StandardCharsets.UTF_8);

        List<Sentence> sentences = ReportLoader.load(txtPath);
        assertThrows(UnsupportedOperationException.class, () -> sentences.add(new Sentence("x", 1, "extra")));
    }

    @Test
    @DisplayName("Strips leading UTF-8 BOM from text report content")
    void stripsLeadingUtf8Bom() throws IOException {
        Path bomTxt = tempDir.resolve("bom_report.txt");
        Files.writeString(bomTxt, "\uFEFFThreat intelligence report starts here.", StandardCharsets.UTF_8);

        List<Sentence> sentences = ReportLoader.load(bomTxt);
        assertFalse(sentences.isEmpty());
        assertEquals("Threat intelligence report starts here.", sentences.get(0).text());
        assertFalse(sentences.get(0).text().startsWith("\uFEFF"));
    }
}
