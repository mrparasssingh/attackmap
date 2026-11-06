package com.team.attackmap.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Sentence Model Contract Tests")
class SentenceTest {

    @Test
    @DisplayName("Valid construction stores trimmed fields and valid index")
    void validConstruction() {
        Sentence sentence = new Sentence("  report-001  ", 0, "  Adversary executed T1059.001.  ");
        assertEquals("report-001", sentence.reportId());
        assertEquals(0, sentence.index());
        assertEquals("Adversary executed T1059.001.", sentence.text());
    }

    @Test
    @DisplayName("Null reportId throws NullPointerException")
    void nullReportIdThrows() {
        assertThrows(NullPointerException.class, () -> new Sentence(null, 0, "Valid text."));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    @DisplayName("Blank reportId throws IllegalArgumentException")
    void blankReportIdThrows(String blankReportId) {
        assertThrows(IllegalArgumentException.class, () -> new Sentence(blankReportId, 0, "Valid text."));
    }

    @Test
    @DisplayName("Null text throws NullPointerException")
    void nullTextThrows() {
        assertThrows(NullPointerException.class, () -> new Sentence("report-1", 0, null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    @DisplayName("Blank text throws IllegalArgumentException")
    void blankTextThrows(String blankText) {
        assertThrows(IllegalArgumentException.class, () -> new Sentence("report-1", 0, blankText));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, -10, Integer.MIN_VALUE})
    @DisplayName("Negative index throws IllegalArgumentException")
    void negativeIndexThrows(int negativeIndex) {
        assertThrows(IllegalArgumentException.class, () -> new Sentence("report-1", negativeIndex, "Valid text."));
    }

    @Test
    @DisplayName("Index zero is allowed as 0-based start")
    void zeroIndexAllowed() {
        Sentence s = new Sentence("rep", 0, "First sentence.");
        assertEquals(0, s.index());
    }

    @Test
    @DisplayName("Sentence text and reportId are stored trimmed")
    void textAndReportIdAreStoredTrimmed() {
        Sentence s = new Sentence("   report-99   ", 0, "   Threat actor used PowerShell.   ");
        assertEquals("report-99", s.reportId());
        assertEquals("Threat actor used PowerShell.", s.text());
    }

    @Test
    @DisplayName("Record equality and hashCode adhere to standard contracts")
    void equalityAndHashCode() {
        Sentence s1 = new Sentence("rep", 1, "Threat detected.");
        Sentence s2 = new Sentence("  rep  ", 1, "  Threat detected.  ");
        Sentence s3 = new Sentence("rep", 2, "Threat detected.");

        assertEquals(s1, s2);
        assertEquals(s1.hashCode(), s2.hashCode());
        assertNotEquals(s1, s3);
    }
}

