package com.team.attackmap.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SentenceSplitter Contract and Normalization Tests")
class SentenceSplitterTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n", "\r\n"})
    @DisplayName("Null or blank input returns an empty list")
    void nullOrBlankReturnsEmptyList(String input) {
        List<String> result = SentenceSplitter.split(input);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Returned list is unmodifiable")
    void returnedListIsUnmodifiable() {
        List<String> result = SentenceSplitter.split("The actor deployed malware. The system halted.");
        assertThrows(UnsupportedOperationException.class, () -> result.add("Extra"));
        assertThrows(UnsupportedOperationException.class, () -> result.remove(0));
    }

    @Test
    @DisplayName("Splits on period, exclamation, and question mark followed by whitespace and uppercase")
    void splitOnTerminalPunctuationFollowedByUppercase() {
        String input = "The adversary infiltrated the network. Persistence was established! Did they exfiltrate data? Yes, they did.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(4, result.size());
        assertEquals("The adversary infiltrated the network.", result.get(0));
        assertEquals("Persistence was established!", result.get(1));
        assertEquals("Did they exfiltrate data?", result.get(2));
        assertEquals("Yes, they did.", result.get(3));
    }

    @Test
    @DisplayName("Splits after terminal punctuation followed by whitespace and digit")
    void splitBeforeDigit() {
        String input = "Malware executed successfully! 2 endpoints were locked down.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("Malware executed successfully!", result.get(0));
        assertEquals("2 endpoints were locked down.", result.get(1));
    }

    @Test
    @DisplayName("Splits after terminal punctuation followed by whitespace and quote or bracket")
    void splitBeforeQuoteOrBracket() {
        String input = "The alert was triggered. \"Analyze immediately,\" commanded the lead. Threat detected. [Priority 1] containment required.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(4, result.size());
        assertEquals("The alert was triggered.", result.get(0));
        assertEquals("\"Analyze immediately,\" commanded the lead.", result.get(1));
        assertEquals("Threat detected.", result.get(2));
        assertEquals("[Priority 1] containment required.", result.get(3));
    }

    @Test
    @DisplayName("Normalization: drops standalone page number lines")
    void dropStandalonePageNumberLines() {
        String input = "First sentence of report.\n42\nSecond sentence of report.\n   105   \nThird sentence.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(3, result.size());
        assertEquals("First sentence of report.", result.get(0));
        assertEquals("Second sentence of report.", result.get(1));
        assertEquals("Third sentence.", result.get(2));
    }

    @Test
    @DisplayName("Normalization: drops 'Page N' and 'Page N of M' lines")
    void dropPageNOfMLines() {
        String input = "Threat summary begins here.\nPage 1\nContinuing with findings.\nPage 2 of 12\nConcluding recommendations.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(3, result.size());
        assertEquals("Threat summary begins here.", result.get(0));
        assertEquals("Continuing with findings.", result.get(1));
        assertEquals("Concluding recommendations.", result.get(2));
    }

    @Test
    @DisplayName("Normalization: joins hyphenated word-break when next line starts lowercase")
    void joinHyphenatedLineBreaks() {
        String input = "The attacker used multi-\nstage payloads and com-\npromised the host.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(1, result.size());
        assertEquals("The attacker used multistage payloads and compromised the host.", result.get(0));
    }

    @Test
    @DisplayName("Normalization: hyphen at line end followed by uppercase is NOT joined")
    void hyphenFollowedByUppercaseIsNotJoined() {
        String input = "The campaign was anti-\nRussian in origin.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(1, result.size());
        assertEquals("The campaign was anti- Russian in origin.", result.get(0));
    }

    @Test
    @DisplayName("Normalization: joins hard-wrapped lines and collapses multiple whitespace")
    void joinHardWrappedLinesAndCollapseWhitespace() {
        String input = "This is a long sentence\n    wrapped across multiple\n\tlines with    redundant\nspaces.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(1, result.size());
        assertEquals("This is a long sentence wrapped across multiple lines with redundant spaces.", result.get(0));
    }

    @Test
    @DisplayName("Do not split inside technique IDs (T1059.001)")
    void doNotSplitInsideTechniqueId() {
        String input = "The actor used T1059.001 to execute powershell. Lateral movement followed.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("The actor used T1059.001 to execute powershell.", result.get(0));
        assertEquals("Lateral movement followed.", result.get(1));
    }

    @Test
    @DisplayName("Do not split inside common abbreviations: e.g., i.e., U.S., Dr., vs., etc., Fig., No.")
    void doNotSplitInsideAbbreviations() {
        String input = "We observed several tools, e.g. PowerShell and CMD. " +
                "The primary vector, i.e. phishing, was successful. " +
                "The target was a U.S. agency. " +
                "Analysis was led by Dr. Smith. " +
                "Consider T1059 vs. T1086 in the analysis. " +
                "Artifacts included registry keys, logs, etc. across hosts. " +
                "Refer to Fig. 1 for details. " +
                "Incident No. 404 is now closed.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(8, result.size());
        assertEquals("We observed several tools, e.g. PowerShell and CMD.", result.get(0));
        assertEquals("The primary vector, i.e. phishing, was successful.", result.get(1));
        assertEquals("The target was a U.S. agency.", result.get(2));
        assertEquals("Analysis was led by Dr. Smith.", result.get(3));
        assertEquals("Consider T1059 vs. T1086 in the analysis.", result.get(4));
        assertEquals("Artifacts included registry keys, logs, etc. across hosts.", result.get(5));
        assertEquals("Refer to Fig. 1 for details.", result.get(6));
        assertEquals("Incident No. 404 is now closed.", result.get(7));
    }

    @Test
    @DisplayName("Do not split inside file extensions (malware.exe)")
    void doNotSplitInsideFileExtension() {
        String input = "The payload malware.exe was executed on victim machine. Persistence followed.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("The payload malware.exe was executed on victim machine.", result.get(0));
        assertEquals("Persistence followed.", result.get(1));
    }

    @Test
    @DisplayName("Do not split inside domain names (evil.example.com)")
    void doNotSplitInsideDomain() {
        String input = "Beaconing to evil.example.com was observed every five minutes. The host was isolated.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("Beaconing to evil.example.com was observed every five minutes.", result.get(0));
        assertEquals("The host was isolated.", result.get(1));
    }

    @Test
    @DisplayName("Do not split inside IP addresses (192.168.1.10)")
    void doNotSplitInsideIpAddress() {
        String input = "Connections to 192.168.1.10 were detected by the firewall. Alerts were raised.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("Connections to 192.168.1.10 were detected by the firewall.", result.get(0));
        assertEquals("Alerts were raised.", result.get(1));
    }

    @Test
    @DisplayName("Do not split inside software version numbers (v2.1.3)")
    void doNotSplitInsideVersionNumber() {
        String input = "The vulnerability affected v2.1.3 of the service. Patching was deployed.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("The vulnerability affected v2.1.3 of the service.", result.get(0));
        assertEquals("Patching was deployed.", result.get(1));
    }

    @Test
    @DisplayName("Do not split inside decimal numbers (3.5)")
    void doNotSplitInsideDecimalNumber() {
        String input = "The CVSS base score was 3.5 according to the report. Next assessment is scheduled.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("The CVSS base score was 3.5 according to the report.", result.get(0));
        assertEquals("Next assessment is scheduled.", result.get(1));
    }

    @Test
    @DisplayName("Defanged indicators stay inside one sentence")
    void defangedIndicatorsStayInsideOneSentence() {
        String input = "The threat actor contacted evil[.]example[.]com and hxxp://evil[.]com/a for staging. Investigation continued.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("The threat actor contacted evil[.]example[.]com and hxxp://evil[.]com/a for staging.", result.get(0));
        assertEquals("Investigation continued.", result.get(1));
    }

    @Test
    @DisplayName("URL and Windows file path do not cause a split")
    void urlAndWindowsPathDoNotCauseSplit() {
        String input = "The executable at C:\\Windows\\System32\\cmd.exe fetched data from https://example.com/a.b successfully. Next step followed.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("The executable at C:\\Windows\\System32\\cmd.exe fetched data from https://example.com/a.b successfully.", result.get(0));
        assertEquals("Next step followed.", result.get(1));
    }

    @Test
    @DisplayName("Very long sentence is returned whole without truncation")
    void veryLongSentenceIsReturnedWhole() {
        String longText = "The adversary executed multiple stages of complex cyber intrusion techniques across the enterprise infrastructure without interruption or pause ".repeat(20) + "and concluded the campaign.";
        List<String> result = SentenceSplitter.split(longText);
        assertEquals(1, result.size());
        assertEquals(longText.trim(), result.get(0));
    }

    @Test
    @DisplayName("Bullet and numbered list lines are treated as separate sentences")
    void bulletAndNumberedListLinesBehavior() {
        String input = "Attack lifecycle:\n" +
                "- Initial access via spearphishing\n" +
                "- Execution via PowerShell\n" +
                "1. Persistence via registry Run keys.\n" +
                "2. Privilege escalation via Token Impersonation.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(5, result.size());
        assertEquals("Attack lifecycle:", result.get(0));
        assertEquals("- Initial access via spearphishing", result.get(1));
        assertEquals("- Execution via PowerShell", result.get(2));
        assertEquals("1. Persistence via registry Run keys.", result.get(3));
        assertEquals("2. Privilege escalation via Token Impersonation.", result.get(4));
    }

    @Test
    @DisplayName("Sentence ending in an abbreviation is not split (known limitation)")
    void sentenceEndingInAbbreviationLimitation() {
        String input = "Artifacts included registry keys, logs, etc. The attacker then moved laterally.";
        List<String> result = SentenceSplitter.split(input);
        // Because "etc." is protected as an abbreviation, it does not trigger a split
        // even though it ends a sentence before "The".
        assertEquals(1, result.size());
        assertEquals("Artifacts included registry keys, logs, etc. The attacker then moved laterally.", result.get(0));
    }

    @Test
    @DisplayName("Short real-word abbreviation followed by uppercase splits into separate sentences")
    void shortWordAbbreviationFollowedByUppercaseSplits() {
        String input = "It was not blocked, no. Then they left.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(2, result.size());
        assertEquals("It was not blocked, no.", result.get(0));
        assertEquals("Then they left.", result.get(1));
    }

    @Test
    @DisplayName("Supports non-ASCII text correctly")
    void nonAsciiTextHandling() {
        String input = "L'attaque a réussi. Les attaquants ont accédé au serveur! Über 10 Systeme waren betroffen? Да, это так.";
        List<String> result = SentenceSplitter.split(input);
        assertEquals(4, result.size());
        assertEquals("L'attaque a réussi.", result.get(0));
        assertEquals("Les attaquants ont accédé au serveur!", result.get(1));
        assertEquals("Über 10 Systeme waren betroffen?", result.get(2));
        assertEquals("Да, это так.", result.get(3));
    }

    @Test
    @DisplayName("Sentence splitting is strictly deterministic across repeated invocations")
    void determinismTest() {
        String input = "Adversary used T1059.001. System compromised! Refer to Fig. 2 for architecture.";
        List<String> firstRun = SentenceSplitter.split(input);
        for (int i = 0; i < 50; i++) {
            List<String> run = SentenceSplitter.split(input);
            assertEquals(firstRun, run);
        }
    }
}
