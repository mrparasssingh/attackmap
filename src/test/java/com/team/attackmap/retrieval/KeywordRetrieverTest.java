package com.team.attackmap.retrieval;

import com.team.attackmap.model.Prediction;
import com.team.attackmap.model.Technique;
import com.team.attackmap.util.Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KeywordRetrieverTest {

    private Technique t1059;
    private Technique t1059_001;
    private Technique t1059_003;
    private Technique t1078;
    private Technique t1082;
    private Technique t1083;

    @BeforeEach
    void setUp() {
        t1059 = new Technique(
                "T1059",
                "Command and Scripting Interpreter",
                "Adversaries may abuse command and script interpreters to execute commands.",
                List.of("execution"),
                false
        );

        t1059_001 = new Technique(
                "T1059.001",
                "PowerShell",
                "Adversaries may abuse PowerShell commands and scripts for execution.",
                List.of("execution"),
                true
        );

        t1059_003 = new Technique(
                "T1059.003",
                "Windows Command Shell",
                "Adversaries may abuse the Windows command shell for execution.",
                List.of("execution"),
                true
        );

        t1078 = new Technique(
                "T1078",
                "Valid Accounts",
                "Adversaries may obtain and abuse credentials of existing accounts.",
                List.of("defense-evasion", "persistence", "privilege-escalation", "initial-access"),
                false
        );

        t1082 = new Technique(
                "T1082",
                "System Information Discovery",
                "An adversary may attempt to get detailed information about the operating system.",
                List.of("discovery"),
                false
        );

        t1083 = new Technique(
                "T1083",
                "File and Directory Discovery",
                "Adversaries may enumerate files and directories to gather information.",
                List.of("discovery"),
                false
        );
    }

    @Test
    @DisplayName("Exact technique name in sentence ranks that technique first")
    void exactTechniqueNameRanksFirst() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1078, t1082));
        List<Prediction> predictions = retriever.rank("The threat actor utilized Command and Scripting Interpreter.", 5);
        assertFalse(predictions.isEmpty());
        assertEquals("T1059", predictions.get(0).techniqueId());
    }

    @Test
    @DisplayName("Name match outranks a description-only match")
    void nameMatchOutranksDescriptionMatch() {
        // t1059_001 has "PowerShell" in name (weight 3.0).
        // Let technique B have "powershell" only in description (weight 1.0).
        Technique b = new Technique("T9999", "Other Tool", "Uses powershell scripts.", List.of("execution"), false);
        KeywordRetriever retriever = new KeywordRetriever(List.of(b, t1059_001));

        List<Prediction> predictions = retriever.rank("The attacker executed powershell.", 2);
        assertEquals(2, predictions.size());
        assertEquals("T1059.001", predictions.get(0).techniqueId());
        assertEquals("T9999", predictions.get(1).techniqueId());
        assertTrue(predictions.get(0).score() > predictions.get(1).score());
    }

    @Test
    @DisplayName("No matching tokens returns an empty list")
    void noMatchingTokensReturnsEmptyList() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1078));
        List<Prediction> predictions = retriever.rank("completely irrelevant text with no overlap xyzabc", 5);
        assertTrue(predictions.isEmpty());
    }

    @Test
    @DisplayName("Repeated words in the query do not inflate the score")
    void repeatedWordsDoNotInflateScore() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059_001));
        List<Prediction> singleWord = retriever.rank("powershell", 5);
        List<Prediction> repeatedWord = retriever.rank("powershell powershell powershell", 5);

        assertEquals(1, singleWord.size());
        assertEquals(1, repeatedWord.size());
        // Binary friendly comparison
        assertEquals(Double.valueOf(singleWord.get(0).score()), Double.valueOf(repeatedWord.get(0).score()));
    }

    @Test
    @DisplayName("Ties are broken by ascending technique ID")
    void tiesBrokenByAscendingTechniqueId() {
        Technique techA = new Technique("T1001", "Alpha", "Common description keyword", List.of("discovery"), false);
        Technique techB = new Technique("T1002", "Beta", "Common description keyword", List.of("discovery"), false);
        Technique techC = new Technique("T1000", "Gamma", "Common description keyword", List.of("discovery"), false);

        KeywordRetriever retriever = new KeywordRetriever(List.of(techB, techA, techC));
        List<Prediction> predictions = retriever.rank("description", 5);

        assertEquals(3, predictions.size());
        // All have same score (1.0 from desc keyword "description"). Sorted by techniqueId ascending: T1000, T1001, T1002
        assertEquals("T1000", predictions.get(0).techniqueId());
        assertEquals("T1001", predictions.get(1).techniqueId());
        assertEquals("T1002", predictions.get(2).techniqueId());
    }

    @Test
    @DisplayName("k smaller than number of matches truncates the list")
    void kSmallerThanMatchesTruncates() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1059_001, t1059_003));
        List<Prediction> predictions = retriever.rank("adversaries execute commands", 2);
        assertEquals(2, predictions.size());
    }

    @Test
    @DisplayName("k larger than number of matches returns only matches")
    void kLargerThanMatchesReturnsOnlyMatches() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1078));
        // Only t1059 matches "command"
        List<Prediction> predictions = retriever.rank("command", 10);
        assertEquals(1, predictions.size());
        assertEquals("T1059", predictions.get(0).techniqueId());
    }

    @Test
    @DisplayName("k = 0 and negative k return an empty list")
    void zeroAndNegativeKReturnEmptyList() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059));
        assertTrue(retriever.rank("command", 0).isEmpty());
        assertTrue(retriever.rank("command", -1).isEmpty());
        assertTrue(retriever.rank("command", -10).isEmpty());
    }

    @Test
    @DisplayName("Null and blank sentence return an empty list")
    void nullAndBlankSentenceReturnEmptyList() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059));
        assertTrue(retriever.rank(null, 5).isEmpty());
        assertTrue(retriever.rank("", 5).isEmpty());
        assertTrue(retriever.rank("   \t\n  ", 5).isEmpty());
    }

    @Test
    @DisplayName("Empty technique list returns an empty list for any sentence")
    void emptyTechniqueListReturnsEmptyList() {
        KeywordRetriever retriever = new KeywordRetriever(Collections.emptyList());
        assertTrue(retriever.rank("command execution powershell", 5).isEmpty());
    }

    @Test
    @DisplayName("Explicit ID T1059 in the sentence ranks T1059 first")
    void explicitIdRanksFirst() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1078, t1082));
        List<Prediction> predictions = retriever.rank("The group leveraged T1059 in this incident.", 5);
        assertFalse(predictions.isEmpty());
        assertEquals("T1059", predictions.get(0).techniqueId());
        assertTrue(predictions.get(0).score() >= Config.ID_MATCH_BONUS);
    }

    @Test
    @DisplayName("Explicit sub-technique ID T1059.001 works when in the list")
    void explicitSubTechniqueIdWorks() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1059_001, t1059_003));
        List<Prediction> predictions = retriever.rank("Threat actor used T1059.001 scripts.", 5);
        assertFalse(predictions.isEmpty());
        assertEquals("T1059.001", predictions.get(0).techniqueId());
        assertTrue(predictions.get(0).score() >= Config.ID_MATCH_BONUS);
    }

    @Test
    @DisplayName("Explicit sub-technique ID gives bonus only to sub-technique and not parent, and vice versa")
    void explicitSubTechniqueIdDoesNotBoostParentAndViceVersa() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1059_001));

        // Sub-technique ID in sentence: T1059.001 gets bonus, T1059 does NOT get ID bonus
        List<Prediction> subResults = retriever.rank("Seen using T1059.001 here.", 5);
        assertEquals("T1059.001", subResults.get(0).techniqueId());
        assertTrue(subResults.get(0).score() >= Config.ID_MATCH_BONUS);
        for (Prediction p : subResults) {
            if (p.techniqueId().equals("T1059")) {
                assertTrue(p.score() < Config.ID_MATCH_BONUS, "Parent T1059 must not receive ID bonus for T1059.001");
            }
        }

        // Parent ID in sentence: T1059 gets bonus, T1059.001 does NOT get ID bonus
        List<Prediction> parentResults = retriever.rank("Seen using T1059 here.", 5);
        assertEquals("T1059", parentResults.get(0).techniqueId());
        assertTrue(parentResults.get(0).score() >= Config.ID_MATCH_BONUS);
        for (Prediction p : parentResults) {
            if (p.techniqueId().equals("T1059.001")) {
                assertTrue(p.score() < Config.ID_MATCH_BONUS, "Sub-technique T1059.001 must not receive ID bonus for T1059");
            }
        }
    }

    @Test
    @DisplayName("An ID not in the list is ignored without error")
    void unknownIdIgnoredWithoutError() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059));
        List<Prediction> predictions = retriever.rank("Attacker used T9999 to pivot.", 5);
        // T9999 is not in technique list, so no bonus given, only keyword matching on words
        for (Prediction p : predictions) {
            assertTrue(p.score() < Config.ID_MATCH_BONUS);
        }
    }

    @Test
    @DisplayName("Lowercase t1059 does NOT trigger the ID bonus")
    void lowercaseIdDoesNotTriggerBonus() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059));
        List<Prediction> predictions = retriever.rank("Attacker used t1059 script.", 5);
        // t1059 might match as token if not filtered, but MUST NOT receive the 100.0 ID bonus
        if (!predictions.isEmpty()) {
            assertTrue(predictions.get(0).score() < Config.ID_MATCH_BONUS,
                    "Lowercase t1059 must not receive ID_MATCH_BONUS");
        }
    }

    @Test
    @DisplayName("ID-only sentence (no keyword matches) still returns that technique with score = ID_MATCH_BONUS")
    void idOnlySentenceReturnsTechnique() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1078));
        // "T1059" alone has no overlapping keywords with t1059 name or description
        List<Prediction> predictions = retriever.rank("T1059", 5);
        assertEquals(1, predictions.size());
        assertEquals("T1059", predictions.get(0).techniqueId());
        assertEquals(Double.valueOf(Config.ID_MATCH_BONUS), Double.valueOf(predictions.get(0).score()));
    }

    @Test
    @DisplayName("Non-ASCII text (curly quotes, em-dash, Cyrillic) does not crash")
    void nonAsciiTextDoesNotCrash() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059));
        assertDoesNotThrow(() -> {
            List<Prediction> predictions = retriever.rank("“Adversaries”—атака ‘script’ execute", 5);
            assertNotNull(predictions);
        });
    }

    @Test
    @DisplayName("evidenceSentence equals original input exactly")
    void evidenceSentenceEqualsOriginalInput() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059));
        String inputSentence = "  Adversaries executed COMMANDS in powershell!  ";
        List<Prediction> predictions = retriever.rank(inputSentence, 5);
        assertFalse(predictions.isEmpty());
        assertEquals(inputSentence, predictions.get(0).evidenceSentence());
    }

    @Test
    @DisplayName("Returned list is unmodifiable")
    void returnedListIsUnmodifiable() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059));
        List<Prediction> predictions = retriever.rank("command execute", 5);
        assertFalse(predictions.isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> predictions.add(null));
        assertThrows(UnsupportedOperationException.class, () -> predictions.remove(0));
    }

    @Test
    @DisplayName("Repeated calls give identical results (deterministic)")
    void repeatedCallsGiveIdenticalResults() {
        KeywordRetriever retriever = new KeywordRetriever(List.of(t1059, t1078, t1082));
        String sentence = "Adversaries executed commands and discovered system accounts";
        List<Prediction> firstCall = retriever.rank(sentence, 5);
        List<Prediction> secondCall = retriever.rank(sentence, 5);

        assertEquals(firstCall.size(), secondCall.size());
        for (int i = 0; i < firstCall.size(); i++) {
            assertEquals(firstCall.get(i).techniqueId(), secondCall.get(i).techniqueId());
            assertEquals(Double.valueOf(firstCall.get(i).score()), Double.valueOf(secondCall.get(i).score()));
            assertEquals(firstCall.get(i).evidenceSentence(), secondCall.get(i).evidenceSentence());
        }
    }

    @Test
    @DisplayName("Modifying original input list after construction does not change retriever behavior")
    void defensiveCopyProtectsAgainstExternalModification() {
        List<Technique> mutableList = new ArrayList<>();
        mutableList.add(t1059);
        KeywordRetriever retriever = new KeywordRetriever(mutableList);

        // Modify input list
        mutableList.clear();
        mutableList.add(t1078);

        List<Prediction> predictions = retriever.rank("Command and Scripting Interpreter", 5);
        assertFalse(predictions.isEmpty());
        assertEquals("T1059", predictions.get(0).techniqueId());
    }

    @Test
    @DisplayName("Null technique list is rejected in constructor with NullPointerException")
    void nullTechniqueListRejected() {
        assertThrows(NullPointerException.class, () -> new KeywordRetriever(null));
    }

    @Test
    @DisplayName("Hand-calculated score check on a 3-technique toy example with arithmetic in comments")
    void handCalculatedScoreCheck() {
        /*
         * Toy example technique definitions:
         *
         * Tech A: T1001
         * Name: "Network Sniffing"
         * Tokens in name: { "network", "sniffing" }
         * Description: "Adversaries may sniff network traffic to identify credentials."
         * Tokens in desc:
         *   - adversaries: "adversaries"
         *   - may: (stopword dropped)
         *   - sniff: "sniff"
         *   - network: "network"
         *   - traffic: "traffic"
         *   - to: (stopword dropped)
         *   - identify: "identify"
         *   - credentials: "credentials"
         * Tokens in desc: { "adversaries", "sniff", "network", "traffic", "identify", "credentials" }
         *
         * Tech B: T1002
         * Name: "Credentials in Files"
         * Tokens in name:
         *   - credentials: "credentials"
         *   - in: (stopword dropped)
         *   - files: "files"
         * Tokens in name: { "credentials", "files" }
         * Description: "Adversaries search files for credentials."
         * Tokens in desc:
         *   - adversaries: "adversaries"
         *   - search: "search"
         *   - files: "files"
         *   - for: (stopword dropped)
         *   - credentials: "credentials"
         * Tokens in desc: { "adversaries", "search", "files", "credentials" }
         *
         * Tech C: T1003
         * Name: "OS Credential Dumping"
         * Tokens in name:
         *   - os: "os" (length 2, kept)
         *   - credential: "credential"
         *   - dumping: "dumping"
         * Tokens in name: { "os", "credential", "dumping" }
         * Description: "Adversaries may dump credentials from operating system memory."
         * Tokens in desc:
         *   - adversaries: "adversaries"
         *   - may: (stopword)
         *   - dump: "dump"
         *   - credentials: "credentials"
         *   - from: (stopword)
         *   - operating: "operating"
         *   - system: "system"
         *   - memory: "memory"
         * Tokens in desc: { "adversaries", "dump", "credentials", "operating", "system", "memory" }
         *
         * Sentence under test:
         * "Adversaries search network traffic T1002"
         *
         * Query tokens Q (deduped set):
         * "adversaries" -> in stopwords? No. length >= 2? Yes.
         * "search" -> length >= 2? Yes.
         * "network" -> length >= 2? Yes.
         * "traffic" -> length >= 2? Yes.
         * "T1002" -> non-letter/digit split yields "t1002" (length >= 2, kept).
         * Note: Regex explicit ID check detects "T1002" matching \bT\d{4}(\.\d{3})?\b.
         *
         * Tokens in Q = { "adversaries", "search", "network", "traffic", "t1002" }
         *
         * Scoring breakdown:
         * NAME_WEIGHT = 3.0
         * DESC_WEIGHT = 1.0
         * ID_MATCH_BONUS = 100.0
         *
         * Tech A (T1001):
         * - Name tokens: { "network", "sniffing" }
         *     Matches in Q: "network" (1 match) -> 1 * 3.0 = 3.0
         * - Desc tokens: { "adversaries", "sniff", "network", "traffic", "identify", "credentials" }
         *     Matches in Q: "adversaries", "network", "traffic" (3 matches) -> 3 * 1.0 = 3.0
         * - ID Match Bonus: 0.0 (T1001 not in sentence)
         * Total score for Tech A = 3.0 + 3.0 + 0.0 = 6.0
         *
         * Tech B (T1002):
         * - Name tokens: { "credentials", "files" }
         *     Matches in Q: none -> 0.0
         * - Desc tokens: { "adversaries", "search", "files", "credentials" }
         *     Matches in Q: "adversaries", "search" (2 matches) -> 2 * 1.0 = 2.0
         * - ID Match Bonus: sentence contains "T1002" -> 100.0
         * Total score for Tech B = 0.0 + 2.0 + 100.0 = 102.0
         *
         * Tech C (T1003):
         * - Name tokens: { "os", "credential", "dumping" }
         *     Matches in Q: none -> 0.0
         * - Desc tokens: { "adversaries", "dump", "credentials", "operating", "system", "memory" }
         *     Matches in Q: "adversaries" (1 match) -> 1 * 1.0 = 1.0
         * - ID Match Bonus: 0.0 (T1003 not in sentence)
         * Total score for Tech C = 0.0 + 1.0 + 0.0 = 1.0
         *
         * Ranking expectation:
         * 1. T1002 with exact score 102.0
         * 2. T1001 with exact score 6.0
         * 3. T1003 with exact score 1.0
         */
        Technique techA = new Technique("T1001", "Network Sniffing",
                "Adversaries may sniff network traffic to identify credentials.", List.of("credential-access"), false);
        Technique techB = new Technique("T1002", "Credentials in Files",
                "Adversaries search files for credentials.", List.of("credential-access"), false);
        Technique techC = new Technique("T1003", "OS Credential Dumping",
                "Adversaries may dump credentials from operating system memory.", List.of("credential-access"), false);

        KeywordRetriever retriever = new KeywordRetriever(List.of(techA, techB, techC));
        List<Prediction> predictions = retriever.rank("Adversaries search network traffic T1002", 5);

        assertEquals(3, predictions.size());

        // Prediction 1: T1002
        assertEquals("T1002", predictions.get(0).techniqueId());
        assertEquals(Double.valueOf(102.0), Double.valueOf(predictions.get(0).score()));

        // Prediction 2: T1001
        assertEquals("T1001", predictions.get(1).techniqueId());
        assertEquals(Double.valueOf(6.0), Double.valueOf(predictions.get(1).score()));

        // Prediction 3: T1003
        assertEquals("T1003", predictions.get(2).techniqueId());
        assertEquals(Double.valueOf(1.0), Double.valueOf(predictions.get(2).score()));
    }
}

