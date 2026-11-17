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

class TfIdfRetrieverTest {

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
    @DisplayName("Unique-term match ranks that technique first")
    void uniqueTermMatchRanksFirst() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059_001, t1078, t1082));
        List<Prediction> predictions = retriever.rank("The threat actor executed powershell commands.", 5);
        assertFalse(predictions.isEmpty());
        assertEquals("T1059.001", predictions.get(0).techniqueId());
        assertTrue(predictions.get(0).score() > Config.ZERO);
    }

    @Test
    @DisplayName("A rare term outweighs a common term across corpus")
    void rareTermOutweighsCommonTerm() {
        // N = 3 documents
        // "common" appears in all 3 documents (df = 3, idf = ln(4/4) + 1 = 1.0)
        // "rare" appears in only techA (df = 1, idf = ln(4/2) + 1 = ln(2) + 1 ≈ 1.693)
        Technique techA = new Technique("T1001", "Technique Alpha", "rare common", List.of("execution"), false);
        Technique techB = new Technique("T1002", "Technique Beta", "common regular", List.of("execution"), false);
        Technique techC = new Technique("T1003", "Technique Gamma", "common standard", List.of("execution"), false);

        TfIdfRetriever retriever = new TfIdfRetriever(List.of(techA, techB, techC));
        // Query has both "rare" and "common"
        List<Prediction> predictions = retriever.rank("rare common", 5);

        assertFalse(predictions.isEmpty());
        assertEquals("T1001", predictions.get(0).techniqueId(),
                "Tech A with rare term match must outrank Tech B with common term match");
    }

    @Test
    @DisplayName("Zero-norm query produces empty list, score 0, never NaN or division by zero")
    void zeroNormQueryProducesEmptyList() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1078));
        // Input containing only stopwords and punctuation
        List<Prediction> predictions = retriever.rank("the and of in !!!", 5);
        assertNotNull(predictions);
        assertTrue(predictions.isEmpty());
    }

    @Test
    @DisplayName("Out-of-vocabulary-only query returns empty list")
    void outOfVocabularyOnlyQueryReturnsEmpty() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1078));
        // Words that never appear in the corpus
        List<Prediction> predictions = retriever.rank("extraterrestrial xenomorph supernova", 5);
        assertNotNull(predictions);
        assertTrue(predictions.isEmpty());
    }

    @Test
    @DisplayName("Ties in score are broken by ascending technique ID")
    void tiesBrokenByAscendingTechniqueId() {
        Technique b = new Technique("T1002", "Credential Access", "Dumping memory credentials.", List.of("credential-access"), false);
        Technique a = new Technique("T1001", "Credential Access", "Dumping memory credentials.", List.of("credential-access"), false);

        TfIdfRetriever retriever = new TfIdfRetriever(List.of(b, a));
        List<Prediction> predictions = retriever.rank("Dumping memory credentials", 5);

        assertEquals(2, predictions.size());
        assertEquals("T1001", predictions.get(0).techniqueId());
        assertEquals("T1002", predictions.get(1).techniqueId());
        assertEquals(predictions.get(0).score(), predictions.get(1).score(), 1e-9);
    }

    @Test
    @DisplayName("k parameter handling: limit results, k <= 0 returns empty")
    void kParameterHandling() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1059_001, t1059_003, t1078, t1082, t1083));
        String query = "execute commands and abuse system information";

        List<Prediction> top1 = retriever.rank(query, 1);
        assertEquals(1, top1.size());

        List<Prediction> top3 = retriever.rank(query, 3);
        assertEquals(3, top3.size());

        List<Prediction> top100 = retriever.rank(query, 100);
        assertTrue(top100.size() >= 3 && top100.size() <= 6);

        List<Prediction> kZero = retriever.rank(query, 0);
        assertNotNull(kZero);
        assertTrue(kZero.isEmpty());

        List<Prediction> kNegative = retriever.rank(query, -1);
        assertNotNull(kNegative);
        assertTrue(kNegative.isEmpty());
    }

    @Test
    @DisplayName("Null or blank sentence returns unmodifiable empty list")
    void nullOrBlankSentenceReturnsEmptyList() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1078));

        assertTrue(retriever.rank(null, 5).isEmpty());
        assertTrue(retriever.rank("", 5).isEmpty());
        assertTrue(retriever.rank("   ", 5).isEmpty());
        assertTrue(retriever.rank("\t\n", 5).isEmpty());
    }

    @Test
    @DisplayName("Empty technique list is allowed and rank returns empty list")
    void emptyTechniqueListAllowed() {
        TfIdfRetriever retriever = new TfIdfRetriever(Collections.emptyList());
        List<Prediction> predictions = retriever.rank("PowerShell execution", 5);
        assertNotNull(predictions);
        assertTrue(predictions.isEmpty());
    }

    @Test
    @DisplayName("Explicit ID regex bonus with parent and child rules")
    void explicitIdRegexBonusWithParentChildRule() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1059_001));

        // Parent mention T1059: only T1059 gets +100.0 bonus
        List<Prediction> parentPreds = retriever.rank("The threat actor leveraged T1059 in the campaign.", 5);
        assertFalse(parentPreds.isEmpty());
        assertEquals("T1059", parentPreds.get(0).techniqueId());
        assertTrue(parentPreds.get(0).score() >= Config.ID_MATCH_BONUS);
        if (parentPreds.size() > 1) {
            assertTrue(parentPreds.get(1).score() < Config.ID_MATCH_BONUS);
        }

        // Child mention T1059.001: only T1059.001 gets +100.0 bonus
        List<Prediction> childPreds = retriever.rank("The threat actor leveraged T1059.001 in the campaign.", 5);
        assertFalse(childPreds.isEmpty());
        assertEquals("T1059.001", childPreds.get(0).techniqueId());
        assertTrue(childPreds.get(0).score() >= Config.ID_MATCH_BONUS);
        if (childPreds.size() > 1) {
            assertTrue(childPreds.get(1).score() < Config.ID_MATCH_BONUS);
        }

        // Lowercase "t1059" does not trigger bonus
        List<Prediction> lowerPreds = retriever.rank("The threat actor leveraged t1059 in the campaign.", 5);
        for (Prediction p : lowerPreds) {
            assertTrue(p.score() < Config.ID_MATCH_BONUS);
        }

        // Non-existent ID "T9999" does not throw or bonus any technique
        List<Prediction> unknownIdPreds = retriever.rank("The threat actor leveraged T9999 in the campaign.", 5);
        for (Prediction p : unknownIdPreds) {
            assertTrue(p.score() < Config.ID_MATCH_BONUS);
        }
    }

    @Test
    @DisplayName("Non-ASCII Unicode characters are properly tokenized and matched")
    void nonAsciiUnicodeHandling() {
        Technique tech = new Technique("T1001", "Überwachung Übertragung", "Datenübertragung über Netzwerk.", List.of("collection"), false);
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(tech));

        List<Prediction> predictions = retriever.rank("Überwachung der Übertragung", 5);
        assertFalse(predictions.isEmpty());
        assertEquals("T1001", predictions.get(0).techniqueId());
        assertTrue(predictions.get(0).score() > Config.ZERO);
    }

    @Test
    @DisplayName("Ranking is deterministic across repeated calls")
    void rankingIsDeterministic() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1059_001, t1078, t1082));
        String sentence = "Adversaries abuse command interpreters and credentials.";

        List<Prediction> run1 = retriever.rank(sentence, 5);
        List<Prediction> run2 = retriever.rank(sentence, 5);

        assertEquals(run1.size(), run2.size());
        for (int i = 0; i < run1.size(); i++) {
            assertEquals(run1.get(i).techniqueId(), run2.get(i).techniqueId());
            assertEquals(run1.get(i).score(), run2.get(i).score(), 1e-12);
            assertEquals(run1.get(i).evidenceSentence(), run2.get(i).evidenceSentence());
        }
    }

    @Test
    @DisplayName("Result list is unmodifiable")
    void resultListIsUnmodifiable() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1078));
        List<Prediction> predictions = retriever.rank("execute commands", 5);
        assertFalse(predictions.isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> predictions.add(new Prediction("T9999", 1.0, "fake")));
        assertThrows(UnsupportedOperationException.class, predictions::clear);
    }

    @Test
    @DisplayName("Defensively copies constructor list; external mutations do not affect index")
    void defensiveCopyOfConstructorList() {
        List<Technique> mutableList = new ArrayList<>();
        mutableList.add(t1059);
        TfIdfRetriever retriever = new TfIdfRetriever(mutableList);

        mutableList.clear();
        mutableList.add(t1078);

        List<Prediction> predictions = retriever.rank("execute commands", 5);
        assertFalse(predictions.isEmpty());
        assertEquals("T1059", predictions.get(0).techniqueId());
    }

    @Test
    @DisplayName("Null constructor argument throws NullPointerException")
    void nullConstructorArgumentThrows() {
        assertThrows(NullPointerException.class, () -> new TfIdfRetriever(null));
    }

    @Test
    @DisplayName("evidenceSentence equals the original input exactly")
    void evidenceSentenceEqualsOriginalInputExactly() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059));
        String rawSentence = "   Adversaries abuse command interpreters to execute commands.   \n";
        List<Prediction> predictions = retriever.rank(rawSentence, 5);
        assertFalse(predictions.isEmpty());
        assertEquals(rawSentence, predictions.get(0).evidenceSentence());
    }

    @Test
    @DisplayName("A sentence containing only a valid technique ID (no other matching tokens) returns that technique via ID bonus")
    void sentenceWithOnlyValidTechniqueIdReturnsViaIdBonus() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1078));
        List<Prediction> predictions = retriever.rank("T1059", 5);
        assertEquals(1, predictions.size());
        assertEquals("T1059", predictions.get(0).techniqueId());
        assertEquals(Config.ID_MATCH_BONUS, predictions.get(0).score(), 1e-9);
        assertEquals("T1059", predictions.get(0).evidenceSentence());
    }

    @Test
    @DisplayName("Sublinear TF: query 'alpha alpha beta' weights alpha by 1 + ln(2), not 2")
    void sublinearTfQueryWeighting() {
        /*
         * HAND-CALCULATED ARITHMETIC VERIFICATION (Calculated on paper):
         *
         * Corpus: N = 2 documents
         * Doc 1 (T1001):
         *   Name: "Alpha", Description: "Beta"
         *   Tokens: alpha (tf = 1), beta (tf = 1)
         * Doc 2 (T1002):
         *   Name: "Gamma", Description: "Gamma"
         *   Tokens: gamma (tf = 2)
         *
         * Document Frequencies & IDF:
         *   N = 2
         *   df(alpha) = 1, df(beta) = 1, df(gamma) = 1
         *   idf(t) = ln((1 + 2) / (1 + 1)) + 1 = ln(3/2) + 1 = ln(1.5) + 1
         *   Since df(alpha) == df(beta), idf(alpha) == idf(beta) = idf.
         *   The constant factor idf factors out of all term weights and cancels in cosine normalization!
         *
         * Query: "alpha alpha beta"
         *   Tokens: alpha (count = 2), beta (count = 1)
         *   Sublinear TF weights:
         *     tf_sub(alpha) = 1 + ln(2) ≈ 1.6931471805599453
         *     tf_sub(beta)  = 1 + ln(1) = 1.0
         *   (Note: If linear TF were used instead, weight would be 2.0).
         *
         * Query vector components (relative to idf):
         *   q(alpha) = 1 + ln(2)
         *   q(beta)  = 1.0
         *   ||q||_2  = sqrt( (1 + ln(2))^2 + 1.0^2 )
         *            = sqrt( (1.6931471805599453)^2 + 1 )
         *            = sqrt( 2.866747374828135 + 1 )
         *            = sqrt( 3.866747374828135 )
         *            ≈ 1.96640468236529
         *
         * Doc 1 (T1001) vector components (relative to idf):
         *   w1(alpha) = 1 + ln(1) = 1.0
         *   w1(beta)  = 1 + ln(1) = 1.0
         *   ||v1||_2  = sqrt( 1.0^2 + 1.0^2 ) = sqrt(2) ≈ 1.4142135623730951
         *
         * Dot product (relative to idf^2):
         *   q . v1 = q(alpha) * w1(alpha) + q(beta) * w1(beta)
         *          = (1 + ln(2)) * 1.0 + 1.0 * 1.0
         *          = 2 + ln(2)
         *          ≈ 2.6931471805599453
         *
         * Expected Cosine Similarity (Sublinear TF):
         *   cos_sublinear = (2 + ln(2)) / (||q||_2 * ||v1||_2)
         *                 = (2 + ln(2)) / (sqrt(3.866747374828135) * sqrt(2))
         *                 = (2 + ln(2)) / sqrt(2 * ((1 + ln(2))^2 + 1))
         *                 ≈ 2.6931471805599453 / 2.7809161709424684
         *                 ≈ 0.9684388219443362
         *
         * Contrast with Linear TF (where weight is 2, not 1 + ln(2)):
         *   q_linear = [2, 1], ||q_linear|| = sqrt(5)
         *   dot_linear = 2 * 1 + 1 * 1 = 3
         *   cos_linear = 3 / (sqrt(5) * sqrt(2)) = 3 / sqrt(10) ≈ 0.9486832980505138
         */
        Technique doc1 = new Technique("T1001", "Alpha", "Beta", List.of("tactica"), false);
        Technique doc2 = new Technique("T1002", "Gamma", "Gamma", List.of("tacticb"), false);

        TfIdfRetriever retriever = new TfIdfRetriever(List.of(doc1, doc2));
        List<Prediction> predictions = retriever.rank("alpha alpha beta", 5);

        assertFalse(predictions.isEmpty());
        assertEquals("T1001", predictions.get(0).techniqueId());

        double ln2 = Math.log(2.0);
        double expectedSublinearCos = (2.0 + ln2) / Math.sqrt(2.0 * (Math.pow(1.0 + ln2, 2.0) + 1.0));
        double linearCos = 3.0 / Math.sqrt(10.0);

        assertEquals(expectedSublinearCos, predictions.get(0).score(), 1e-9);
        assertNotEquals(linearCos, predictions.get(0).score(), 1e-3);
    }

    @Test
    @DisplayName("A query made only of stopwords returns an empty list")
    void queryMadeOnlyOfStopwordsReturnsEmptyList() {
        TfIdfRetriever retriever = new TfIdfRetriever(List.of(t1059, t1078, t1082));
        List<Prediction> predictions = retriever.rank("the and of in on at by for with", 5);
        assertNotNull(predictions);
        assertTrue(predictions.isEmpty());
    }

    @Test
    @DisplayName("Zero-norm document scores 0 and is excluded from results")
    void zeroNormDocumentScoresZeroAndExcluded() {
        // Technique with only stopwords or blank text has zero document norm
        Technique zeroDoc = new Technique("T0000", "the", "and of in", List.of("discovery"), false);
        Technique validDoc = new Technique("T1001", "PowerShell", "PowerShell commands execution", List.of("execution"), false);

        TfIdfRetriever retriever = new TfIdfRetriever(List.of(zeroDoc, validDoc));
        List<Prediction> predictions = retriever.rank("the and of in", 5);
        assertTrue(predictions.isEmpty(), "Zero-norm query over zero-norm doc yields empty");

        List<Prediction> validPreds = retriever.rank("powershell commands", 5);
        assertEquals(1, validPreds.size());
        assertEquals("T1001", validPreds.get(0).techniqueId());
    }

    @Test
    @DisplayName("Hand-calculated test on a 3-document toy corpus asserting cosine within 1e-9")
    void handCalculatedToyCorpusCosine() {
        /*
         * HAND-CALCULATED ARITHMETIC VERIFICATION (Calculated on paper):
         *
         * Corpus: N = 3 documents
         * Doc 1 (T1001):
         *   Name: "Alpha", Description: "Alpha Beta"
         *   Combined doc text: "Alpha Alpha Beta"
         *   Tokens: alpha (tf = 2), beta (tf = 1)
         *
         * Doc 2 (T1002):
         *   Name: "Beta", Description: "Gamma"
         *   Combined doc text: "Beta Gamma"
         *   Tokens: beta (tf = 1), gamma (tf = 1)
         *
         * Doc 3 (T1003):
         *   Name: "Gamma", Description: "Gamma"
         *   Combined doc text: "Gamma Gamma"
         *   Tokens: gamma (tf = 2)
         *
         * Vocabulary & Document Frequencies (df):
         *   N = 3
         *   df(alpha) = 1 (Doc 1)
         *   df(beta)  = 2 (Doc 1, Doc 2)
         *   df(gamma) = 2 (Doc 2, Doc 3)
         *
         * Smoothed IDF Formula: idf(t) = ln((1 + N) / (1 + df(t))) + 1
         *   1 + N = 4
         *   Let a = idf(alpha) = ln(4 / (1 + 1)) + 1 = ln(2) + 1 ≈ 1.69314718055995
         *   Let b = idf(beta)  = ln(4 / (1 + 2)) + 1 = ln(4/3) + 1 ≈ 1.28768207245178
         *       b = idf(gamma) = ln(4 / (1 + 2)) + 1 = ln(4/3) + 1 ≈ 1.28768207245178
         *
         * Sublinear TF Formula: tf_sub = 1 + ln(tf)
         * Document TF-IDF Weight: w(t, d) = (1 + ln(tf)) * idf(t)
         *
         * Query: "Alpha Beta Gamma"
         *   tf_q(alpha) = 1 => q(alpha) = (1 + ln(1)) * a = a
         *   tf_q(beta)  = 1 => q(beta)  = (1 + ln(1)) * b = b
         *   tf_q(gamma) = 1 => q(gamma) = (1 + ln(1)) * b = b
         *   ||q||_2 = sqrt( q(alpha)^2 + q(beta)^2 + q(gamma)^2 )
         *           = sqrt( a^2 + 2 * b^2 )
         *           ≈ sqrt( 2.866747375 + 2 * 1.658125120 )
         *           ≈ sqrt( 6.182997614 )
         *           ≈ 2.4865634145
         *
         * Document Vectors & Cosine Similarities:
         *
         * 1) Doc 1 (T1001):
         *   w1(alpha) = (1 + ln(2)) * a = a * a = a^2
         *   w1(beta)  = (1 + ln(1)) * b = 1 * b = b
         *   ||v1||_2  = sqrt( (a^2)^2 + b^2 ) = sqrt( a^4 + b^2 )
         *             ≈ sqrt( (1.69314718)^4 + (1.28768207)^2 )
         *             ≈ sqrt( 8.218240515 + 1.658125120 )
         *             ≈ sqrt( 9.876365635 )
         *             ≈ 3.142668553
         *   q . v1    = q(alpha) * w1(alpha) + q(beta) * w1(beta)
         *             = a * a^2 + b * b
         *             = a^3 + b^2
         *             ≈ 4.853825235 + 1.658125120
         *             ≈ 6.511950355
         *   Denominator = ||q||_2 * ||v1||_2 = sqrt(a^2 + 2*b^2) * sqrt(a^4 + b^2)
         *               ≈ 2.486563415 * 3.142668553 ≈ 7.814444647
         *   cosine(q, d1) = (a^3 + b^2) / (||q||_2 * sqrt(a^4 + b^2))
         *                 ≈ 6.511950355 / 7.814444647
         *                 ≈ 0.833322219202307
         *
         * 2) Doc 2 (T1002):
         *   w2(beta)  = 1 * b = b
         *   w2(gamma) = 1 * b = b
         *   ||v2||_2  = sqrt( b^2 + b^2 ) = sqrt(2) * b
         *   q . v2    = b * b + b * b = 2 * b^2
         *   cosine(q, d2) = (2 * b^2) / (||q||_2 * sqrt(2) * b)
         *                 = sqrt(2) * b / ||q||_2
         *                 ≈ sqrt(2) * 1.287682072 / 2.486563415
         *                 ≈ 0.732359142842215
         *
         * 3) Doc 3 (T1003):
         *   w3(gamma) = (1 + ln(2)) * b = a * b
         *   ||v3||_2  = a * b
         *   q . v3    = q(gamma) * w3(gamma) = b * (a * b) = a * b^2
         *   cosine(q, d3) = (a * b^2) / (||q||_2 * (a * b))
         *                 = b / ||q||_2
         *                 ≈ 1.287682072 / 2.486563415
         *                 ≈ 0.517856116167697
         *
         * Ranking expectation:
         *   Rank 1: T1001 with cosine ≈ 0.833322219202307
         *   Rank 2: T1002 with cosine ≈ 0.732359142842215
         *   Rank 3: T1003 with cosine ≈ 0.517856116167697
         */
        Technique doc1 = new Technique("T1001", "Alpha", "Alpha Beta", List.of("tactica"), false);
        Technique doc2 = new Technique("T1002", "Beta", "Gamma", List.of("tacticb"), false);
        Technique doc3 = new Technique("T1003", "Gamma", "Gamma", List.of("tacticc"), false);

        TfIdfRetriever retriever = new TfIdfRetriever(List.of(doc1, doc2, doc3));
        List<Prediction> predictions = retriever.rank("Alpha Beta Gamma", 5);

        assertEquals(3, predictions.size());

        // Closed-form mathematical expressions:
        // a = 1 + ln(2), b = 1 + ln(4/3)
        // |q| = sqrt(a^2 + 2*b^2)
        // T1001 = (a^3 + b^2) / (|q| * sqrt(a^4 + b^2))
        // T1002 = sqrt(2) * b / |q|
        // T1003 = b / |q|
        double a = 1.0 + Math.log(2.0);
        double b = 1.0 + Math.log(4.0 / 3.0);
        double qNorm = Math.sqrt(a * a + 2.0 * b * b);

        double expectedCos1 = (a * a * a + b * b) / (qNorm * Math.sqrt(Math.pow(a, 4.0) + b * b));
        double expectedCos2 = (Math.sqrt(2.0) * b) / qNorm;
        double expectedCos3 = b / qNorm;

        // Verify Rank 1: T1001
        assertEquals("T1001", predictions.get(0).techniqueId());
        assertEquals(expectedCos1, predictions.get(0).score(), 1e-9);

        // Verify Rank 2: T1002
        assertEquals("T1002", predictions.get(1).techniqueId());
        assertEquals(expectedCos2, predictions.get(1).score(), 1e-9);

        // Verify Rank 3: T1003
        assertEquals("T1003", predictions.get(2).techniqueId());
        assertEquals(expectedCos3, predictions.get(2).score(), 1e-9);
    }
}

