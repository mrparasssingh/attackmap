package com.team.attackmap.retrieval;

import com.team.attackmap.model.Prediction;
import com.team.attackmap.model.Technique;
import com.team.attackmap.util.Config;
import com.team.attackmap.util.TextTokenizer;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Keyword- and regular-expression-based baseline retriever for MITRE ATT&amp;CK techniques.
 * <p>
 * Implements the {@link Retriever} interface. The index is constructed once during instantiation
 * and is fully immutable and thread-safe afterwards.
 * </p>
 *
 * <h3>Scoring Formula</h3>
 * <p>
 * Let {@code Q} be the set of unique query tokens extracted from the input sentence using
 * {@link TextTokenizer} (a repeated word in the sentence counts once). For each indexed technique
 * {@code t}:
 * </p>
 * <pre>
 * score(t) = sum_{q in Q} [
 *              (NAME_WEIGHT if q is in NameTokens(t) else 0.0)
 *            + (DESC_WEIGHT if q is in DescTokens(t) else 0.0)
 *            ]
 *          + (ID_MATCH_BONUS if sentence contains technique ID t.id() else 0.0)
 * </pre>
 * <ul>
 *   <li>{@code NAME_WEIGHT = 3.0} (defined in {@link Config#NAME_WEIGHT})</li>
 *   <li>{@code DESC_WEIGHT = 1.0} (defined in {@link Config#DESC_WEIGHT})</li>
 *   <li>{@code ID_MATCH_BONUS = 100.0} (defined in {@link Config#ID_MATCH_BONUS})</li>
 * </ul>
 * <p>
 * If a token is present in both the technique's name and description, it contributes both weights
 * ({@code 3.0 + 1.0 = 4.0}).
 * </p>
 * <p>
 * The explicit-ID regex bonus searches the input sentence for technique IDs matching
 * {@code \bT\d{4}(\.\d{3})?\b} (case-sensitive on the uppercase letter 'T'). If an extracted ID
 * exactly matches an indexed technique's ID, that technique receives the {@code ID_MATCH_BONUS}.
 * IDs mentioned in the sentence that do not exist in the indexed technique list are ignored without error.
 * A mention of a sub-technique (e.g., "T1059.001") bonuses only that sub-technique and does not boost
 * its parent ("T1059"). Conversely, a mention of "T1059" bonuses only the parent and does not boost
 * any sub-techniques.
 * </p>
 *
 * <h3>Ranking Contract</h3>
 * <ul>
 *   <li>Only techniques with {@code score > 0.0} are returned. Zero-score techniques are omitted.</li>
 *   <li>Predictions are sorted in descending order of score. Ties are broken by ascending technique ID
 *       using plain {@link String#compareTo(String)}.</li>
 *   <li>Note on score comparison: Because all weights ({@code 3.0}, {@code 1.0}, {@code 100.0}) are
 *       exact binary-friendly floating-point numbers, accumulated scores are exact integers represented as
 *       doubles; tie detection relies on this exactness and ordering is performed using {@link Double#compare(double, double)}.</li>
 *   <li>Returns at most {@code k} results.</li>
 *   <li>If {@code sentence} is null or blank, or if {@code k <= 0}, an empty unmodifiable list is returned.</li>
 *   <li>Never returns null. The returned list is unmodifiable.</li>
 *   <li>Each {@link Prediction} contains the technique ID, the calculated score, and the unmodified input sentence as evidence.</li>
 *   <li>Deterministic: the same input sentence and {@code k} will always produce identical output.</li>
 * </ul>
 */
public class KeywordRetriever implements Retriever {

    private static final Pattern TECHNIQUE_ID_PATTERN = Pattern.compile("\\bT\\d{4}(?:\\.\\d{3})?\\b");

    private final List<IndexedTechnique> indexedTechniques;
    private final Set<String> knownTechniqueIds;
    private final TextTokenizer tokenizer;

    /**
     * Internal representation of a pre-tokenized technique for fast query scoring.
     */
    private static final class IndexedTechnique {
        private final Technique technique;
        private final Set<String> nameTokens;
        private final Set<String> descTokens;

        private IndexedTechnique(Technique technique, Set<String> nameTokens, Set<String> descTokens) {
            this.technique = technique;
            this.nameTokens = nameTokens;
            this.descTokens = descTokens;
        }
    }

    /**
     * Constructs a KeywordRetriever with the provided list of techniques.
     * Pre-tokenizes technique names and descriptions into an immutable index.
     *
     * @param techniques The list of candidate techniques to index (defensively copied, cannot be null).
     * @throws NullPointerException If {@code techniques} is null.
     */
    public KeywordRetriever(List<Technique> techniques) {
        Objects.requireNonNull(techniques, "Technique list cannot be null");
        this.tokenizer = new TextTokenizer();

        List<Technique> defensiveCopy = List.copyOf(techniques);
        List<IndexedTechnique> indexed = new ArrayList<>(defensiveCopy.size());
        Set<String> ids = new HashSet<>(defensiveCopy.size());

        for (Technique tech : defensiveCopy) {
            Set<String> nameTokens = tokenizer.tokenizeToSet(tech.name());
            Set<String> descTokens = tokenizer.tokenizeToSet(tech.description());
            indexed.add(new IndexedTechnique(tech, nameTokens, descTokens));
            ids.add(tech.id());
        }

        this.indexedTechniques = Collections.unmodifiableList(indexed);
        this.knownTechniqueIds = Collections.unmodifiableSet(ids);
    }

    /**
     * Ranks candidate MITRE ATT&amp;CK techniques for a given threat sentence.
     *
     * @param sentence The sentence extracted from a threat report describing adversary behavior.
     * @param k        The maximum number of predictions to return (must be positive).
     * @return An unmodifiable List of ranked predictions with score &gt; 0, sorted descending by score
     *         and ascending by technique ID on ties. Returns an empty list if sentence is null/blank or k &lt;= 0.
     */
    @Override
    public List<Prediction> rank(String sentence, int k) {
        if (sentence == null || sentence.isBlank() || k <= 0 || indexedTechniques.isEmpty()) {
            return Collections.emptyList();
        }

        // 1. Extract query tokens (Q is a unique set)
        Set<String> queryTokens = tokenizer.tokenizeToSet(sentence);

        // 2. Extract explicit MITRE technique IDs from sentence
        Set<String> explicitIdsInSentence = extractExplicitTechniqueIds(sentence);

        // 3. Score each technique
        List<Prediction> candidatePredictions = new ArrayList<>();

        for (IndexedTechnique indexed : indexedTechniques) {
            double score = 0.0;
            Technique tech = indexed.technique;

            // Keyword scoring over Q
            for (String q : queryTokens) {
                if (indexed.nameTokens.contains(q)) {
                    score += Config.NAME_WEIGHT;
                }
                if (indexed.descTokens.contains(q)) {
                    score += Config.DESC_WEIGHT;
                }
            }

            // Explicit technique ID regex bonus
            if (explicitIdsInSentence.contains(tech.id())) {
                score += Config.ID_MATCH_BONUS;
            }

            // Only techniques with score > 0 are retained
            if (score > 0.0) {
                candidatePredictions.add(new Prediction(tech.id(), score, sentence));
            }
        }

        if (candidatePredictions.isEmpty()) {
            return Collections.emptyList();
        }

        // 4. Sort: descending by score, ascending by technique ID
        candidatePredictions.sort((p1, p2) -> {
            int scoreCompare = Double.compare(p2.score(), p1.score());
            if (scoreCompare != 0) {
                return scoreCompare;
            }
            return p1.techniqueId().compareTo(p2.techniqueId());
        });

        // 5. Truncate to at most k entries
        int limit = Math.min(candidatePredictions.size(), k);
        List<Prediction> topK = candidatePredictions.subList(0, limit);

        return Collections.unmodifiableList(new ArrayList<>(topK));
    }

    /**
     * Finds explicit technique IDs matching \bT\d{4}(\.\d{3})?\b in the raw sentence
     * that belong to the set of indexed techniques.
     */
    private Set<String> extractExplicitTechniqueIds(String sentence) {
        Matcher matcher = TECHNIQUE_ID_PATTERN.matcher(sentence);
        Set<String> matchedIds = new HashSet<>();
        while (matcher.find()) {
            String candidateId = matcher.group();
            if (knownTechniqueIds.contains(candidateId)) {
                matchedIds.add(candidateId);
            }
        }
        return matchedIds;
    }
}

