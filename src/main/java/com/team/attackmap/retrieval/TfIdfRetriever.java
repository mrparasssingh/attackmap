package com.team.attackmap.retrieval;

import com.team.attackmap.model.Prediction;
import com.team.attackmap.model.Technique;
import com.team.attackmap.util.Config;
import com.team.attackmap.util.TextTokenizer;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Term Frequency-Inverse Document Frequency (TF-IDF) retriever for MITRE ATT&amp;CK techniques.
 * <p>
 * Implements the {@link Retriever} interface. The vocabulary and IDF weights are fitted exclusively
 * on candidate technique documents at index construction time, never on report sentences. The index
 * is thread-safe and immutable after construction.
 * </p>
 *
 * <h3>Mathematical Formulation</h3>
 * <h4>1. Document Representation and Vocabulary</h4>
 * <p>
 * Each technique {@code tech} defines a document formed by concatenating its name and description:
 * {@code doc = tech.name() + " " + tech.description()}. Tokens are extracted using {@link TextTokenizer}.
 * Let {@code N} be the total number of technique documents in the corpus ({@code N = techniques.size()}).
 * For each term {@code t} in the vocabulary, let {@code df(t)} be the document frequency (the number of
 * technique documents in which term {@code t} occurs with count &ge; 1).
 * </p>
 *
 * <h4>2. Smoothed Inverse Document Frequency (IDF)</h4>
 * <p>
 * The IDF weight for term {@code t} is calculated as:
 * </p>
 * <pre>
 * idf(t) = ln((1 + N) / (1 + df(t))) + 1
 * </pre>
 * <p>
 * Tokens that do not appear in any technique document are out-of-vocabulary and are ignored.
 * </p>
 *
 * <h4>3. Sublinear Term Frequency (TF)</h4>
 * <p>
 * For a term {@code t} with raw occurrence frequency {@code tf &ge; 1} in a document or query:
 * </p>
 * <pre>
 * tf_sub(t) = 1 + ln(tf)
 * </pre>
 * <p>
 * If {@code tf == 0}, the term weight is 0.
 * </p>
 *
 * <h4>4. TF-IDF Vectors and L2 Normalization</h4>
 * <p>
 * For each term {@code t} present in document {@code d} or query {@code q}, the unnormalized weight is:
 * </p>
 * <pre>
 * w(t) = tf_sub(t) * idf(t) = (1 + ln(tf)) * (ln((1 + N) / (1 + df(t))) + 1)
 * </pre>
 * <p>
 * Each vector is normalized by its Euclidean (L2) norm:
 * </p>
 * <pre>
 * ||v||_2 = sqrt( sum_{t} (w(t))^2 )
 * v_hat(t) = w(t) / ||v||_2   (if ||v||_2 &gt; 0, else 0)
 * </pre>
 * <p>
 * If a query or document has zero norm (e.g., contains only stopwords or out-of-vocabulary terms),
 * its cosine similarity is strictly 0.0, avoiding division by zero or NaN.
 * </p>
 *
 * <h4>5. Cosine Similarity and Scoring</h4>
 * <p>
 * The base similarity score between query vector {@code q_hat} and technique vector {@code d_hat} is
 * their dot product:
 * </p>
 * <pre>
 * cosine(q_hat, d_hat) = sum_{t} (q_hat(t) * d_hat(t))
 * </pre>
 * <p>
 * The final score includes an explicit technique ID regex match bonus:
 * </p>
 * <pre>
 * score(tech) = cosine(q_hat, d_hat)
 *             + (ID_MATCH_BONUS if sentence contains tech.id() else 0.0)
 * </pre>
 * <ul>
 *   <li>{@code ID_MATCH_BONUS = 100.0} (defined in {@link Config#ID_MATCH_BONUS}).</li>
 *   <li>Explicit IDs match {@code \bT\d{4}(?:\.\d{3})?\b} (case-sensitive on the uppercase 'T').</li>
 *   <li>Only IDs belonging to indexed techniques receive the bonus; sub-technique IDs bonus only that
 *       sub-technique and do not boost the parent.</li>
 * </ul>
 *
 * <h3>Ranking Contract</h3>
 * <ul>
 *   <li>Only techniques with {@code score > 0.0} are returned.</li>
 *   <li>Predictions are sorted descending by score; ties are broken by ascending technique ID.</li>
 *   <li>Returns at most {@code k} predictions in an unmodifiable list.</li>
 *   <li>If {@code sentence} is null or blank, or if {@code k <= 0}, returns an empty list.</li>
 *   <li>Each {@link Prediction} retains the unmodified input sentence as {@code evidenceSentence}.</li>
 *   <li>Never returns null and produces deterministic results.</li>
 * </ul>
 */
public class TfIdfRetriever implements Retriever {

    private static final Pattern TECHNIQUE_ID_PATTERN = Pattern.compile("\\bT\\d{4}(?:\\.\\d{3})?\\b");

    private final List<IndexedTechnique> indexedTechniques;
    private final Set<String> knownTechniqueIds;
    private final Map<String, Double> idfMap;
    private final TextTokenizer tokenizer;

    /**
     * Immutable pre-computed TF-IDF representation of an indexed technique.
     */
    private static final class IndexedTechnique {
        private final Technique technique;
        private final Map<String, Double> normalizedVector;
        private final double norm;

        private IndexedTechnique(Technique technique, Map<String, Double> normalizedVector, double norm) {
            this.technique = technique;
            this.normalizedVector = normalizedVector;
            this.norm = norm;
        }
    }

    /**
     * Constructs a {@code TfIdfRetriever} from candidate techniques.
     * Fits vocabulary and IDF weights on technique documents only.
     *
     * @param techniques Candidate MITRE ATT&amp;CK techniques to index (defensively copied, cannot be null).
     * @throws NullPointerException If {@code techniques} is null.
     */
    public TfIdfRetriever(List<Technique> techniques) {
        Objects.requireNonNull(techniques, "Technique list cannot be null");
        this.tokenizer = new TextTokenizer();

        List<Technique> defensiveCopy = List.copyOf(techniques);
        int totalDocs = defensiveCopy.size();

        // 1. Tokenize each technique and count document frequencies (df)
        List<Map<String, Integer>> docTfMaps = new ArrayList<>(totalDocs);
        Map<String, Integer> dfCounts = new HashMap<>();
        Set<String> ids = new HashSet<>(totalDocs);

        for (Technique tech : defensiveCopy) {
            ids.add(tech.id());
            String docText = tech.name() + " " + tech.description();
            List<String> tokens = tokenizer.tokenize(docText);

            Map<String, Integer> tfMap = new HashMap<>();
            for (String token : tokens) {
                tfMap.merge(token, Config.ONE, Integer::sum);
            }
            docTfMaps.add(tfMap);

            for (String term : tfMap.keySet()) {
                dfCounts.merge(term, Config.ONE, Integer::sum);
            }
        }

        // 2. Compute smoothed IDF: ln((1 + N) / (1 + df(t))) + 1
        Map<String, Double> computedIdf = new HashMap<>(dfCounts.size());
        for (Map.Entry<String, Integer> entry : dfCounts.entrySet()) {
            String term = entry.getKey();
            int df = entry.getValue();
            double numerator = (double) Config.ONE + (double) totalDocs;
            double denominator = (double) Config.ONE + (double) df;
            double idfVal = Math.log(numerator / denominator) + (double) Config.ONE;
            computedIdf.put(term, idfVal);
        }

        this.idfMap = Collections.unmodifiableMap(computedIdf);
        this.knownTechniqueIds = Collections.unmodifiableSet(ids);

        // 3. Compute L2-normalized vector for each technique document
        List<IndexedTechnique> indexed = new ArrayList<>(totalDocs);
        for (int i = Config.ZERO; i < totalDocs; i++) {
            Technique tech = defensiveCopy.get(i);
            Map<String, Integer> tfMap = docTfMaps.get(i);

            Map<String, Double> unnormalized = new HashMap<>(tfMap.size());
            double sumSquares = (double) Config.ZERO;

            for (Map.Entry<String, Integer> entry : tfMap.entrySet()) {
                String term = entry.getKey();
                int tf = entry.getValue();
                double tfWeight = (double) Config.ONE + Math.log(tf);
                Double termIdf = this.idfMap.get(term);
                double weight = (termIdf != null) ? (tfWeight * termIdf) : (double) Config.ZERO;

                unnormalized.put(term, weight);
                sumSquares += weight * weight;
            }

            double docNorm = Math.sqrt(sumSquares);
            Map<String, Double> normalized = new HashMap<>(unnormalized.size());
            if (docNorm > (double) Config.ZERO) {
                for (Map.Entry<String, Double> entry : unnormalized.entrySet()) {
                    normalized.put(entry.getKey(), entry.getValue() / docNorm);
                }
            }

            indexed.add(new IndexedTechnique(tech, Collections.unmodifiableMap(normalized), docNorm));
        }

        this.indexedTechniques = Collections.unmodifiableList(indexed);
    }

    /**
     * Ranks indexed techniques against a threat report sentence using TF-IDF cosine similarity
     * combined with explicit technique ID matching.
     *
     * @param sentence Threat report sentence describing adversary behavior.
     * @param k        Maximum number of predictions to return (must be positive).
     * @return An unmodifiable List of ranked predictions with score &gt; 0, sorted descending
     *         by score and ascending by technique ID on ties.
     */
    @Override
    public List<Prediction> rank(String sentence, int k) {
        if (sentence == null || sentence.isBlank() || k <= Config.ZERO || indexedTechniques.isEmpty()) {
            return Collections.emptyList();
        }

        // 1. Extract query tokens and retain only vocabulary terms
        List<String> rawTokens = tokenizer.tokenize(sentence);
        Map<String, Integer> queryTfMap = new HashMap<>();
        for (String token : rawTokens) {
            if (idfMap.containsKey(token)) {
                queryTfMap.merge(token, Config.ONE, Integer::sum);
            }
        }

        // 2. Compute L2-normalized query vector
        Map<String, Double> queryNormVector = new HashMap<>(queryTfMap.size());
        double querySumSquares = (double) Config.ZERO;
        Map<String, Double> queryUnnormalized = new HashMap<>(queryTfMap.size());

        for (Map.Entry<String, Integer> entry : queryTfMap.entrySet()) {
            String term = entry.getKey();
            int tf = entry.getValue();
            double tfWeight = (double) Config.ONE + Math.log(tf);
            double idf = idfMap.get(term);
            double weight = tfWeight * idf;

            queryUnnormalized.put(term, weight);
            querySumSquares += weight * weight;
        }

        double queryNorm = Math.sqrt(querySumSquares);
        if (queryNorm > (double) Config.ZERO) {
            for (Map.Entry<String, Double> entry : queryUnnormalized.entrySet()) {
                queryNormVector.put(entry.getKey(), entry.getValue() / queryNorm);
            }
        }

        // 3. Extract explicit technique IDs from sentence
        Set<String> explicitIdsInSentence = extractExplicitTechniqueIds(sentence);

        // 4. Score each technique: cosine similarity + explicit ID bonus
        List<Prediction> candidatePredictions = new ArrayList<>();

        for (IndexedTechnique indexed : indexedTechniques) {
            double cosine = (double) Config.ZERO;

            if (!queryNormVector.isEmpty() && indexed.norm > (double) Config.ZERO) {
                // Compute dot product iterating over smaller vector
                Map<String, Double> smaller = (queryNormVector.size() <= indexed.normalizedVector.size())
                        ? queryNormVector : indexed.normalizedVector;
                Map<String, Double> larger = (smaller == queryNormVector)
                        ? indexed.normalizedVector : queryNormVector;

                for (Map.Entry<String, Double> entry : smaller.entrySet()) {
                    Double matchingWeight = larger.get(entry.getKey());
                    if (matchingWeight != null) {
                        cosine += entry.getValue() * matchingWeight;
                    }
                }
            }

            double score = cosine;
            if (explicitIdsInSentence.contains(indexed.technique.id())) {
                score += Config.ID_MATCH_BONUS;
            }

            if (score > (double) Config.ZERO) {
                candidatePredictions.add(new Prediction(indexed.technique.id(), score, sentence));
            }
        }

        if (candidatePredictions.isEmpty()) {
            return Collections.emptyList();
        }

        // 5. Sort descending by score, ascending by technique ID
        candidatePredictions.sort((p1, p2) -> {
            int scoreCompare = Double.compare(p2.score(), p1.score());
            if (scoreCompare != Config.ZERO) {
                return scoreCompare;
            }
            return p1.techniqueId().compareTo(p2.techniqueId());
        });

        // 6. Truncate to at most k entries
        int limit = Math.min(candidatePredictions.size(), k);
        List<Prediction> topK = candidatePredictions.subList(Config.ZERO, limit);

        return Collections.unmodifiableList(new ArrayList<>(topK));
    }

    /**
     * Finds explicit technique IDs matching \bT\d{4}(?:\.\d{3})?\b in the sentence
     * that belong to the indexed technique set.
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
