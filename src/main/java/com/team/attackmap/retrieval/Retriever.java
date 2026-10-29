package com.team.attackmap.retrieval;

import com.team.attackmap.model.Prediction;

import java.util.List;

/**
 * Common retrieval interface for technique identification models.
 * Reads threat sentences and ranks candidate MITRE ATT&CK techniques by similarity or relevance.
 */
public interface Retriever {

    /**
     * Ranks candidate MITRE ATT&CK techniques for a given evidence sentence.
     *
     * @param sentence The sentence extracted from a threat report describing attacker behavior.
     * @param k        The maximum number of top predictions to return (must be positive).
     * @return A ranked list of predictions in descending score order, containing at most k entries.
     */
    List<Prediction> rank(String sentence, int k);
}
