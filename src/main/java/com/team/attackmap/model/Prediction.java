package com.team.attackmap.model;

import java.util.Objects;

/**
 * Represents a technique prediction produced by a retriever for a given threat sentence.
 *
 * @param techniqueId      The predicted MITRE ATT&CK technique ID (e.g., "T1059.001").
 * @param score            The confidence or similarity score assigned by the retriever model.
 * @param evidenceSentence The supporting sentence from the threat report serving as evidence.
 */
public record Prediction(
        String techniqueId,
        double score,
        String evidenceSentence
) {

    /**
     * Compact constructor validating required prediction attributes.
     */
    public Prediction {
        Objects.requireNonNull(techniqueId, "techniqueId cannot be null");
        Objects.requireNonNull(evidenceSentence, "evidenceSentence cannot be null");
    }
}
