package com.team.attackmap.eval;

import java.util.Objects;
import java.util.Set;

/**
 * An immutable gold-standard annotation record for a single sentence.
 *
 * @param reportId     Report identifier (non-null, non-blank).
 * @param sentenceId   0-based sentence index within the report (>= 0).
 * @param text         The original sentence text (non-null, non-blank).
 * @param techniqueIds Unmodifiable set of gold technique IDs (may be empty for NONE).
 * @param labelType    The annotation label type.
 */
public record GoldRecord(
        String reportId,
        int sentenceId,
        String text,
        Set<String> techniqueIds,
        LabelType labelType
) {

    /**
     * Compact constructor with validation.
     */
    public GoldRecord {
        Objects.requireNonNull(reportId, "reportId cannot be null");
        Objects.requireNonNull(text, "text cannot be null");
        Objects.requireNonNull(techniqueIds, "techniqueIds cannot be null");
        Objects.requireNonNull(labelType, "labelType cannot be null");
        if (reportId.isBlank()) {
            throw new IllegalArgumentException("reportId cannot be blank");
        }
        if (text.isBlank()) {
            throw new IllegalArgumentException("text cannot be blank");
        }
        if (sentenceId < 0) {
            throw new IllegalArgumentException("sentenceId must be >= 0");
        }
        techniqueIds = Set.copyOf(techniqueIds);
    }
}

