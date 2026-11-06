package com.team.attackmap.model;

import com.team.attackmap.util.Config;

import java.util.Objects;

/**
 * Represents a single extracted sentence from a threat report.
 *
 * @param reportId Unique identifier of the source threat report (non-null, non-blank, stored trimmed).
 * @param index    0-based sequential index of the sentence within the report (must be &gt;= 0).
 * @param text     Extracted sentence text content (non-null, non-blank, stored trimmed).
 */
public record Sentence(
        String reportId,
        int index,
        String text
) {

    /**
     * Compact constructor validating invariants and trimming string attributes.
     *
     * @param reportId Unique identifier of the source threat report.
     * @param index    0-based sequential index within the report.
     * @param text     Extracted sentence text content.
     * @throws NullPointerException     If {@code reportId} or {@code text} is null.
     * @throws IllegalArgumentException If {@code reportId} or {@code text} is blank,
     *                                  or if {@code index} is less than {@link Config#MIN_SENTENCE_INDEX}.
     */
    public Sentence {
        Objects.requireNonNull(reportId, "reportId cannot be null");
        Objects.requireNonNull(text, "text cannot be null");

        reportId = reportId.trim();
        text = text.trim();

        if (reportId.isEmpty()) {
            throw new IllegalArgumentException("reportId cannot be blank");
        }
        if (text.isEmpty()) {
            throw new IllegalArgumentException("text cannot be blank");
        }
        if (index < Config.MIN_SENTENCE_INDEX) {
            throw new IllegalArgumentException("index must be >= " + Config.MIN_SENTENCE_INDEX + ", got: " + index);
        }
    }
}
