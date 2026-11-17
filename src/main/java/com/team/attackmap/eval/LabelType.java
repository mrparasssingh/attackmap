package com.team.attackmap.eval;

/**
 * Label type for a gold-standard annotation sentence.
 * <ul>
 *   <li>{@code EXPLICIT} — technique ID is stated verbatim in the sentence.</li>
 *   <li>{@code AMBIGUOUS} — sentence could map to multiple techniques.</li>
 *   <li>{@code INFERRED} — technique was inferred by the annotator from context.</li>
 *   <li>{@code NONE} — no technique applies to this sentence.</li>
 * </ul>
 */
public enum LabelType {
    EXPLICIT,
    AMBIGUOUS,
    INFERRED,
    NONE
}

