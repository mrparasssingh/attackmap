package com.team.attackmap.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable representation of a MITRE ATT&CK technique or sub-technique.
 *
 * @param id             The unique MITRE ATT&CK technique ID (e.g., "T1059", "T1059.001").
 * @param name           The human-readable technique name (e.g., "Command and Scripting Interpreter").
 * @param description    The technical description of the technique (guaranteed non-null, defaults to empty string).
 * @param tactics        The list of tactics this technique maps to, represented as lowercase
 *                       kill-chain short names (e.g., "defense-evasion", "lateral-movement", "execution").
 * @param isSubTechnique True if this entry represents a sub-technique (e.g., "T1059.001"); false if a parent technique.
 */
public record Technique(
        String id,
        String name,
        String description,
        List<String> tactics,
        boolean isSubTechnique
) {

    /**
     * Compact constructor validating invariants and establishing defensive immutability.
     *
     * @param id             The unique MITRE ATT&CK technique ID (required).
     * @param name           The human-readable technique name (required).
     * @param description    The description text (nulls converted to empty string).
     * @param tactics        The list of lowercase kill-chain tactic short names (defensively copied).
     * @param isSubTechnique Whether the technique is a sub-technique.
     */
    public Technique {
        Objects.requireNonNull(id, "Technique id cannot be null");
        Objects.requireNonNull(name, "Technique name cannot be null");
        if (description == null) {
            description = "";
        }
        if (tactics == null) {
            tactics = Collections.emptyList();
        } else {
            tactics = List.copyOf(tactics);
        }
    }
}
