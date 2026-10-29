package com.team.attackmap.data;

/**
 * Thrown when MITRE ATT&CK STIX JSON parsing fails due to syntax errors,
 * malformed STIX bundles, unreadable streams, or duplicate active technique IDs.
 */
public class StixParseException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new StixParseException with the specified detail message.
     *
     * @param message Detailed diagnostic message describing the parsing or structural failure.
     */
    public StixParseException(String message) {
        super(message);
    }

    /**
     * Constructs a new StixParseException with the specified detail message and root cause.
     *
     * @param message Detailed diagnostic message describing the parsing failure.
     * @param cause   The underlying exception (e.g. Jackson JsonProcessingException or IOException).
     */
    public StixParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
