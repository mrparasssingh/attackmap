package com.team.attackmap.data;

/**
 * Unchecked exception thrown when PDF document loading or text extraction fails.
 */
public class PdfExtractionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a PdfExtractionException with an error message.
     *
     * @param message Detailed error explanation.
     */
    public PdfExtractionException(String message) {
        super(message);
    }

    /**
     * Constructs a PdfExtractionException with an error message and causing exception.
     *
     * @param message Detailed error explanation.
     * @param cause   Underlying root cause exception.
     */
    public PdfExtractionException(String message, Throwable cause) {
        super(message, cause);
    }
}
