package com.team.attackmap.eval;

/**
 * Unchecked exception thrown when a gold-standard CSV file has structural
 * or semantic errors. Carries the 1-based line number of the offending row.
 */
public class GoldFormatException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int lineNumber;

    /**
     * @param message    Human-readable description of the format violation.
     * @param lineNumber 1-based line number in the CSV file where the error was detected.
     */
    public GoldFormatException(String message, int lineNumber) {
        super("Line " + lineNumber + ": " + message);
        this.lineNumber = lineNumber;
    }

    /**
     * @param message    Human-readable description of the format violation.
     * @param lineNumber 1-based line number in the CSV file where the error was detected.
     * @param cause      The underlying exception, if any.
     */
    public GoldFormatException(String message, int lineNumber, Throwable cause) {
        super("Line " + lineNumber + ": " + message, cause);
        this.lineNumber = lineNumber;
    }

    /**
     * Returns the 1-based line number where the error was detected.
     *
     * @return line number (1-based).
     */
    public int getLineNumber() {
        return lineNumber;
    }
}

