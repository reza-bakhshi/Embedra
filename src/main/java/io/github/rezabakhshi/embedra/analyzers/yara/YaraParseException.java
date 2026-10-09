package io.github.rezabakhshi.embedra.analyzers.yara;

/**
 * Exception thrown when a YARA rule fails to parse.
 */
public final class YaraParseException extends Exception {
    private static final long serialVersionUID = 1L;

    private final int line;

    private final int column;

    public YaraParseException(String message, int line, int column) {
        super("YARA parse error at line " + line + ", column " + column + ": " + message);
        this.line = line;
        this.column = column;
    }

    public YaraParseException(String message, int line, int column, Throwable cause) {
        super("YARA parse error at line " + line + ", column " + column + ": " + message, cause);
        this.line = line;
        this.column = column;
    }

    public int line() {
        return line;
    }

    public int column() {
        return column;
    }
}
