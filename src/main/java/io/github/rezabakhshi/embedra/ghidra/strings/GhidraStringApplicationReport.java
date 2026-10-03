package io.github.rezabakhshi.embedra.ghidra.strings;

/**
 * Summary report of string annotations applied to a Ghidra program.
 */
public record GhidraStringApplicationReport(
        int staticStringsCount,
        int stackStringsCount,
        int asciiCount,
        int utf8Count,
        int utf16LeCount,
        int utf16BeCount,
        int pascalCount,
        int bookmarksCreated,
        int commentsCreated) {

    public int totalStringsCount() {
        return staticStringsCount + stackStringsCount;
    }
}
