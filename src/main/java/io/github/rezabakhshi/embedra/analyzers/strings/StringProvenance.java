package io.github.rezabakhshi.embedra.analyzers.strings;

/** Provenance differentiating static string literals from stack-constructed strings. */
public enum StringProvenance {
    STATIC_LITERAL,
    STACK_CONSTRUCTED
}
