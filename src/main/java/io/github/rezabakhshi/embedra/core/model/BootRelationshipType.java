package io.github.rezabakhshi.embedra.core.model;

/** Boot-order or reset-control relation between processor nodes. */
public enum BootRelationshipType {
    BOOTS,
    RELEASES_FROM_RESET,
    DEPENDS_ON,
    ALTERNATIVE_TO
}
