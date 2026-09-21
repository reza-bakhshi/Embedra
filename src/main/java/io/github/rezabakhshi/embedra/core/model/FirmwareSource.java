package io.github.rezabakhshi.embedra.core.model;

/** Relationship between an execution unit and supplied firmware bytes. */
public enum FirmwareSource {
    SHARED_IMAGE,
    INDEPENDENT_IMAGE,
    ROM,
    NOT_APPLICABLE,
    UNKNOWN
}
