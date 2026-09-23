package io.github.rezabakhshi.embedra.formats.esp;

/** Vendor-defined OTA image state, preserving unknown numeric values separately. */
public enum EspOtaImageState {
    NEW,
    PENDING_VERIFY,
    VALID,
    INVALID,
    ABORTED,
    UNDEFINED,
    UNKNOWN
}
