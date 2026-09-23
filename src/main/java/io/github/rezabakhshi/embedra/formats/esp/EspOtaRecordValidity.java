package io.github.rezabakhshi.embedra.formats.esp;

/** Integrity and boot eligibility of one redundant ESP OTA selection record. */
public enum EspOtaRecordValidity {
    VALID,
    ERASED,
    CRC_MISMATCH,
    REJECTED_STATE
}
