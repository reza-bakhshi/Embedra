package io.github.rezabakhshi.embedra.formats.esp;

/** Explicit handler identity for every T021 partition category. */
public enum EspPartitionHandlerKind {
    OTA_STATE,
    NVS,
    NVS_KEYS,
    PHY,
    COREDUMP,
    FAT,
    SPIFFS,
    LITTLEFS,
    CUSTOM,
    INACTIVE_APPLICATION,
    ENCRYPTED
}
