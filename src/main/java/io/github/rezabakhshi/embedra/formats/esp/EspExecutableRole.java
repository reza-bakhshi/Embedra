package io.github.rezabakhshi.embedra.formats.esp;

/** Role of an independently loadable ESP image extracted from physical flash. */
public enum EspExecutableRole {
    BOOTLOADER,
    FACTORY,
    OTA,
    APPLICATION
}
