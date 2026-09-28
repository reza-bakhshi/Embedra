package io.github.rezabakhshi.embedra.formats.esp8266;

/** Structurally distinct ESP8266 ROM and software-bootloader image versions. */
public enum Esp8266ImageVersion {
    VERSION_1(0xe9),
    VERSION_2(0xea);

    private final int magic;

    Esp8266ImageVersion(int magic) {
        this.magic = magic;
    }

    public int magic() {
        return magic;
    }
}
