package io.github.rezabakhshi.embedra.targets.rp.binaryinfo;

/**
 * Pico SDK binary info marker constants, namespace tags, entry types, and well-known IDs.
 */
public final class RpBinaryInfoMarker {

    public static final long MARKER_START = 0x7188dac3L;

    public static final long MARKER_END = 0xe71aa39aL;

    /** Namespace tag 'RP' = 'R' | ('P' << 8) = 0x5052. */
    public static final int TAG_RASPBERRY_PI = 0x5052;

    // Entry Types
    public static final int TYPE_RAW_DATA = 1;

    public static final int TYPE_SIZED_DATA = 2;

    public static final int TYPE_BINARY_INFO_LIST_ZERO_TERMINATED = 3;

    public static final int TYPE_BSON = 4;

    public static final int TYPE_ID_AND_INT = 5;

    public static final int TYPE_ID_AND_STRING = 6;

    public static final int TYPE_BLOCK_DEVICE = 7;

    public static final int TYPE_PINS_WITH_FUNC = 8;

    public static final int TYPE_PINS_WITH_NAME = 9;

    public static final int TYPE_NAMED_GROUP = 10;

    public static final int TYPE_PTR_INT32_WITH_NAME = 11;

    public static final int TYPE_PTR_STRING_WITH_NAME = 12;

    public static final int TYPE_PINS64_WITH_FUNC = 13;

    public static final int TYPE_PINS64_WITH_NAME = 14;

    // Raspberry Pi Well-Known IDs
    public static final long ID_RP_PROGRAM_NAME = 0x02031c86L;

    public static final long ID_RP_PROGRAM_VERSION_STRING = 0x11a9bc3aL;

    public static final long ID_RP_PROGRAM_BUILD_DATE_STRING = 0x9da22254L;

    public static final long ID_RP_BINARY_END = 0x68f465deL;

    public static final long ID_RP_PROGRAM_URL = 0x1856239aL;

    public static final long ID_RP_PROGRAM_DESCRIPTION = 0xb6a07c19L;

    public static final long ID_RP_PROGRAM_FEATURE = 0xa1f4b453L;

    public static final long ID_RP_PROGRAM_BUILD_ATTRIBUTE = 0x4275f0d3L;

    public static final long ID_RP_SDK_VERSION = 0x5360b3abL;

    public static final long ID_RP_PICO_BOARD = 0xb63cffbbL;

    public static final long ID_RP_BOOT2_NAME = 0x7f8882e1L;

    private RpBinaryInfoMarker() {
    }
}
