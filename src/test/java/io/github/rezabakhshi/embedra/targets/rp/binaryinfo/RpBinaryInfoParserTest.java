package io.github.rezabakhshi.embedra.targets.rp.binaryinfo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class RpBinaryInfoParserTest {

    private final RpBinaryInfoParser parser = new RpBinaryInfoParser();

    @Test
    void testParseValidBinaryInfoBlock() throws Exception {
        byte[] buffer = new byte[1024];
        ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
        long base = 0x10000000L;

        // Strings at offset 0x200..
        int strProgramName = 0x200;
        writeString(buffer, strProgramName, "BlinkyApp");
        int strVersion = 0x220;
        writeString(buffer, strVersion, "1.2.3");
        int strBuildDate = 0x240;
        writeString(buffer, strBuildDate, "2026-10-03");
        int strUrl = 0x260;
        writeString(buffer, strUrl, "https://raspberrypi.com");
        int strDesc = 0x280;
        writeString(buffer, strDesc, "Pico Blinky Sample");
        int strSdk = 0x2A0;
        writeString(buffer, strSdk, "2.0.0");
        int strBoard = 0x2C0;
        writeString(buffer, strBoard, "pico_w");
        int strBoot2 = 0x2E0;
        writeString(buffer, strBoot2, "w25q080");
        int strFeature = 0x300;
        writeString(buffer, strFeature, "USB_CDC");
        int strAttr = 0x320;
        writeString(buffer, strAttr, "Release");
        int strPinLed = 0x340;
        writeString(buffer, strPinLed, "On-board LED");
        int strBlockDev = 0x360;
        writeString(buffer, strBlockDev, "littlefs");

        // Entries at offset 0x80..
        // Entry 0: Program Name (Type 6, Tag 0x5052, ID 0x02031c86)
        int e0 = 0x80;
        bb.putShort(e0, (short) 6);
        bb.putShort(e0 + 2, (short) 0x5052);
        bb.putInt(e0 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_NAME);
        bb.putInt(e0 + 8, (int) (base + strProgramName));

        // Entry 1: Program Version
        int e1 = 0x90;
        bb.putShort(e1, (short) 6);
        bb.putShort(e1 + 2, (short) 0x5052);
        bb.putInt(e1 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_VERSION_STRING);
        bb.putInt(e1 + 8, (int) (base + strVersion));

        // Entry 2: Build Date
        int e2 = 0xA0;
        bb.putShort(e2, (short) 6);
        bb.putShort(e2 + 2, (short) 0x5052);
        bb.putInt(e2 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_BUILD_DATE_STRING);
        bb.putInt(e2 + 8, (int) (base + strBuildDate));

        // Entry 3: Program URL
        int e3 = 0xB0;
        bb.putShort(e3, (short) 6);
        bb.putShort(e3 + 2, (short) 0x5052);
        bb.putInt(e3 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_URL);
        bb.putInt(e3 + 8, (int) (base + strUrl));

        // Entry 4: Program Description
        int e4 = 0xC0;
        bb.putShort(e4, (short) 6);
        bb.putShort(e4 + 2, (short) 0x5052);
        bb.putInt(e4 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_DESCRIPTION);
        bb.putInt(e4 + 8, (int) (base + strDesc));

        // Entry 5: SDK Version
        int e5 = 0xD0;
        bb.putShort(e5, (short) 6);
        bb.putShort(e5 + 2, (short) 0x5052);
        bb.putInt(e5 + 4, (int) RpBinaryInfoMarker.ID_RP_SDK_VERSION);
        bb.putInt(e5 + 8, (int) (base + strSdk));

        // Entry 6: Pico Board
        int e6 = 0xE0;
        bb.putShort(e6, (short) 6);
        bb.putShort(e6 + 2, (short) 0x5052);
        bb.putInt(e6 + 4, (int) RpBinaryInfoMarker.ID_RP_PICO_BOARD);
        bb.putInt(e6 + 8, (int) (base + strBoard));

        // Entry 7: Boot2 Name
        int e7 = 0xF0;
        bb.putShort(e7, (short) 6);
        bb.putShort(e7 + 2, (short) 0x5052);
        bb.putInt(e7 + 4, (int) RpBinaryInfoMarker.ID_RP_BOOT2_NAME);
        bb.putInt(e7 + 8, (int) (base + strBoot2));

        // Entry 8: Feature
        int e8 = 0x100;
        bb.putShort(e8, (short) 6);
        bb.putShort(e8 + 2, (short) 0x5052);
        bb.putInt(e8 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_FEATURE);
        bb.putInt(e8 + 8, (int) (base + strFeature));

        // Entry 9: Build Attribute
        int e9 = 0x110;
        bb.putShort(e9, (short) 6);
        bb.putShort(e9 + 2, (short) 0x5052);
        bb.putInt(e9 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_BUILD_ATTRIBUTE);
        bb.putInt(e9 + 8, (int) (base + strAttr));

        // Entry 10: Binary End (ID_AND_INT)
        int e10 = 0x120;
        bb.putShort(e10, (short) 5);
        bb.putShort(e10 + 2, (short) 0x5052);
        bb.putInt(e10 + 4, (int) RpBinaryInfoMarker.ID_RP_BINARY_END);
        bb.putInt(e10 + 8, 0x10040000);

        // Entry 11: Pins With Name (Type 9)
        int e11 = 0x130;
        bb.putShort(e11, (short) 9);
        bb.putShort(e11 + 2, (short) 0x5052);
        bb.putInt(e11 + 4, 1 << 25); // GPIO 25
        bb.putInt(e11 + 8, (int) (base + strPinLed));

        // Entry 12: Block device (Type 7)
        int e12 = 0x140;
        bb.putShort(e12, (short) 7);
        bb.putShort(e12 + 2, (short) 0x5052);
        bb.putInt(e12 + 4, (int) (base + strBlockDev));
        bb.putInt(e12 + 8, 0x10100000);
        bb.putInt(e12 + 12, 0x100000);
        bb.putInt(e12 + 16, 0);
        bb.putShort(e12 + 20, (short) 3);

        // Table of pointers at offset 0x40..
        int tableStart = 0x40;
        int[] entries = {e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12};
        for (int i = 0; i < entries.length; i++) {
            bb.putInt(tableStart + i * 4, (int) (base + entries[i]));
        }
        int tableEnd = tableStart + entries.length * 4;

        // Binary Info Header at offset 0x10:
        // Word 0: 0x7188dac3 (START)
        // Word 1: entries_start
        // Word 2: entries_end
        // Word 3: data_cpy_table
        // Word 4: 0xe71aa39a (END)
        bb.putInt(0x10, (int) RpBinaryInfoMarker.MARKER_START);
        bb.putInt(0x14, (int) (base + tableStart));
        bb.putInt(0x18, (int) (base + tableEnd));
        bb.putInt(0x1C, 0);
        bb.putInt(0x20, (int) RpBinaryInfoMarker.MARKER_END);

        RpBinaryInfoResult result = parser.parse(buffer, base, ParserLimits.defaults(), CancellationToken.none());
        assertTrue(result.present());
        assertEquals(base + 0x10, result.headerAddress());
        assertEquals("BlinkyApp", result.programName().orElse(""));
        assertEquals("1.2.3", result.programVersion().orElse(""));
        assertEquals("2026-10-03", result.programBuildDate().orElse(""));
        assertEquals("https://raspberrypi.com", result.programUrl().orElse(""));
        assertEquals("Pico Blinky Sample", result.programDescription().orElse(""));
        assertEquals("2.0.0", result.sdkVersion().orElse(""));
        assertEquals("pico_w", result.picoBoard().orElse(""));
        assertEquals("w25q080", result.boot2Name().orElse(""));
        assertTrue(result.programFeatures().contains("USB_CDC"));
        assertTrue(result.buildAttributes().contains("Release"));
        assertEquals(0x10040000L, result.binaryEnd().orElse(0L));

        assertEquals(1, result.pins().size());
        RpBinaryInfoPin pin = result.pins().get(0);
        assertTrue(pin.coversPin(25));
        assertEquals("On-board LED", pin.label());

        assertEquals(1, result.blockDevices().size());
        assertEquals("littlefs", result.blockDevices().get(0).name());
        assertEquals(0x10100000L, result.blockDevices().get(0).address());
        assertEquals(0x100000L, result.blockDevices().get(0).size());
    }

    @Test
    void testParseCorruptedMarkersReturnsNotPresent() throws Exception {
        byte[] buffer = new byte[256];
        long base = 0x10000000L;

        // No markers
        RpBinaryInfoResult rEmpty = parser.parse(buffer, base, ParserLimits.defaults(), CancellationToken.none());
        assertFalse(rEmpty.present());

        // Start marker present, end marker mismatch
        ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0x10, (int) RpBinaryInfoMarker.MARKER_START);
        bb.putInt(0x14, (int) (base + 0x30));
        bb.putInt(0x18, (int) (base + 0x40));
        bb.putInt(0x1C, 0);
        bb.putInt(0x20, 0x12345678); // Wrong end marker
        RpBinaryInfoResult rBadEnd = parser.parse(buffer, base, ParserLimits.defaults(), CancellationToken.none());
        assertFalse(rBadEnd.present());
    }

    @Test
    void testReversedBoundsFailsClosed() {
        byte[] buffer = new byte[256];
        long base = 0x10000000L;
        ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0x10, (int) RpBinaryInfoMarker.MARKER_START);
        bb.putInt(0x14, (int) (base + 0x40));
        bb.putInt(0x18, (int) (base + 0x20)); // entries_end < entries_start!
        bb.putInt(0x1C, 0);
        bb.putInt(0x20, (int) RpBinaryInfoMarker.MARKER_END);

        DiagnosticException ex = assertThrows(DiagnosticException.class,
                () -> parser.parse(buffer, base, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.RP_BINARY_INFO_INVALID, ex.diagnostic().code());
    }

    @Test
    void testExceededLimitFailsClosed() {
        byte[] buffer = new byte[256];
        long base = 0x10000000L;
        ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0x10, (int) RpBinaryInfoMarker.MARKER_START);
        bb.putInt(0x14, (int) (base + 0x00));
        bb.putInt(0x18, (int) (base + 0x10000)); // 16384 entries > 2048 limit!
        bb.putInt(0x1C, 0);
        bb.putInt(0x20, (int) RpBinaryInfoMarker.MARKER_END);

        DiagnosticException ex = assertThrows(DiagnosticException.class,
                () -> parser.parse(buffer, base, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void testCancellationTokenEnforced() {
        byte[] buffer = new byte[256];
        long base = 0x10000000L;
        ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0x10, (int) RpBinaryInfoMarker.MARKER_START);
        bb.putInt(0x14, (int) (base + 0x30));
        bb.putInt(0x18, (int) (base + 0x40));
        bb.putInt(0x1C, 0);
        bb.putInt(0x20, (int) RpBinaryInfoMarker.MARKER_END);

        CancellationToken cancelled = () -> true;
        assertThrows(DiagnosticException.class,
                () -> parser.parse(buffer, base, ParserLimits.defaults(), cancelled));
    }

    private static void writeString(byte[] buffer, int offset, String s) {
        byte[] strBytes = s.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(strBytes, 0, buffer, offset, strBytes.length);
        buffer[offset + strBytes.length] = 0;
    }
}
