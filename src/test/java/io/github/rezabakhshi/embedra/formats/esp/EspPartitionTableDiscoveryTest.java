package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class EspPartitionTableDiscoveryTest {
    @Test
    void discoversAndValidatesDefaultTableBeforeScanning() throws Exception {
        EspPartitionTable table = discover("default-factory.bin");

        assertEquals(EspPartitionDiscoveryMethod.DEFAULT_OFFSET,
            table.discoveryMethod());
        assertEquals(new EspFlashRange(0x8000, 0x1000), table.tableFlashRange());
        assertEquals(new SourceRange(0x8000, 0x1000), table.sourceRange());
        assertTrue(table.md5Valid());
        assertEquals(4, table.entries().size());
        assertEntry(table.entries().get(0), 0, "nvs", 1, 2, 0x9000, 0x6000, 0);
        assertEntry(table.entries().get(2), 2, "factory", 0, 0, 0x10000,
            0x20000, 0);
        assertArrayEquals(table.storedMd5(), table.calculatedMd5());
        byte[] stored = table.storedMd5();
        stored[0] ^= 1;
        assertArrayEquals(table.calculatedMd5(), table.storedMd5());
    }

    @Test
    void scansSectorAlignedCandidatesAndRejectsMisleadingMagic() throws Exception {
        byte[] flash = fixture("custom-offset-misleading-magic.bin");

        EspPartitionTable table = EspPartitionTableDiscovery.discover(flash,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals(EspPartitionDiscoveryMethod.BOUNDED_SCAN,
            table.discoveryMethod());
        assertEquals(0x10000, table.tableFlashRange().offset());
        assertEquals(2, table.entries().size());
        assertEntry(table.entries().get(0), 0, "nvs", 1, 2, 0x11000, 0x5000, 0);

        DiagnosticException misleading = assertThrows(DiagnosticException.class,
            () -> EspPartitionTableDiscovery.parseAt(flash, 0x8000,
                ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.ESP_PARTITION_INVALID,
            misleading.diagnostic().code());

        EspPartitionTable explicit = EspPartitionTableDiscovery.parseAt(flash,
            0x10000, ParserLimits.defaults(), CancellationToken.none());
        assertEquals(EspPartitionDiscoveryMethod.EXPLICIT_OFFSET,
            explicit.discoveryMethod());
    }

    @Test
    void preservesOtaCustomTypeAndFlagsWithoutInventingSemantics() throws Exception {
        EspPartitionTable table = discover("ota-custom-encrypted.bin");

        assertEquals(6, table.entries().size());
        assertEntry(table.entries().get(3), 3, "ota_0", 0, 0x10, 0x10000,
            0x20000, 0);
        assertEntry(table.entries().get(4), 4, "ota_1", 0, 0x11, 0x30000,
            0x20000, 0);
        EspPartitionEntry custom = table.entries().get(5);
        assertEntry(custom, 5, "assets", 0x40, 0x7f, 0x50000, 0x10000, 1);
        assertTrue(custom.encrypted());
        assertFalse(custom.readOnly());
    }

    @Test
    void rejectsInvalidMd5BeforeExposingEntries() throws Exception {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> discover("invalid-partition-md5.bin"));

        assertEquals(DiagnosticCode.ESP_PARTITION_MD5_MISMATCH,
            failure.diagnostic().code());
        assertEquals(new SourceRange(0x8090, 16),
            failure.diagnostic().sourceRange().orElseThrow());
    }

    @Test
    void rejectsMissingTruncatedMisalignedAndOutOfFlashTables() throws Exception {
        byte[] noTable = new byte[0x20000];
        Arrays.fill(noTable, (byte) 0xff);
        assertDiagnostic(noTable, DiagnosticCode.ESP_PARTITION_NOT_FOUND);

        byte[] truncated = Arrays.copyOf(fixture("default-factory.bin"), 0x8080);
        assertDiagnosticAt(truncated, 0x8000, DiagnosticCode.ESP_PARTITION_TRUNCATED);

        byte[] flash = fixture("default-factory.bin");
        DiagnosticException misaligned = assertThrows(DiagnosticException.class,
            () -> EspPartitionTableDiscovery.parseAt(flash, 0x8001,
                ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.ESP_PARTITION_OFFSET_INVALID,
            misaligned.diagnostic().code());

        byte[] outside = flash.clone();
        writeUnsignedInt(outside, 0x8000 + 4, outside.length - 0x1000L);
        writeUnsignedInt(outside, 0x8000 + 8, 0x2000);
        updateMd5(outside, 0x8000, 4);
        assertDiagnosticAt(outside, 0x8000, DiagnosticCode.ESP_PARTITION_INVALID);
    }

    @Test
    void enforcesLimitsAndCancellationAcrossDiscovery() throws Exception {
        byte[] flash = fixture("default-factory.bin");
        ParserLimits inputLimit = new ParserLimits(flash.length - 1L,
            16 * 1024 * 1024, 16 * 1024 * 1024, 1_000_000, 32,
            Duration.ofSeconds(30));
        assertDiagnostic(flash, inputLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        ParserLimits objectLimit = new ParserLimits(flash.length,
            16 * 1024 * 1024, 16 * 1024 * 1024, 3, 32,
            Duration.ofSeconds(30));
        assertDiagnostic(flash, objectLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        assertDiagnostic(flash, ParserLimits.defaults(), cancellation.token(),
            DiagnosticCode.CANCELLED);
    }

    private static EspPartitionTable discover(String fixture) throws Exception {
        return EspPartitionTableDiscovery.discover(fixture(fixture),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static void assertEntry(EspPartitionEntry entry, int index, String label,
            int type, int subtype, long offset, long size, long flags) {
        assertEquals(index, entry.index());
        assertEquals(label, entry.label());
        assertEquals(type, entry.type());
        assertEquals(subtype, entry.subtype());
        assertEquals(new EspFlashRange(offset, size), entry.flashRange());
        assertEquals(flags, entry.flags());
    }

    private static void assertDiagnostic(byte[] input, DiagnosticCode code) {
        assertDiagnostic(input, ParserLimits.defaults(), CancellationToken.none(), code);
    }

    private static void assertDiagnostic(byte[] input, ParserLimits limits,
            CancellationToken cancellation, DiagnosticCode code) {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> EspPartitionTableDiscovery.discover(input, limits, cancellation));
        assertEquals(code, failure.diagnostic().code());
    }

    private static void assertDiagnosticAt(byte[] input, long offset,
            DiagnosticCode code) {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> EspPartitionTableDiscovery.parseAt(input, offset,
                ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(code, failure.diagnostic().code());
    }

    private static void updateMd5(byte[] flash, int tableOffset, int entryCount)
            throws Exception {
        int marker = tableOffset + entryCount * 32;
        byte[] digest = java.security.MessageDigest.getInstance("MD5")
            .digest(Arrays.copyOfRange(flash, tableOffset, marker));
        System.arraycopy(digest, 0, flash, marker + 16, digest.length);
    }

    private static void writeUnsignedInt(byte[] output, int offset, long value) {
        for (int index = 0; index < 4; index++) {
            output[offset + index] = (byte) (value >>> (index * 8));
        }
    }

    private static byte[] fixture(String name) throws IOException {
        String path = "/fixtures/esp32s3/full-flash/" + name;
        try (InputStream input = EspPartitionTableDiscoveryTest.class
                .getResourceAsStream(path)) {
            assertTrue(input != null, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
