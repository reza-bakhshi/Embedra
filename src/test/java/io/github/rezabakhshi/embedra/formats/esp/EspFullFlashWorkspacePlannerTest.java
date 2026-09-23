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
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class EspFullFlashWorkspacePlannerTest {
    @Test
    void plansDefaultBootloaderFactoryAndExactDataArtifacts() throws Exception {
        byte[] flash = fixture("default-factory.bin");

        EspFullFlashWorkspace workspace = plan(flash);

        assertEquals(ProgramStrategy.SEPARATE_PROGRAMS, workspace.programStrategy());
        assertEquals(0x8000, workspace.partitionTable().tableFlashRange().offset());
        assertEquals(List.of("bootloader", "factory"),
            workspace.executables().stream().map(EspExtractedExecutable::name).toList());
        assertExecutable(workspace.executables().get(0), EspExecutableRole.BOOTLOADER,
            0, 432, null);
        assertExecutable(workspace.executables().get(1), EspExecutableRole.FACTORY,
            0x10000, 432, "factory");
        assertEquals(List.of("nvs", "phy_init", "storage"),
            workspace.dataPartitions().stream()
                .map(partition -> partition.entry().label()).toList());
        assertEquals(EspPartitionPayloadKind.DATA,
            workspace.dataPartitions().get(0).kind());
        assertEquals(0x6000, workspace.dataPartitions().get(0).payload().length);
        assertArrayEquals(slice(flash, 0x9000, 0x6000),
            workspace.dataPartitions().get(0).payload());
    }

    @Test
    void usesValidatedCustomTableAndIgnoresMisleadingMagic() throws Exception {
        EspFullFlashWorkspace workspace = plan(
            fixture("custom-offset-misleading-magic.bin"));

        assertEquals(EspPartitionDiscoveryMethod.BOUNDED_SCAN,
            workspace.partitionTable().discoveryMethod());
        assertEquals(0x10000, workspace.partitionTable().tableFlashRange().offset());
        assertEquals(List.of("bootloader", "factory"),
            workspace.executables().stream().map(EspExtractedExecutable::name).toList());
        assertEquals(0x20000,
            workspace.executables().get(1).flashRange().offset());
    }

    @Test
    void keepsOtaProgramsSeparateAndEncryptedCustomPartitionOpaque() throws Exception {
        EspFullFlashWorkspace workspace = plan(fixture("ota-custom-encrypted.bin"));

        assertEquals(List.of("bootloader", "ota_0", "ota_1"),
            workspace.executables().stream().map(EspExtractedExecutable::name).toList());
        assertEquals(List.of(EspExecutableRole.BOOTLOADER, EspExecutableRole.OTA,
            EspExecutableRole.OTA), workspace.executables().stream()
                .map(EspExtractedExecutable::role).toList());
        EspExtractedPartition assets = workspace.dataPartitions().stream()
            .filter(partition -> partition.entry().label().equals("assets"))
            .findFirst().orElseThrow();
        assertEquals(EspPartitionPayloadKind.ENCRYPTED_OPAQUE, assets.kind());
        assertTrue(assets.entry().encrypted());
        assertEquals(0x10000, assets.payload().length);
        assertFalse(workspace.executables().stream()
            .anyMatch(executable -> executable.name().equals("assets")));

        byte[] copy = assets.payload();
        copy[0] ^= 1;
        assertArrayEquals(slice(fixture("ota-custom-encrypted.bin"), 0x50000,
            0x10000), assets.payload());
    }

    @Test
    void rejectsInvalidTableAndCorruptEmbeddedImageWithoutPartialPlan()
            throws Exception {
        assertDiagnostic(fixture("invalid-partition-md5.bin"),
            DiagnosticCode.ESP_PARTITION_MD5_MISMATCH);

        byte[] corrupt = fixture("default-factory.bin");
        corrupt[0x10000 + 32] ^= 1;
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> plan(corrupt));
        assertEquals(DiagnosticCode.ESP_CHECKSUM_MISMATCH,
            failure.diagnostic().code());
        assertTrue(failure.diagnostic().sourceRange().orElseThrow().offset()
            >= 0x10000);
    }

    @Test
    void enforcesExtractionLimitsAndCancellation() throws Exception {
        byte[] flash = fixture("default-factory.bin");
        ParserLimits extractionLimit = new ParserLimits(flash.length,
            16 * 1024 * 1024, 0x1000, 1_000_000, 32,
            Duration.ofSeconds(30));
        assertDiagnostic(flash, extractionLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        ParserLimits allocationLimit = new ParserLimits(flash.length, 1024,
            flash.length, 1_000_000, 32, Duration.ofSeconds(30));
        assertDiagnostic(flash, allocationLimit, CancellationToken.none(),
            DiagnosticCode.LIMIT_EXCEEDED);

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        assertDiagnostic(flash, ParserLimits.defaults(), cancellation.token(),
            DiagnosticCode.CANCELLED);
    }

    private static void assertExecutable(EspExtractedExecutable executable,
            EspExecutableRole role, long offset, long length, String partitionLabel) {
        assertEquals(role, executable.role());
        assertEquals(new EspFlashRange(offset, length), executable.flashRange());
        assertEquals(new SourceRange(offset, length), executable.sourceRange());
        assertEquals(partitionLabel, executable.partitionLabel().orElse(null));
        assertEquals(9, executable.image().header().chipId());
        assertEquals(length, executable.bytes().length);
    }

    private static EspFullFlashWorkspace plan(byte[] flash) throws DiagnosticException {
        return EspFullFlashWorkspacePlanner.plan(flash, ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static void assertDiagnostic(byte[] flash, DiagnosticCode code) {
        assertDiagnostic(flash, ParserLimits.defaults(), CancellationToken.none(), code);
    }

    private static void assertDiagnostic(byte[] flash, ParserLimits limits,
            CancellationToken cancellation, DiagnosticCode code) {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> EspFullFlashWorkspacePlanner.plan(flash, limits, cancellation));
        assertEquals(code, failure.diagnostic().code());
    }

    private static byte[] slice(byte[] input, int offset, int length) {
        return java.util.Arrays.copyOfRange(input, offset, offset + length);
    }

    private static byte[] fixture(String name) throws IOException {
        String path = "/fixtures/esp32s3/full-flash/" + name;
        try (InputStream input = EspFullFlashWorkspacePlannerTest.class
                .getResourceAsStream(path)) {
            assertTrue(input != null, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
