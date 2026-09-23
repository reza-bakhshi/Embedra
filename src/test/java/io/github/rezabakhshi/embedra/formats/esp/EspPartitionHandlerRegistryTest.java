package io.github.rezabakhshi.embedra.formats.esp;

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
import java.util.Arrays;
import java.util.List;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class EspPartitionHandlerRegistryTest {
    @Test
    void dispatchesEveryRequiredSubtypeAndCustomTypeExplicitly() {
        assertKind(1, 0x00, EspPartitionHandlerKind.OTA_STATE);
        assertKind(1, 0x01, EspPartitionHandlerKind.PHY);
        assertKind(1, 0x02, EspPartitionHandlerKind.NVS);
        assertKind(1, 0x03, EspPartitionHandlerKind.COREDUMP);
        assertKind(1, 0x04, EspPartitionHandlerKind.NVS_KEYS);
        assertKind(1, 0x81, EspPartitionHandlerKind.FAT);
        assertKind(1, 0x82, EspPartitionHandlerKind.SPIFFS);
        assertKind(1, 0x83, EspPartitionHandlerKind.LITTLEFS);
        assertKind(0x40, 0x7f, EspPartitionHandlerKind.CUSTOM);
        assertKind(0, 0x11, EspPartitionHandlerKind.INACTIVE_APPLICATION);
    }

    @Test
    void validatesOtaCopiesAndResolvesOnlyPopulatedActiveSlot() throws Exception {
        byte[] payload = erased(0x2000);
        writeOtaRecord(payload, 0, 1, 0xffff_ffffL);
        EspExtractedPartition ota = artifact("otadata", 1, 0, 0xe000,
            payload, EspPartitionPayloadKind.DATA, 0);
        EspPartitionTable table = table(List.of(ota.entry(),
            entry(1, "app0", 0, 0x10, 0x10000, 0x140000, 0),
            entry(2, "app1", 0, 0x11, 0x150000, 0x140000, 0)));

        EspPartitionAnalysis analysis = EspPartitionHandlerRegistry.defaults()
            .analyze(table, List.of(ota), List.of("app0"),
                ParserLimits.defaults(), CancellationToken.none());

        EspOtaSelection selection = analysis.otaSelection().orElseThrow();
        assertEquals(0, selection.activeSlot().orElseThrow());
        assertEquals("app0", selection.activePartitionLabel().orElseThrow());
        assertEquals(EspOtaRecordValidity.VALID, selection.records().get(0).validity());
        assertEquals(EspOtaRecordValidity.ERASED,
            selection.records().get(1).validity());
        assertEquals(EspPartitionDisposition.VALIDATED_METADATA,
            analysis.inspections().get(0).disposition());
    }

    @Test
    void reportsMalformedOtaAsNonFatalTypedInspection() throws Exception {
        byte[] payload = erased(0x2000);
        writeUnsignedInt(payload, 0, 2);
        writeUnsignedInt(payload, 24, 2);
        writeUnsignedInt(payload, 28, 0x12345678);
        EspExtractedPartition ota = artifact("otadata", 1, 0, 0xe000,
            payload, EspPartitionPayloadKind.DATA, 0);

        EspPartitionAnalysis analysis = EspPartitionHandlerRegistry.defaults()
            .analyze(table(List.of(ota.entry())), List.of(ota), List.of(),
                ParserLimits.defaults(), CancellationToken.none());

        EspPartitionInspection inspection = analysis.inspections().get(0);
        assertEquals(EspPartitionDisposition.INVALID, inspection.disposition());
        assertEquals(DiagnosticCode.ESP_PARTITION_HANDLER_INVALID,
            inspection.diagnostics().get(0).code());
        assertTrue(analysis.otaSelection().isPresent());
        assertTrue(analysis.otaSelection().orElseThrow().activeSlot().isEmpty());
    }

    @Test
    void handlesNvsSecretsCoredumpFilesystemsAndCustomConservatively()
            throws Exception {
        byte[] nvs = erased(0x3000);
        writeUnsignedInt(nvs, 0, 0xffff_fffeL);
        writeUnsignedInt(nvs, 4, 7);
        nvs[8] = (byte) 0xfe;
        byte[] keys = new byte[0x1000];
        Arrays.fill(keys, (byte) 0x5a);
        byte[] core = erased(0x1000);
        writeUnsignedInt(core, 0, 0x100);
        writeUnsignedInt(core, 4, 0x0009_0102);
        writeUnsignedInt(core, 8, 3);
        core[24] = 0x7f;
        core[25] = 'E';
        core[26] = 'L';
        core[27] = 'F';
        byte[] fat = erased(0x1000);
        fat[510] = 0x55;
        fat[511] = (byte) 0xaa;
        List<EspExtractedPartition> artifacts = List.of(
            artifact("nvs", 1, 2, 0x9000, nvs, EspPartitionPayloadKind.DATA, 0),
            artifact("nvs_keys", 1, 4, 0xc000, keys,
                EspPartitionPayloadKind.DATA, 0),
            artifact("phy", 1, 1, 0xd000, new byte[0x1000],
                EspPartitionPayloadKind.DATA, 0),
            artifact("core", 1, 3, 0xe000, core,
                EspPartitionPayloadKind.DATA, 0),
            artifact("fat", 1, 0x81, 0xf000, fat,
                EspPartitionPayloadKind.DATA, 0),
            artifact("spiffs", 1, 0x82, 0x10000, new byte[0x1000],
                EspPartitionPayloadKind.DATA, 0),
            artifact("littlefs", 1, 0x83, 0x11000, new byte[0x1000],
                EspPartitionPayloadKind.DATA, 0),
            artifact("custom", 0x40, 7, 0x12000, new byte[0x1000],
                EspPartitionPayloadKind.CUSTOM, 0));

        EspPartitionAnalysis analysis = EspPartitionHandlerRegistry.defaults()
            .analyze(table(artifacts.stream().map(EspExtractedPartition::entry)
                .toList()), artifacts, List.of(), ParserLimits.defaults(),
                CancellationToken.none());

        assertDisposition(analysis, "nvs", EspPartitionDisposition.VALIDATED_METADATA);
        EspPartitionInspection keyInspection = inspection(analysis, "nvs_keys");
        assertEquals(EspPartitionDisposition.SENSITIVE_REDACTED,
            keyInspection.disposition());
        assertTrue(keyInspection.sensitive());
        assertFalse(keyInspection.metadata().toString().contains("5a5a"));
        assertDisposition(analysis, "phy", EspPartitionDisposition.OPAQUE);
        EspPartitionInspection coreInspection = inspection(analysis, "core");
        assertEquals("9", coreInspection.metadata().get("chipId"));
        assertEquals("true", coreInspection.metadata().get("elfPresent"));
        assertDisposition(analysis, "fat",
            EspPartitionDisposition.VALIDATED_METADATA);
        assertDisposition(analysis, "spiffs",
            EspPartitionDisposition.CONFIGURATION_REQUIRED);
        assertDisposition(analysis, "littlefs",
            EspPartitionDisposition.CONFIGURATION_REQUIRED);
        assertDisposition(analysis, "custom", EspPartitionDisposition.OPAQUE);
    }

    @Test
    void encryptedPartitionsBypassAllContentHandlers() throws Exception {
        byte[] payload = new byte[0x1000];
        EspExtractedPartition encrypted = artifact("secret", 1, 4, 0x9000,
            payload, EspPartitionPayloadKind.ENCRYPTED_OPAQUE, 1);

        EspPartitionAnalysis analysis = EspPartitionHandlerRegistry.defaults()
            .analyze(table(List.of(encrypted.entry())), List.of(encrypted),
                List.of(), ParserLimits.defaults(), CancellationToken.none());

        EspPartitionInspection inspection = analysis.inspections().get(0);
        assertEquals(EspPartitionHandlerKind.ENCRYPTED, inspection.kind());
        assertEquals(EspPartitionDisposition.OPAQUE, inspection.disposition());
        assertTrue(inspection.sensitive());
        assertTrue(inspection.metadata().isEmpty());
    }

    @Test
    void enforcesCancellationAndReturnsImmutableResults() throws Exception {
        EspExtractedPartition phy = artifact("phy", 1, 1, 0x9000,
            new byte[0x1000], EspPartitionPayloadKind.DATA, 0);
        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> EspPartitionHandlerRegistry.defaults().analyze(
                table(List.of(phy.entry())), List.of(phy), List.of(),
                ParserLimits.defaults(), cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, failure.diagnostic().code());

        EspPartitionAnalysis analysis = EspPartitionHandlerRegistry.defaults()
            .analyze(table(List.of(phy.entry())), List.of(phy), List.of(),
                ParserLimits.defaults(), CancellationToken.none());
        assertThrows(UnsupportedOperationException.class,
            () -> analysis.inspections().clear());
        assertThrows(UnsupportedOperationException.class,
            () -> analysis.inspections().get(0).metadata().put("x", "y"));

        ParserLimits noObjects = new ParserLimits(0x10000, 0x10000, 0x10000,
            1, 32, Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> EspPartitionHandlerRegistry.defaults().analyze(
                table(List.of(phy.entry(), entry(1, "other", 1, 1, 0xa000,
                    0x1000, 0))), List.of(phy, artifact("other", 1, 1,
                    0xa000, new byte[0x1000], EspPartitionPayloadKind.DATA, 0)),
                List.of(), noObjects, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());
    }

    private static void assertKind(int type, int subtype,
            EspPartitionHandlerKind expected) {
        EspPartitionEntry entry = entry(0, "p", type, subtype, 0x9000,
            0x1000, type == 0 ? 0 : 0);
        assertEquals(expected,
            EspPartitionHandlerRegistry.defaults().handlerFor(entry).kind());
    }

    private static void assertDisposition(EspPartitionAnalysis analysis,
            String label, EspPartitionDisposition disposition) {
        assertEquals(disposition, inspection(analysis, label).disposition());
    }

    private static EspPartitionInspection inspection(EspPartitionAnalysis analysis,
            String label) {
        return analysis.inspections().stream()
            .filter(candidate -> candidate.entry().label().equals(label))
            .findFirst().orElseThrow();
    }

    private static EspExtractedPartition artifact(String label, int type,
            int subtype, long offset, byte[] payload, EspPartitionPayloadKind kind,
            long flags) {
        EspPartitionEntry entry = entry(0, label, type, subtype, offset,
            payload.length, flags);
        return new EspExtractedPartition(entry, kind,
            new SourceRange(offset, payload.length), payload);
    }

    private static EspPartitionEntry entry(int index, String label, int type,
            int subtype, long offset, long size, long flags) {
        return new EspPartitionEntry(index, label, type, subtype,
            new EspFlashRange(offset, size), flags,
            new SourceRange(0x8000 + index * 32L, 32));
    }

    private static EspPartitionTable table(List<EspPartitionEntry> entries) {
        byte[] digest = new byte[16];
        return new EspPartitionTable(EspPartitionDiscoveryMethod.DEFAULT_OFFSET,
            new EspFlashRange(0x8000, 0x1000), new SourceRange(0x8000, 0x1000),
            entries, digest, digest, new SourceRange(0x8080, 16));
    }

    private static byte[] erased(int length) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) 0xff);
        return bytes;
    }

    private static void writeOtaRecord(byte[] output, int offset, long sequence,
            long state) {
        writeUnsignedInt(output, offset, sequence);
        writeUnsignedInt(output, offset + 24, state);
        writeUnsignedInt(output, offset + 28,
            EspOtaStateHandler.otaSequenceCrc(sequence));
    }

    private static void writeUnsignedInt(byte[] output, int offset, long value) {
        for (int index = 0; index < 4; index++) {
            output[offset + index] = (byte) (value >>> (index * 8));
        }
    }
}
