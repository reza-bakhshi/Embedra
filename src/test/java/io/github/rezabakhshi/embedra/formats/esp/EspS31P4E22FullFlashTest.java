package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.formats.esp.layout.EspFlashLayoutProvider;
import io.github.rezabakhshi.embedra.formats.esp.layout.EspFlashLayoutRegistry;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Full-flash tests for ESP32-P4, ESP32-S31, and ESP32-E22 targets (T085).
 */
class EspS31P4E22FullFlashTest {
    private static final Map<String, Integer> TARGETS = Map.of(
            "esp32p4", 18,
            "esp32s31", 32,
            "esp32e22", 31
    );

    @Test
    void verifiesLayoutProfilesForP4S31E22() {
        for (Map.Entry<String, Integer> entry : TARGETS.entrySet()) {
            String target = entry.getKey();
            int chipId = entry.getValue();

            EspFlashLayoutProvider provider = EspFlashLayoutRegistry.defaults().requireByChipId(chipId);
            assertEquals(chipId, provider.chipId());
            assertEquals(EspCpuIsa.RISCV, provider.profile().isa());
            assertEquals("RISCV:LE:32:default", provider.profile().defaultLanguageId());
            assertEquals("gcc", provider.profile().defaultCompilerSpecId());
            assertEquals(0x0000, provider.profile().bootloaderOffset());
            assertEquals(0x8000, provider.profile().defaultPartitionTableOffset());
            assertEquals(0x10000, provider.profile().mmuPageSize());
        }
    }

    @Test
    void plansDefaultFactoryFullFlashForP4S31E22() throws Exception {
        for (Map.Entry<String, Integer> entry : TARGETS.entrySet()) {
            String target = entry.getKey();
            int chipId = entry.getValue();

            byte[] flash = fixture(target, "default-factory.bin");
            EspFlashLayoutProvider provider = EspFlashLayoutRegistry.defaults().requireByChipId(chipId);

            EspFullFlashWorkspace workspace = EspFullFlashWorkspacePlanner.plan(
                    flash, provider, ParserLimits.defaults(), CancellationToken.none()
            );

            assertEquals(ProgramStrategy.SEPARATE_PROGRAMS, workspace.programStrategy());
            assertEquals(0x8000, workspace.partitionTable().tableFlashRange().offset());
            assertEquals(List.of("bootloader", "factory"),
                    workspace.executables().stream().map(EspExtractedExecutable::name).toList());

            EspExtractedExecutable bootloader = workspace.executables().get(0);
            assertEquals(EspExecutableRole.BOOTLOADER, bootloader.role());
            assertEquals(0x0000, bootloader.flashRange().offset());
            assertEquals(chipId, bootloader.image().header().chipId());

            EspExtractedExecutable factory = workspace.executables().get(1);
            assertEquals(EspExecutableRole.FACTORY, factory.role());
            assertEquals(0x10000, factory.flashRange().offset());
            assertEquals(chipId, factory.image().header().chipId());
        }
    }

    @Test
    void autoDetectsChipIdAndProviderFromCandidateHeader() throws Exception {
        for (Map.Entry<String, Integer> entry : TARGETS.entrySet()) {
            String target = entry.getKey();
            int chipId = entry.getValue();

            byte[] flash = fixture(target, "default-factory.bin");
            EspFullFlashWorkspace workspace = EspFullFlashWorkspacePlanner.plan(
                    flash, ParserLimits.defaults(), CancellationToken.none()
            );

            assertEquals(chipId, workspace.executables().get(0).image().header().chipId());
            assertEquals(0x0000, workspace.executables().get(0).flashRange().offset());
        }
    }

    @Test
    void handlesCustomOffsetAndOta() throws Exception {
        for (String target : TARGETS.keySet()) {
            byte[] custom = fixture(target, "custom-offset-misleading-magic.bin");
            EspFullFlashWorkspace customWs = EspFullFlashWorkspacePlanner.plan(
                    custom, ParserLimits.defaults(), CancellationToken.none()
            );
            assertEquals(0x10000, customWs.partitionTable().tableFlashRange().offset());

            byte[] ota = fixture(target, "ota-custom-encrypted.bin");
            EspFullFlashWorkspace otaWs = EspFullFlashWorkspacePlanner.plan(
                    ota, ParserLimits.defaults(), CancellationToken.none()
            );
            assertTrue(otaWs.dataPartitions().stream().anyMatch(p -> p.entry().label().equals("assets")));
        }
    }

    @Test
    void rejectsMalformedAndInvalidMd5() throws Exception {
        for (String target : TARGETS.keySet()) {
            byte[] invalidMd5 = fixture(target, "invalid-partition-md5.bin");
            DiagnosticException md5Fail = assertThrows(DiagnosticException.class,
                    () -> EspFullFlashWorkspacePlanner.plan(
                            invalidMd5, ParserLimits.defaults(), CancellationToken.none()));
            assertEquals(DiagnosticCode.ESP_PARTITION_MD5_MISMATCH, md5Fail.diagnostic().code());

            byte[] wrongChip = fixture(target, "malformed-wrong-chip.bin");
            DiagnosticException chipFail = assertThrows(DiagnosticException.class,
                    () -> EspFullFlashWorkspacePlanner.plan(
                            wrongChip, ParserLimits.defaults(), CancellationToken.none()));
            assertEquals(DiagnosticCode.ESP_CHIP_MISMATCH, chipFail.diagnostic().code());
        }
    }

    private static byte[] fixture(String target, String name) throws IOException {
        String path = "/fixtures/" + target + "/full-flash/" + name;
        try (InputStream in = EspS31P4E22FullFlashTest.class.getResourceAsStream(path)) {
            assertNotNull(in, "missing fixture " + path);
            return in.readAllBytes();
        }
    }
}
