package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
import io.github.rezabakhshi.embedra.formats.esp.layout.Esp32FlashLayoutProvider;
import io.github.rezabakhshi.embedra.formats.esp.layout.Esp32S2FlashLayoutProvider;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class Esp32AndS2FullFlashTest {
    @Test
    void plansEsp32DefaultFactoryAndRespects4kBootloaderOffset() throws Exception {
        byte[] flash = fixture("esp32", "default-factory.bin");
        EspFullFlashWorkspace workspace = EspFullFlashWorkspacePlanner.plan(
                flash, Esp32FlashLayoutProvider.INSTANCE, ParserLimits.defaults(), CancellationToken.none()
        );

        assertEquals(ProgramStrategy.SEPARATE_PROGRAMS, workspace.programStrategy());
        assertEquals(0x8000, workspace.partitionTable().tableFlashRange().offset());
        assertEquals(List.of("bootloader", "factory"),
                workspace.executables().stream().map(EspExtractedExecutable::name).toList());

        EspExtractedExecutable bootloader = workspace.executables().get(0);
        assertEquals(EspExecutableRole.BOOTLOADER, bootloader.role());
        assertEquals(0x1000, bootloader.flashRange().offset());
        assertEquals(0, bootloader.image().header().chipId());

        EspExtractedExecutable factory = workspace.executables().get(1);
        assertEquals(EspExecutableRole.FACTORY, factory.role());
        assertEquals(0x10000, factory.flashRange().offset());
        assertEquals(0, factory.image().header().chipId());
    }

    @Test
    void plansEsp32S2DefaultFactoryAndRespectsZeroBootloaderOffset() throws Exception {
        byte[] flash = fixture("esp32s2", "default-factory.bin");
        EspFullFlashWorkspace workspace = EspFullFlashWorkspacePlanner.plan(
                flash, Esp32S2FlashLayoutProvider.INSTANCE, ParserLimits.defaults(), CancellationToken.none()
        );

        assertEquals(ProgramStrategy.SEPARATE_PROGRAMS, workspace.programStrategy());
        assertEquals(0x8000, workspace.partitionTable().tableFlashRange().offset());
        assertEquals(List.of("bootloader", "factory"),
                workspace.executables().stream().map(EspExtractedExecutable::name).toList());

        EspExtractedExecutable bootloader = workspace.executables().get(0);
        assertEquals(EspExecutableRole.BOOTLOADER, bootloader.role());
        assertEquals(0x0000, bootloader.flashRange().offset());
        assertEquals(2, bootloader.image().header().chipId());

        EspExtractedExecutable factory = workspace.executables().get(1);
        assertEquals(EspExecutableRole.FACTORY, factory.role());
        assertEquals(0x10000, factory.flashRange().offset());
        assertEquals(2, factory.image().header().chipId());
    }

    @Test
    void autoDetectsEsp32AndEsp32S2FromCandidateHeader() throws Exception {
        byte[] esp32Flash = fixture("esp32", "default-factory.bin");
        EspFullFlashWorkspace esp32Ws = EspFullFlashWorkspacePlanner.plan(
                esp32Flash, ParserLimits.defaults(), CancellationToken.none()
        );
        assertEquals(0, esp32Ws.executables().get(0).image().header().chipId());
        assertEquals(0x1000, esp32Ws.executables().get(0).flashRange().offset());

        byte[] s2Flash = fixture("esp32s2", "default-factory.bin");
        EspFullFlashWorkspace s2Ws = EspFullFlashWorkspacePlanner.plan(
                s2Flash, ParserLimits.defaults(), CancellationToken.none()
        );
        assertEquals(2, s2Ws.executables().get(0).image().header().chipId());
        assertEquals(0x0000, s2Ws.executables().get(0).flashRange().offset());
    }

    @Test
    void handlesCustomOffsetAndOtaEncryptedForEsp32AndS2() throws Exception {
        for (String target : List.of("esp32", "esp32s2")) {
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
    void rejectsCorruptAndMismatchedChipImagesForEsp32AndS2() throws Exception {
        for (String target : List.of("esp32", "esp32s2")) {
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
        try (InputStream in = Esp32AndS2FullFlashTest.class.getResourceAsStream(path)) {
            assertNotNull(in, "missing fixture " + path);
            return in.readAllBytes();
        }
    }
}
