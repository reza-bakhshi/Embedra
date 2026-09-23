package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Esp32S3EnrichmentPackTest {
    private static final String REVISION =
        "662a3be354759d9487bf4b1a629fadb766cb1800";

    @TempDir
    Path temporaryDirectory;

    @Test
    void loadsIntegrityCheckedRomSymbolsWithExactProvenance() throws Exception {
        EspRomSymbolPack pack = Esp32S3PackLoader.loadRom(
            pack("espressif.esp32s3.rom"), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals("espressif.esp32s3.rom", pack.manifest().packId());
        assertEquals("esp32s3", pack.deviceId());
        assertEquals(REVISION, pack.manifest().provenance().revision());
        assertEquals("Apache-2.0", pack.manifest().provenance().license());
        assertEquals(RedistributionStatus.ALLOWED,
            pack.manifest().provenance().redistribution());
        assertTrue(pack.symbols().size() > 1500);
        EspRomSymbol printf = pack.requireSymbol("ets_printf");
        assertEquals(0x4000_05d0L, printf.address());
        assertEquals(EspRomSymbolKind.FUNCTION, printf.kind());
        assertEquals(EspRomSymbolKind.DATA,
            pack.requireSymbol("ets_ops_table_ptr").kind());
        assertThrows(UnsupportedOperationException.class,
            () -> pack.symbols().clear());
    }

    @Test
    void loadsPeripheralRegistersAndPreservesAddressAliases() throws Exception {
        EspPeripheralPack pack = Esp32S3PackLoader.loadPeripherals(
            pack("espressif.esp32s3.peripherals"), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals("esp32s3", pack.deviceId());
        assertEquals(REVISION, pack.manifest().provenance().revision());
        assertTrue(pack.peripherals().size() > 40);
        assertTrue(pack.registerCount() > 1500);
        EspPeripheral gpio = pack.requirePeripheral("GPIO");
        assertEquals(0x6000_4000L, gpio.baseAddress());
        EspPeripheralRegister gpioOut = gpio.requireRegister("GPIO_OUT_REG");
        assertEquals(0x6000_4004L, gpioOut.address());
        assertEquals(32, gpioOut.widthBits());
        EspPeripheral syscon = pack.requirePeripheral("SYSCON");
        assertTrue(syscon.aliases().contains("APB_CTRL"));
        assertThrows(UnsupportedOperationException.class,
            () -> gpioOut.names().add("user"));
    }

    @Test
    void rejectsTamperingWrongPackKindLimitsAndCancellation() throws Exception {
        Path copy = temporaryDirectory.resolve("rom");
        copyTree(pack("espressif.esp32s3.rom"), copy);
        Files.writeString(copy.resolve("rom-symbols.json"), "tampered");
        DiagnosticException tampered = assertThrows(DiagnosticException.class,
            () -> Esp32S3PackLoader.loadRom(copy, ParserLimits.defaults(),
                CancellationToken.none()));
        assertEquals(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
            tampered.diagnostic().code());

        DiagnosticException wrongKind = assertThrows(DiagnosticException.class,
            () -> Esp32S3PackLoader.loadRom(
                pack("espressif.esp32s3.peripherals"), ParserLimits.defaults(),
                CancellationToken.none()));
        assertEquals(DiagnosticCode.PACK_INCOMPATIBLE,
            wrongKind.diagnostic().code());

        ParserLimits tiny = new ParserLimits(128, 128, 128, 8, 4,
            ParserLimits.defaults().maxWallTime());
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> Esp32S3PackLoader.loadRom(pack("espressif.esp32s3.rom"), tiny,
                CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> Esp32S3PackLoader.loadPeripherals(
                pack("espressif.esp32s3.peripherals"), ParserLimits.defaults(),
                cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());
    }

    @Test
    void generatedPacksContainNoRestrictedDumpOrHostPaths() throws Exception {
        String rom = Files.readString(pack("espressif.esp32s3.rom")
            .resolve("rom-symbols.json"));
        String peripherals = Files.readString(pack("espressif.esp32s3.peripherals")
            .resolve("peripherals.json"));
        assertFalse(rom.contains("esp32s3_ctf_dump"));
        assertFalse(peripherals.contains("esp32s3_ctf_dump"));
        assertFalse(rom.contains("/home/"));
        assertFalse(peripherals.contains("/home/"));
    }

    private static Path pack(String id) {
        return Path.of("packs", id, "1.0.0");
    }

    private static void copyTree(Path source, Path destination) throws Exception {
        try (var paths = Files.walk(source)) {
            for (Path path : paths.toList()) {
                Path target = destination.resolve(source.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    Files.createDirectories(target);
                }
                else {
                    Files.copy(path, target);
                }
            }
        }
    }
}
