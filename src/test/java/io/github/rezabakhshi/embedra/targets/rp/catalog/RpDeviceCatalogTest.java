package io.github.rezabakhshi.embedra.targets.rp.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RpDeviceCatalogTest {

    private static final Path CATALOG_DIR = Path.of("catalogs", "rp", "2026-10-02");

    @TempDir
    Path tempDir;

    @Test
    void loadsPinnedCompleteOfficialSnapshotWithoutPromotingSupport() throws Exception {
        RpDeviceCatalog catalog = RpDeviceCatalogLoader.load(
                CATALOG_DIR, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(catalog);
        assertEquals(5, catalog.siliconRecords().size());
        assertEquals(4, catalog.boardProfiles().size());

        Set<String> parts = catalog.siliconRecords().stream()
                .map(RpSiliconRecord::exactPart)
                .collect(Collectors.toSet());
        assertEquals(Set.of("RP2040", "RP2350A", "RP2350B", "RP2354A", "RP2354B"), parts);

        // Every part starts in PLANNED state
        assertTrue(catalog.siliconRecords().stream()
                .allMatch(r -> r.supportState() == SupportState.PLANNED));
        assertTrue(catalog.boardProfiles().stream()
                .allMatch(b -> b.supportState() == SupportState.PLANNED));

        // Exact RP2040 checks
        RpSiliconRecord rp2040 = catalog.requireExactPart("RP2040");
        assertEquals("QFN-56", rp2040.packageName());
        assertEquals(30, rp2040.gpioCount());
        assertEquals(264 * 1024, rp2040.sramBytes());
        assertEquals(0, rp2040.internalFlashBytes());
        assertEquals(16 * 1024 * 1024, rp2040.externalXipLimitBytes());
        assertEquals(2, rp2040.pioBlocks());
        assertEquals(8, rp2040.totalPioStateMachines());
        assertEquals(List.of("ARM_CORTEX_M0P"), rp2040.bootArchitectures());
        assertTrue(rp2040.supportsArm());
        assertFalse(rp2040.supportsRiscV());
        assertFalse(rp2040.hasInternalFlash());

        // RP2350A vs RP2350B package and GPIO differences
        RpSiliconRecord rp2350a = catalog.requireExactPart("RP2350A");
        RpSiliconRecord rp2350b = catalog.requireExactPart("RP2350B");
        assertEquals("QFN-60", rp2350a.packageName());
        assertEquals(30, rp2350a.gpioCount());
        assertEquals("QFN-80", rp2350b.packageName());
        assertEquals(48, rp2350b.gpioCount());
        assertEquals(520 * 1024, rp2350a.sramBytes());
        assertEquals(3, rp2350a.pioBlocks());
        assertEquals(12, rp2350a.totalPioStateMachines());
        assertTrue(rp2350a.supportsArm());
        assertTrue(rp2350a.supportsRiscV());
        assertTrue(rp2350a.securityCapabilities().contains("ARM_TRUSTZONE"));
        assertTrue(rp2350a.securityCapabilities().contains("OTP_8KB"));

        // RP2354 stacked internal flash
        RpSiliconRecord rp2354a = catalog.requireExactPart("RP2354A");
        RpSiliconRecord rp2354b = catalog.requireExactPart("RP2354B");
        assertTrue(rp2354a.hasInternalFlash());
        assertTrue(rp2354b.hasInternalFlash());
        assertEquals(2 * 1024 * 1024, rp2354a.internalFlashBytes());
        assertEquals(2 * 1024 * 1024, rp2354b.internalFlashBytes());
        assertEquals("QFN-60", rp2354a.packageName());
        assertEquals("QFN-80", rp2354b.packageName());

        // Board profiles
        RpBoardProfile pico = catalog.requireBoardProfile("pico");
        assertEquals("RP2040", pico.siliconPart());
        assertEquals(2 * 1024 * 1024, pico.externalFlashBytes());
        assertFalse(pico.hasWireless());
        assertNull(pico.wirelessChip());

        RpBoardProfile picoW = catalog.requireBoardProfile("pico_w");
        assertEquals("RP2040", picoW.siliconPart());
        assertTrue(picoW.hasWireless());
        assertEquals("Infineon CYW43439", picoW.wirelessChip().model());

        RpBoardProfile pico2 = catalog.requireBoardProfile("pico2");
        assertEquals("RP2350A", pico2.siliconPart());
        assertEquals(4 * 1024 * 1024, pico2.externalFlashBytes());
        assertFalse(pico2.hasWireless());

        RpBoardProfile pico2W = catalog.requireBoardProfile("pico2_w");
        assertEquals("RP2350A", pico2W.siliconPart());
        assertTrue(pico2W.hasWireless());
    }

    @Test
    void rejectsCorruptedChecksumWithIntegrityMismatch() throws IOException {
        copyDirectory(CATALOG_DIR, tempDir);
        Files.writeString(tempDir.resolve("catalog.sha256"), "0".repeat(64) + "  catalog.json\n");

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpDeviceCatalogLoader.load(tempDir, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.RP_CATALOG_INTEGRITY_MISMATCH, ex.diagnostic().code());
    }

    @Test
    void rejectsCorruptedBoardProfilesChecksum() throws IOException {
        copyDirectory(CATALOG_DIR, tempDir);
        Files.writeString(tempDir.resolve("board-profiles.sha256"), "f".repeat(64) + "  board-profiles.json\n");

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpDeviceCatalogLoader.load(tempDir, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(DiagnosticCode.RP_CATALOG_INTEGRITY_MISMATCH, ex.diagnostic().code());
    }

    @Test
    void respectsCancellationAndLimits() throws IOException {
        copyDirectory(CATALOG_DIR, tempDir);

        CancellationSource source = new CancellationSource();
        source.cancel();
        DiagnosticException cancelEx = assertThrows(DiagnosticException.class, () ->
                RpDeviceCatalogLoader.load(tempDir, ParserLimits.defaults(), source.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelEx.diagnostic().code());

        ParserLimits tinyLimits = new ParserLimits(10, 10, 10, 10, 5, java.time.Duration.ofSeconds(1));
        DiagnosticException limitEx = assertThrows(DiagnosticException.class, () ->
                RpDeviceCatalogLoader.load(tempDir, tinyLimits, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limitEx.diagnostic().code());
    }

    @Test
    void rejectsBoardReferencingUnknownSiliconPart() {
        RpSiliconRecord rp2040 = new RpSiliconRecord(
                "rp:silicon:rp2040", "RP2040", "RP2040", "Raspberry Pi Ltd",
                "QFN-56", "7x7mm", 30, 0, 16777216, 270336, List.of(),
                16384, 0, 0x10000000, 2, List.of("ARM_CORTEX_M0P"),
                "FIXED", 2, 4, true, 0x50000000, 0xD0000000,
                List.of(), List.of(), SupportState.PLANNED);

        RpBoardProfile invalidBoard = new RpBoardProfile(
                "custom", "Custom Board", "Vendor", "UNKNOWN_PART",
                2097152, "W25Q16", "QSPI", null, null, SupportState.PLANNED, "");

        assertThrows(IllegalArgumentException.class, () ->
                new RpDeviceCatalog(List.of(rp2040), List.of(invalidBoard), "sha1", "sha2"));
    }

    private static void copyDirectory(Path source, Path target) throws IOException {
        try (var stream = Files.walk(source)) {
            for (Path path : stream.toList()) {
                Path dest = target.resolve(source.relativize(path));
                if (Files.isDirectory(path)) {
                    Files.createDirectories(dest);
                } else {
                    Files.copy(path, dest);
                }
            }
        }
    }
}
