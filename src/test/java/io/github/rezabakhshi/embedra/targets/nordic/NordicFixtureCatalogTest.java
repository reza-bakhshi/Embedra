package io.github.rezabakhshi.embedra.targets.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Automated verification for the T097 Nordic fixture suite, manifests, and catalog loading. */
class NordicFixtureCatalogTest {
    private static final Path FIXTURE_DIR = Path.of("src/test/resources/fixtures/nordic");

    private static final Path MALFORMED_DIR = FIXTURE_DIR.resolve("malformed");

    private static final Path ORACLE_DIR = Path.of("src/test/resources/oracles/nordic");

    private static final Path CATALOG_PATH =
        Path.of("catalogs/nordic/2026-10-13/catalog.json");

    private static final List<String> REPRESENTATIVE_BAREMETAL = List.of(
        "nrf51822_app", "nrf52832_app", "nrf52840_app"
    );

    @Test
    void allBaremetalFixturesHaveAllFormatsAndManifests() throws IOException {
        for (String pfx : REPRESENTATIVE_BAREMETAL) {
            for (String ext : List.of(".bin", ".hex", ".elf")) {
                Path fixturePath = FIXTURE_DIR.resolve(pfx + ext);
                Path manifestPath = FIXTURE_DIR.resolve(pfx + ext + ".manifest.json");

                assertTrue(Files.isRegularFile(fixturePath), "Fixture must exist: " + fixturePath);
                assertTrue(Files.isRegularFile(manifestPath), "Manifest must exist: " + manifestPath);

                String manifest = Files.readString(manifestPath);
                assertTrue(manifest.contains("\"redistributionStatus\": \"REDISTRIBUTABLE\""));
                assertTrue(manifest.contains("\"requirements\""));
            }

            Path oraclePath = ORACLE_DIR.resolve(pfx + ".json");
            assertTrue(Files.isRegularFile(oraclePath), "Oracle must exist: " + oraclePath);
            String oracle = Files.readString(oraclePath);
            assertTrue(oracle.contains("\"initialSp\""));
            assertTrue(oracle.contains("\"resetVector\""));
            assertTrue(oracle.contains("\"flashBase\": \"0x00000000\""));
        }
    }

    @Test
    void rawBinaryFixturesContainValidCortexMVectorTable() throws IOException {
        for (String pfx : REPRESENTATIVE_BAREMETAL) {
            Path binPath = FIXTURE_DIR.resolve(pfx + ".bin");
            byte[] bytes = Files.readAllBytes(binPath);
            assertTrue(bytes.length >= 64, "Binary must be at least 64 bytes for vector table");

            ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            int initialSp = buf.getInt(0);
            int resetVector = buf.getInt(4);

            assertEquals(0x20000000, initialSp & 0xFFF00000,
                pfx + " Initial SP must reside in internal SRAM (0x20000000 range)");
            assertEquals(1, resetVector & 1,
                pfx + " Reset vector must have Thumb bit set (bit 0 == 1)");
        }
    }

    @Test
    void softDeviceCombinationFixturesAreWellFormed() throws IOException {
        Path s132Hex = FIXTURE_DIR.resolve("nrf52832_s132_app.hex");
        Path s140Hex = FIXTURE_DIR.resolve("nrf52840_s140_app.hex");

        assertTrue(Files.isRegularFile(s132Hex), "S132 combination image must exist");
        assertTrue(Files.isRegularFile(s140Hex), "S140 combination image must exist");

        String s132Oracle = Files.readString(ORACLE_DIR.resolve("nrf52832_s132_app.json"));
        assertTrue(s132Oracle.contains("\"applicationOffset\": \"0x00026000\""));

        String s140Oracle = Files.readString(ORACLE_DIR.resolve("nrf52840_s140_app.json"));
        assertTrue(s140Oracle.contains("\"applicationOffset\": \"0x00027000\""));
    }

    @Test
    void uicrConfigurationBlockIsPresentAndVerified() throws IOException {
        Path uicrHex = FIXTURE_DIR.resolve("nrf52840_uicr.hex");
        assertTrue(Files.isRegularFile(uicrHex), "UICR HEX fixture must exist");

        String uicrOracle = Files.readString(ORACLE_DIR.resolve("nrf52840_uicr.json"));
        assertTrue(uicrOracle.contains("\"baseAddress\": \"0x10001000\""));
        assertTrue(uicrOracle.contains("\"bootloaderAddr\": \"0x000F8000\""));
        assertTrue(uicrOracle.contains("\"customer0\": \"0xCAFEBABE\""));
    }

    @Test
    void dualCoreAndTrustZoneFixturesArePresentAndValid() throws IOException {
        Path appElf = FIXTURE_DIR.resolve("nrf5340_app_core.elf");
        Path netElf = FIXTURE_DIR.resolve("nrf5340_net_core.elf");
        Path secElf = FIXTURE_DIR.resolve("nrf9160_secure.elf");
        Path nsElf = FIXTURE_DIR.resolve("nrf9160_nonsecure.elf");

        assertTrue(Files.isRegularFile(appElf), "nRF5340 App ELF must exist");
        assertTrue(Files.isRegularFile(netElf), "nRF5340 Net ELF must exist");
        assertTrue(Files.isRegularFile(secElf), "nRF9160 Secure ELF must exist");
        assertTrue(Files.isRegularFile(nsElf), "nRF9160 Non-Secure ELF must exist");

        // Verify ELF magic and ARM machine type (40)
        byte[] appBytes = Files.readAllBytes(appElf);
        assertEquals(0x7F, appBytes[0]);
        assertEquals('E', appBytes[1]);
        assertEquals('L', appBytes[2]);
        assertEquals('F', appBytes[3]);
        ByteBuffer buf = ByteBuffer.wrap(appBytes).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(2, buf.getShort(16), "ET_EXEC");
        assertEquals(40, buf.getShort(18), "EM_ARM");
    }

    @Test
    void malformedFixturesAreDocumentedAndFailClosed() throws IOException {
        List<String> malformedFiles = List.of(
            "nrf52_invalid_vector.bin",
            "nrf52_truncated.hex",
            "nrf52_bad_checksum.hex",
            "nrf52_overlapping.hex",
            "nrf52_truncated_elf.elf"
        );

        for (String mfile : malformedFiles) {
            Path mpath = MALFORMED_DIR.resolve(mfile);
            Path manPath = MALFORMED_DIR.resolve(mfile + ".manifest.json");
            String stem = mfile.contains(".") ? mfile.substring(0, mfile.lastIndexOf('.')) : mfile;
            Path oraclePath = ORACLE_DIR.resolve("malformed").resolve(stem + ".json");

            assertTrue(Files.isRegularFile(mpath), "Malformed fixture must exist: " + mpath);
            assertTrue(Files.isRegularFile(manPath), "Manifest must exist: " + manPath);
            assertTrue(Files.isRegularFile(oraclePath), "Oracle must exist: " + oraclePath);

            String oracle = Files.readString(oraclePath);
            assertTrue(oracle.contains("\"expectedOutcome\": \"FAIL_CLOSED_VALIDATION\""));
        }
    }

    @Test
    void catalogFileIsAccessibleAndCoversAllTwentyOneParts() throws IOException {
        assertTrue(Files.isRegularFile(CATALOG_PATH), "Catalog JSON must exist");
        String catalog = Files.readString(CATALOG_PATH);
        assertTrue(catalog.contains("\"catalogId\": \"nordic-catalog-2026-10-13\""));
        assertTrue(catalog.contains("\"recordCount\": 21"));
        assertTrue(catalog.contains("nRF51822-QFAA"));
        assertTrue(catalog.contains("nRF52840-QIAA"));
        assertTrue(catalog.contains("nRF5340-QKAA"));
        assertTrue(catalog.contains("nRF54L15"));
        assertTrue(catalog.contains("nRF9160-SICA"));
    }
}
