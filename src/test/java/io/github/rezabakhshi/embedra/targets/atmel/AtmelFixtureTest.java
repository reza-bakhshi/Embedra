package io.github.rezabakhshi.embedra.targets.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Automated verification for the T105 Atmel / Microchip fixture suite and manifests. */
class AtmelFixtureTest {
    private static final Path FIXTURE_DIR = Path.of("src/test/resources/fixtures/atmel");

    private static final Path MALFORMED_DIR = FIXTURE_DIR.resolve("malformed");

    private static final Path ORACLE_DIR = Path.of("src/test/resources/oracles/atmel");

    private static final Path ORACLE_MALFORMED_DIR = ORACLE_DIR.resolve("malformed");

    private static final List<String> REPRESENTATIVE_PARTS = List.of(
        "atmega328p_app", "atmega2560_app", "attiny85_app",
        "samd21g18a_app", "same70q21_app"
    );

    private static final List<String> MALFORMED_CASES = List.of(
        "atmel_bad_checksum.hex",
        "atmel_truncated.hex",
        "atmel_overlapping.hex",
        "attiny85_invalid_vector.bin",
        "samd21_bad_sp.bin",
        "same70_truncated.bin",
        "atmega328p_truncated_elf.elf"
    );

    @Test
    void allRepresentativePartsHaveAllFormatsAndManifests() throws IOException {
        for (String pfx : REPRESENTATIVE_PARTS) {
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
            assertTrue(oracle.contains("\"part\""));
            assertTrue(oracle.contains("\"vectorTable\""));
        }
    }

    @Test
    void bootloaderAndCompositeFixturesArePresent() throws IOException {
        for (String ext : List.of(".bin", ".hex", ".elf")) {
            Path fixture = FIXTURE_DIR.resolve("atmega328p_optiboot" + ext);
            Path manifest = FIXTURE_DIR.resolve("atmega328p_optiboot" + ext + ".manifest.json");
            assertTrue(Files.isRegularFile(fixture), "Optiboot fixture missing: " + fixture);
            assertTrue(Files.isRegularFile(manifest), "Optiboot manifest missing: " + manifest);
        }

        Path compHex = FIXTURE_DIR.resolve("atmega328p_composite.hex");
        Path compMan = FIXTURE_DIR.resolve("atmega328p_composite.hex.manifest.json");
        Path compOrc = ORACLE_DIR.resolve("atmega328p_composite.json");
        assertTrue(Files.isRegularFile(compHex));
        assertTrue(Files.isRegularFile(compMan));
        assertTrue(Files.isRegularFile(compOrc));

        String compContent = Files.readString(compHex);
        assertTrue(compContent.contains(":107E0000"), "Composite HEX must include Optiboot high flash record");

        for (String ext : List.of(".bin", ".hex")) {
            Path sambaFix = FIXTURE_DIR.resolve("same70q21_samba" + ext);
            Path sambaMan = FIXTURE_DIR.resolve("same70q21_samba" + ext + ".manifest.json");
            assertTrue(Files.isRegularFile(sambaFix));
            assertTrue(Files.isRegularFile(sambaMan));
        }
    }

    @Test
    void rawBinaryFixturesContainValidVectorTables() throws IOException {
        // ATmega328P: 4-byte JMP (0x0C 0x94)
        byte[] m328 = Files.readAllBytes(FIXTURE_DIR.resolve("atmega328p_app.bin"));
        assertEquals((byte) 0x0C, m328[0]);
        assertEquals((byte) 0x94, m328[1]);

        // ATtiny85: 2-byte RJMP (0xCxxx)
        byte[] t85 = Files.readAllBytes(FIXTURE_DIR.resolve("attiny85_app.bin"));
        ByteBuffer t85Buf = ByteBuffer.wrap(t85).order(ByteOrder.LITTLE_ENDIAN);
        int op = t85Buf.getShort(0) & 0xFFFF;
        assertEquals(0xC000, op & 0xF000, "ATtiny85 vector must be RJMP (opcode 0xCxxx)");

        // SAMD21: Cortex-M SP in SRAM, Thumb reset
        byte[] samd = Files.readAllBytes(FIXTURE_DIR.resolve("samd21g18a_app.bin"));
        ByteBuffer samdBuf = ByteBuffer.wrap(samd).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(0x20008000, samdBuf.getInt(0), "SAMD21 initial SP must be 0x20008000");
        assertEquals(1, samdBuf.getInt(4) & 1, "SAMD21 reset vector must have Thumb bit set");

        // SAME70: Cortex-M SP in SRAM, Thumb reset
        byte[] same = Files.readAllBytes(FIXTURE_DIR.resolve("same70q21_app.bin"));
        ByteBuffer sameBuf = ByteBuffer.wrap(same).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(0x20460000, sameBuf.getInt(0), "SAME70 initial SP must be 0x20460000");
        assertEquals(1, sameBuf.getInt(4) & 1, "SAME70 reset vector must have Thumb bit set");
    }

    @Test
    void malformedFixturesAreWellFormed() throws IOException {
        for (String filename : MALFORMED_CASES) {
            Path fpath = MALFORMED_DIR.resolve(filename);
            Path mpath = MALFORMED_DIR.resolve(filename + ".manifest.json");
            String base = filename.replaceFirst("\\.[^.]+$", "");
            Path opath = ORACLE_MALFORMED_DIR.resolve(base + ".json");

            assertTrue(Files.isRegularFile(fpath), "Missing malformed fixture: " + fpath);
            assertTrue(Files.isRegularFile(mpath), "Missing malformed manifest: " + mpath);
            assertTrue(Files.isRegularFile(opath), "Missing malformed oracle: " + opath);

            String oracle = Files.readString(opath);
            assertTrue(oracle.contains("\"errorExpected\": true"));
            assertTrue(oracle.contains("\"diagnosticCode\""));
        }
    }
}
