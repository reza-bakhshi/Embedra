package io.github.rezabakhshi.embedra.targets.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Automated verification for the T089 STM8 fixture suite and manifests. */
class Stm8FixtureTest {
    private static final Path FIXTURE_DIR = Path.of("src/test/resources/fixtures/stm8");

    private static final Path MALFORMED_DIR = FIXTURE_DIR.resolve("malformed");

    private static final Path ORACLE_DIR = Path.of("src/test/resources/oracles/stm8");


    private static final List<String> REPRESENTATIVE_PARTS = List.of(
        "STM8S003F3P6", "STM8S103F3P6", "STM8S208RBT6",
        "STM8L151C8T6", "STM8L152R8T6", "STM8AF5288TAY",
        "STM8AL3188TA", "STM8T143AU"
    );

    @Test
    void allRepresentativePartsHaveAllFourFormatsAndManifests() throws IOException {
        for (String part : REPRESENTATIVE_PARTS) {
            for (String ext : List.of(".bin", ".hex", ".s19", ".elf")) {
                Path fixturePath = FIXTURE_DIR.resolve(part + ext);
                Path manifestPath = FIXTURE_DIR.resolve(part + ext + ".manifest.json");

                assertTrue(Files.isRegularFile(fixturePath), "Fixture must exist: " + fixturePath);
                assertTrue(Files.isRegularFile(manifestPath), "Manifest must exist: " + manifestPath);

                String manifest = Files.readString(manifestPath);
                assertTrue(manifest.contains("\"target\": \"" + part + "\""));
                assertTrue(manifest.contains("\"redistributionStatus\": \"REDISTRIBUTABLE\""));
                assertTrue(manifest.contains("\"requirements\""));
            }

            Path oraclePath = ORACLE_DIR.resolve(part + ".json");
            assertTrue(Files.isRegularFile(oraclePath), "Oracle must exist: " + oraclePath);
            String oracle = Files.readString(oraclePath);
            assertTrue(oracle.contains("\"part\": \"" + part + "\""));
            assertTrue(oracle.contains("\"flashBase\": \"0x008000\""));
            assertTrue(oracle.contains("\"vectorCount\": 32"));
            assertTrue(oracle.contains("\"resetVector\": \"0x008080\""));
        }
    }

    @Test
    void rawBinaryFixturesContainValidThirtyTwoVectorTable() throws IOException {
        for (String part : REPRESENTATIVE_PARTS) {
            Path binPath = FIXTURE_DIR.resolve(part + ".bin");
            byte[] bytes = Files.readAllBytes(binPath);
            assertTrue(bytes.length >= 128, "Binary must be at least 128 bytes for 32 vectors");

            for (int slot = 0; slot < 32; slot++) {
                int offset = slot * 4;
                int opcode = bytes[offset] & 0xFF;
                assertEquals(0x82, opcode, "Slot " + slot + " must start with 0x82 JPF opcode");

                int target = ((bytes[offset + 1] & 0xFF) << 16)
                    | ((bytes[offset + 2] & 0xFF) << 8)
                    | (bytes[offset + 3] & 0xFF);
                if (slot == 0) {
                    assertEquals(0x008080, target, "Reset vector must target 0x008080");
                } else {
                    assertEquals(0x008090, target, "Default interrupt handler must target 0x008090");
                }
            }
        }
    }

    @Test
    void malformedFixturesAreWellFormedAndDocumented() throws IOException {
        List<String> malformedNames = List.of(
            "stm8s003_checksum.hex",
            "stm8s103_truncated.bin",
            "stm8l151_checksum.s19",
            "stm8s208_overlapping.hex",
            "stm8af_invalid_opcode.bin",
            "stm8al_out_of_bounds_vector.bin"
        );

        for (String mname : malformedNames) {
            Path mpath = MALFORMED_DIR.resolve(mname);
            Path manPath = MALFORMED_DIR.resolve(mname + ".manifest.json");
            Path oraclePath = ORACLE_DIR.resolve("malformed").resolve(mname + ".json");

            assertTrue(Files.isRegularFile(mpath), "Malformed fixture must exist: " + mpath);
            assertTrue(Files.isRegularFile(manPath), "Manifest must exist: " + manPath);
            assertTrue(Files.isRegularFile(oraclePath), "Oracle must exist: " + oraclePath);

            String oracle = Files.readString(oraclePath);
            assertTrue(oracle.contains("\"expectedOutcome\": \"FAIL_CLOSED_VALIDATION\""));
        }
    }
}
