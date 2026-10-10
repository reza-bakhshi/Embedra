package io.github.rezabakhshi.embedra.core.fixture;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DeterministicFixtureGeneratorTest {

    @Test
    void verifiesBitForBitIdentityOnDeterministicGenerator() throws DiagnosticException {
        DeterministicFixtureGenerator generator = new DeterministicFixtureGenerator() {
            @Override
            public String generatorId() {
                return "test.deterministic";
            }

            @Override
            public byte[] generate(Map<String, Object> parameters) {
                return new byte[] {0x01, 0x02, 0x03, 0x04};
            }
        };

        byte[] result = DeterministicGenerationRunner.generateAndVerify(generator, Map.of());
        assertArrayEquals(new byte[] {0x01, 0x02, 0x03, 0x04}, result);
    }

    @Test
    void detectsAndRejectsNonDeterministicGenerator() {
        AtomicInteger counter = new AtomicInteger(0);
        DeterministicFixtureGenerator badGenerator = new DeterministicFixtureGenerator() {
            @Override
            public String generatorId() {
                return "test.nondeterministic";
            }

            @Override
            public byte[] generate(Map<String, Object> parameters) {
                // Returns different bytes on successive calls
                return new byte[] {(byte) counter.incrementAndGet()};
            }
        };

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                DeterministicGenerationRunner.generateAndVerify(badGenerator, Map.of()));
        assertEquals(DiagnosticCode.FIXTURE_MANIFEST_INVALID, ex.diagnostic().code());
        assertTrue(ex.diagnostic().message().contains("Non-deterministic fixture generation"));
    }

    @Test
    void builtInArmVectorGeneratorProducesReproducibleBytes() throws DiagnosticException {
        DeterministicFixtureGenerator armGen = DeterministicGenerationRunner.armVectorGenerator();
        assertEquals("embedra.synthetic.arm-vector", armGen.generatorId());

        Map<String, Object> params = Map.of(
                "stackPointer", 0x20005000,
                "resetVector", 0x08000101,
                "vectorCount", 16);

        byte[] bytes = DeterministicGenerationRunner.generateAndVerify(armGen, params);
        assertEquals(64, bytes.length);

        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(0x20005000, buf.getInt(0));
        assertEquals(0x08000101, buf.getInt(4));
    }

    @Test
    void builtInRiscvVectorGeneratorProducesReproducibleBytes() throws DiagnosticException {
        DeterministicFixtureGenerator riscvGen = DeterministicGenerationRunner.riscvVectorGenerator();
        assertEquals("embedra.synthetic.riscv-vector", riscvGen.generatorId());

        Map<String, Object> params = Map.of("wordCount", 16);
        byte[] bytes = DeterministicGenerationRunner.generateAndVerify(riscvGen, params);
        assertEquals(64, bytes.length);

        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(0xff010113, buf.getInt(0)); // addi sp, sp, -16
        assertEquals(0x00112623, buf.getInt(4)); // sw ra, 12(sp)
    }

    @Test
    void builtInFlashPartitionGeneratorProducesValidChecksum() throws DiagnosticException {
        DeterministicFixtureGenerator partGen = DeterministicGenerationRunner.flashPartitionGenerator();
        assertEquals("embedra.synthetic.flash-partition", partGen.generatorId());

        byte[] bytes = DeterministicGenerationRunner.generateAndVerify(partGen, Map.of());
        assertTrue(bytes.length >= 0xC00);

        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        // First entry magic 0x50AA
        assertEquals((short) 0x50AA, buf.getShort(0));
    }

    @Test
    void rejectsNullReturnedBytesFromGenerator() {
        DeterministicFixtureGenerator nullGen = new DeterministicFixtureGenerator() {
            @Override
            public String generatorId() {
                return "test.null";
            }

            @Override
            public byte[] generate(Map<String, Object> parameters) {
                return null;
            }
        };

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                DeterministicGenerationRunner.generateAndVerify(nullGen, Map.of()));
        assertEquals(DiagnosticCode.FIXTURE_MANIFEST_INVALID, ex.diagnostic().code());
    }

    @Test
    void rejectsDifferentLengthRunsFromGenerator() {
        AtomicInteger counter = new AtomicInteger(0);
        DeterministicFixtureGenerator diffLenGen = new DeterministicFixtureGenerator() {
            @Override
            public String generatorId() {
                return "test.difflen";
            }

            @Override
            public byte[] generate(Map<String, Object> parameters) {
                return new byte[counter.incrementAndGet()];
            }
        };

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                DeterministicGenerationRunner.generateAndVerify(diffLenGen, Map.of()));
        assertEquals(DiagnosticCode.FIXTURE_MANIFEST_INVALID, ex.diagnostic().code());
    }

    @Test
    void generatorsRunSuccessfullyWithDefaultParameters() throws DiagnosticException {
        // armVectorGenerator with default params
        byte[] arm = DeterministicGenerationRunner.generateAndVerify(
                DeterministicGenerationRunner.armVectorGenerator(), Map.of());
        assertEquals(64, arm.length);

        // riscvVectorGenerator with default params
        byte[] riscv = DeterministicGenerationRunner.generateAndVerify(
                DeterministicGenerationRunner.riscvVectorGenerator(), Map.of());
        assertEquals(64, riscv.length);

        // flashPartitionGenerator with custom size
        byte[] part = DeterministicGenerationRunner.generateAndVerify(
                DeterministicGenerationRunner.flashPartitionGenerator(),
                Map.of("totalSize", 0x1000));
        assertEquals(0x1000, part.length);
    }
}
