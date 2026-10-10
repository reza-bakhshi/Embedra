package io.github.rezabakhshi.embedra.core.fixture;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

/**
 * Runner that executes generators twice in isolated invocations and enforces bit-for-bit identity.
 */
public final class DeterministicGenerationRunner {

    private DeterministicGenerationRunner() {
    }

    /**
     * Executes generation twice and enforces bit-for-bit reproducibility.
     *
     * @param generator generator implementation
     * @param parameters generation parameters
     * @return verified byte-identical fixture bytes
     * @throws DiagnosticException if runs differ or generation fails
     */
    public static byte[] generateAndVerify(
            DeterministicFixtureGenerator generator,
            Map<String, Object> parameters) throws DiagnosticException {
        Objects.requireNonNull(generator, "generator");
        Objects.requireNonNull(parameters, "parameters");

        byte[] firstRun;
        byte[] secondRun;
        try {
            firstRun = generator.generate(parameters);
            secondRun = generator.generate(parameters);
        } catch (Exception exception) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                    "Generator '" + generator.generatorId() + "' threw exception: " + exception.getMessage()));
        }

        if (firstRun == null || secondRun == null) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                    "Generator '" + generator.generatorId() + "' returned null bytes"));
        }

        if (!Arrays.equals(firstRun, secondRun)) {
            int diffIndex = findMismatch(firstRun, secondRun);
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                    "Non-deterministic fixture generation in '" + generator.generatorId()
                            + "': byte mismatch at offset 0x" + Integer.toHexString(diffIndex)
                            + " (lengths: " + firstRun.length + " vs " + secondRun.length + ")"));
        }

        return firstRun;
    }

    /**
     * Built-in deterministic generator for minimal ARM Cortex-M vector tables.
     */
    public static DeterministicFixtureGenerator armVectorGenerator() {
        return new DeterministicFixtureGenerator() {
            @Override
            public String generatorId() {
                return "embedra.synthetic.arm-vector";
            }

            @Override
            public byte[] generate(Map<String, Object> parameters) {
                int stackPointer = getInt(parameters, "stackPointer", 0x20005000);
                int resetVector = getInt(parameters, "resetVector", 0x08000101);
                int nmiVector = getInt(parameters, "nmiVector", resetVector);
                int hardFaultVector = getInt(parameters, "hardFaultVector", resetVector);
                int vectorCount = getInt(parameters, "vectorCount", 16);

                ByteBuffer buffer = ByteBuffer.allocate(vectorCount * 4).order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt(stackPointer);
                buffer.putInt(resetVector);
                buffer.putInt(nmiVector);
                buffer.putInt(hardFaultVector);
                for (int i = 4; i < vectorCount; i++) {
                    buffer.putInt(resetVector);
                }
                return buffer.array();
            }
        };
    }

    /**
     * Built-in deterministic generator for minimal RISC-V reset sequences.
     */
    public static DeterministicFixtureGenerator riscvVectorGenerator() {
        return new DeterministicFixtureGenerator() {
            @Override
            public String generatorId() {
                return "embedra.synthetic.riscv-vector";
            }

            @Override
            public byte[] generate(Map<String, Object> parameters) {
                int wordCount = getInt(parameters, "wordCount", 16);
                ByteBuffer buffer = ByteBuffer.allocate(wordCount * 4).order(ByteOrder.LITTLE_ENDIAN);
                // addi sp, sp, -16 : 0x1101
                // sw ra, 12(sp)    : 0x4102 or full 32-bit: addi x2, x2, -16 (0xff010113)
                buffer.putInt(0xff010113); // addi sp, sp, -16
                buffer.putInt(0x00112623); // sw ra, 12(sp)
                buffer.putInt(0x00000013); // nop
                buffer.putInt(0x0000006f); // j . (infinite loop)
                for (int i = 4; i < wordCount; i++) {
                    buffer.putInt(0x00000013); // nop padding
                }
                return buffer.array();
            }
        };
    }

    /**
     * Built-in deterministic generator for partition table structures with MD5 checksum.
     */
    public static DeterministicFixtureGenerator flashPartitionGenerator() {
        return new DeterministicFixtureGenerator() {
            @Override
            public String generatorId() {
                return "embedra.synthetic.flash-partition";
            }

            @Override
            public byte[] generate(Map<String, Object> parameters) {
                // Generates standard 0xC000 size partition table area (or minimal 0xC00 area)
                int totalSize = getInt(parameters, "totalSize", 0xC00);
                ByteBuffer buffer = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN);

                // Entry 1: nvs (type 0x01, subtype 0x00, offset 0x9000, size 0x6000)
                writePartitionEntry(buffer, "nvs", (byte) 0x01, (byte) 0x00, 0x9000, 0x6000, 0);
                // Entry 2: factory (type 0x00, subtype 0x00, offset 0x10000, size 0x100000)
                writePartitionEntry(buffer, "factory", (byte) 0x00, (byte) 0x00, 0x10000, 0x100000, 0);

                // End marker with MD5 checksum
                buffer.putShort((short) 0xEBEB); // MD5 partition entry magic
                buffer.put((byte) 0);
                buffer.put((byte) 0);
                buffer.putInt(0); // offset
                buffer.putInt(0); // size
                // 16 bytes name = zero
                for (int i = 0; i < 16; i++) {
                    buffer.put((byte) 0);
                }
                buffer.putInt(0); // flags

                // Compute MD5 over preceding entries (position up to offset 32 before this entry)
                int dataEnd = buffer.position() - 32;
                byte[] dataForMd5 = Arrays.copyOfRange(buffer.array(), 0, dataEnd);
                try {
                    MessageDigest md5 = MessageDigest.getInstance("MD5");
                    byte[] md5Digest = md5.digest(dataForMd5);
                    buffer.position(buffer.position() - 16);
                    buffer.put(md5Digest);
                } catch (NoSuchAlgorithmException exception) {
                    throw new IllegalStateException("MD5 not found", exception);
                }

                return buffer.array();
            }

            private void writePartitionEntry(
                    ByteBuffer buffer,
                    String name,
                    byte type,
                    byte subtype,
                    int offset,
                    int size,
                    int flags) {
                buffer.putShort((short) 0x50AA); // Magic
                buffer.put(type);
                buffer.put(subtype);
                buffer.putInt(offset);
                buffer.putInt(size);
                byte[] nameBytes = new byte[16];
                byte[] src = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                System.arraycopy(src, 0, nameBytes, 0, Math.min(src.length, 16));
                buffer.put(nameBytes);
                buffer.putInt(flags);
            }
        };
    }

    private static int findMismatch(byte[] a, byte[] b) {
        int limit = Math.min(a.length, b.length);
        for (int i = 0; i < limit; i++) {
            if (a[i] != b[i]) {
                return i;
            }
        }
        return limit;
    }

    private static int getInt(Map<String, Object> params, String key, int defaultValue) {
        Object val = params.get(key);
        if (val instanceof Number n) {
            return n.intValue();
        }
        return defaultValue;
    }
}
