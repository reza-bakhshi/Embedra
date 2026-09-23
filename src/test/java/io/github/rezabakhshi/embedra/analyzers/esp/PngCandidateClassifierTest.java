package io.github.rezabakhshi.embedra.analyzers.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import org.junit.jupiter.api.Test;

class PngCandidateClassifierTest {
    private static final byte[] SIGNATURE = {
        (byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
    };

    @Test
    void classifiesValidInvalidCrcZeroDimensionTruncationAndCollision()
            throws Exception {
        byte[] valid = png(1, 1);
        assertEquals(PngCandidateStatus.VALID, classify(valid));
        byte[] badCrc = valid.clone();
        badCrc[29] ^= 1;
        assertEquals(PngCandidateStatus.INVALID_CRC, classify(badCrc));
        assertEquals(PngCandidateStatus.INVALID_HEADER, classify(png(111, 0)));
        assertEquals(PngCandidateStatus.TRUNCATED,
            classify(Arrays.copyOf(valid, valid.length - 2)));
        assertEquals(PngCandidateStatus.SIGNATURE_COLLISION,
            classify(SIGNATURE));
        assertEquals(PngCandidateStatus.NOT_PNG, classify(new byte[8]));
        byte[] collision = new byte[20];
        System.arraycopy(SIGNATURE, 0, collision, 0, SIGNATURE.length);
        collision[11] = 1;
        assertEquals(PngCandidateStatus.SIGNATURE_COLLISION, classify(collision));
        assertEquals(PngCandidateStatus.RESOURCE_LIMIT,
            PngCandidateClassifier.classify(valid,
                ParserLimits.defaults().withMaxAllocationBytes(32),
                CancellationToken.none()));
        assertThrows(DiagnosticException.class, () ->
            PngCandidateClassifier.classify(valid, ParserLimits.defaults(), () -> true));
    }

    @Test
    void restrictedRealCandidateIsInvalidHeader() throws Exception {
        Path dump = Path.of("esp32s3_ctf_dump_4MB.bin");
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.isRegularFile(dump),
            "restricted local fixture is intentionally absent from public CI");
        byte[] bytes = Files.readAllBytes(dump);
        assertEquals("837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de",
            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
        assertEquals(PngCandidateStatus.INVALID_HEADER,
            classify(Arrays.copyOfRange(bytes, 0x25bbb, 0x25bbb + 33)));
    }

    private static PngCandidateStatus classify(byte[] input) throws Exception {
        return PngCandidateClassifier.classify(input, ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static byte[] png(int width, int height) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(SIGNATURE);
        byte[] ihdr = new byte[13];
        putInt(ihdr, 0, width);
        putInt(ihdr, 4, height);
        ihdr[8] = 8;
        ihdr[9] = 2;
        chunk(output, "IHDR", ihdr);
        Deflater compressor = new Deflater();
        compressor.setInput(new byte[] {0, 0, 0, 0});
        compressor.finish();
        byte[] compressed = new byte[32];
        int count = compressor.deflate(compressed);
        compressor.end();
        chunk(output, "IDAT", Arrays.copyOf(compressed, count));
        chunk(output, "IEND", new byte[0]);
        return output.toByteArray();
    }

    private static void chunk(ByteArrayOutputStream output, String type, byte[] data) {
        byte[] name = type.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] length = new byte[4];
        putInt(length, 0, data.length);
        output.writeBytes(length);
        output.writeBytes(name);
        output.writeBytes(data);
        CRC32 crc = new CRC32();
        crc.update(name);
        crc.update(data);
        byte[] checksum = new byte[4];
        putInt(checksum, 0, (int) crc.getValue());
        output.writeBytes(checksum);
    }

    private static void putInt(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 24);
        bytes[offset + 1] = (byte) (value >>> 16);
        bytes[offset + 2] = (byte) (value >>> 8);
        bytes[offset + 3] = (byte) value;
    }
}
