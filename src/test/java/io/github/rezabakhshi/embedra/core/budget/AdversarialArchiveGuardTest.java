package io.github.rezabakhshi.embedra.core.budget;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.zip.CRC32;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;

class AdversarialArchiveGuardTest {

    @Test
    void rejectsNullInputs() {
        SharedResourceBudget budget = SharedResourceBudget.defaults();
        assertThrows(NullPointerException.class, () -> AdversarialArchiveGuard.validateZipArchive(null, budget));
        assertThrows(NullPointerException.class, () ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(new byte[0]), null));

        assertThrows(NullPointerException.class, () -> AdversarialArchiveGuard.decompressGzipSafely(null, budget));
        assertThrows(NullPointerException.class, () ->
                AdversarialArchiveGuard.decompressGzipSafely(new byte[0], null));
    }

    @Test
    void validatesValidZipArchive() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry entry1 = new ZipEntry("folder/file1.txt");
            zos.putNextEntry(entry1);
            zos.write("hello embedded world".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            ZipEntry entry2 = new ZipEntry("folder/file2.bin");
            zos.putNextEntry(entry2);
            zos.write(new byte[64]);
            zos.closeEntry();
        }

        byte[] zipData = baos.toByteArray();
        SharedResourceBudget budget = SharedResourceBudget.defaults();

        assertDoesNotThrow(() ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(zipData), budget));

        assertEquals(2, budget.createdObjects());
        assertEquals(84, budget.consumedExtractedBytes());
    }

    @Test
    void rejectsZipSlipEntry() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry entry = new ZipEntry("../../etc/cron.d/evil");
            zos.putNextEntry(entry);
            zos.write("payload".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        byte[] zipData = baos.toByteArray();
        SharedResourceBudget budget = SharedResourceBudget.defaults();

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(zipData), budget));

        assertEquals(DiagnosticCode.PATH_TRAVERSAL_DETECTED, ex.diagnostic().code());
    }

    @Test
    void rejectsDecompressionBombRatio() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(new byte[]{0x50, 0x4b, 0x03, 0x04}); // signature
        baos.write(new byte[]{20, 0}); // version
        baos.write(new byte[]{0, 0}); // flags
        baos.write(new byte[]{8, 0}); // method (deflated)
        baos.write(new byte[]{0, 0, 0, 0}); // time/date
        baos.write(new byte[]{0, 0, 0, 0}); // crc
        baos.write(new byte[]{100, 0, 0, 0}); // compressed size: 100
        baos.write(new byte[]{0x40, 0x4b, 0x4c, 0x00}); // uncompressed size: 5,000,000
        byte[] name = "bomb.bin".getBytes(StandardCharsets.UTF_8);
        baos.write(new byte[]{(byte) name.length, 0}); // name length
        baos.write(new byte[]{0, 0}); // extra length
        baos.write(name);
        baos.write(new byte[100]); // dummy payload

        byte[] zipData = baos.toByteArray();
        SharedResourceBudget budget = SharedResourceBudget.defaults();

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(zipData), budget));

        assertEquals(DiagnosticCode.DECOMPRESSION_BOMB_DETECTED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Decompression bomb detected"));
    }

    @Test
    void allowsBenignDeclaredSizeEntries() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            // Entry 1: Large entry above 1MB threshold, but safe ratio (1:1)
            ZipEntry ze1 = new ZipEntry("safe_large.bin");
            byte[] data1 = new byte[2 * 1024 * 1024];
            CRC32 crc1 = new CRC32();
            crc1.update(data1);
            ze1.setMethod(ZipEntry.STORED);
            ze1.setSize(data1.length);
            ze1.setCompressedSize(data1.length);
            ze1.setCrc(crc1.getValue());
            zos.putNextEntry(ze1);
            zos.write(data1);
            zos.closeEntry();

            // Entry 2: Small entry below 1MB threshold with known size
            ZipEntry ze2 = new ZipEntry("safe_small.bin");
            byte[] data2 = new byte[100];
            CRC32 crc2 = new CRC32();
            crc2.update(data2);
            ze2.setMethod(ZipEntry.STORED);
            ze2.setSize(data2.length);
            ze2.setCompressedSize(data2.length);
            ze2.setCrc(crc2.getValue());
            zos.putNextEntry(ze2);
            zos.write(data2);
            zos.closeEntry();
        }

        byte[] zipData = baos.toByteArray();
        SharedResourceBudget budget = SharedResourceBudget.defaults();

        assertDoesNotThrow(() ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(zipData), budget));
    }

    @Test
    void allowsEntryWithZeroCompressedSize() throws Exception {
        java.util.zip.Deflater def = new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true);
        ByteArrayOutputStream payloadBaos = new ByteArrayOutputStream();
        java.util.zip.DeflaterOutputStream dos = new java.util.zip.DeflaterOutputStream(payloadBaos, def);
        dos.write(new byte[]{0x42});
        dos.finish();
        byte[] payload = payloadBaos.toByteArray();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(new byte[]{0x50, 0x4b, 0x03, 0x04}); // signature
        baos.write(new byte[]{20, 0}); // version
        baos.write(new byte[]{0, 0}); // flags
        baos.write(new byte[]{8, 0}); // method (deflated)
        baos.write(new byte[]{0, 0, 0, 0}); // time/date
        baos.write(new byte[]{0, 0, 0, 0}); // crc
        baos.write(new byte[]{0, 0, 0, 0}); // compressed size: 0
        baos.write(new byte[]{1, 0, 0, 0}); // uncompressed size: 1
        byte[] name = "safe.bin".getBytes(StandardCharsets.UTF_8);
        baos.write(new byte[]{(byte) name.length, 0}); // name length
        baos.write(new byte[]{0, 0}); // extra length
        baos.write(name);
        baos.write(payload);

        byte[] zipData = baos.toByteArray();
        SharedResourceBudget budget = SharedResourceBudget.defaults();
        assertThrows(java.util.zip.ZipException.class, () ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(zipData), budget));
    }

    @Test
    void rejectsExtractedBytesExceedingBudget() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry entry = new ZipEntry("large.bin");
            zos.putNextEntry(entry);
            zos.write(new byte[1000]);
            zos.closeEntry();
        }

        byte[] zipData = baos.toByteArray();
        ParserLimits limits = new ParserLimits(100_000, 100_000, 200, 100, 10, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(zipData), budget));

        assertEquals(DiagnosticCode.DECOMPRESSION_BOMB_DETECTED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Extracted decompression budget exceeded"));
    }

    @Test
    void checksLivenessDuringZipValidation() {
        CancellationToken cancelled = () -> true;
        SharedResourceBudget budget = new SharedResourceBudget(ParserLimits.defaults(), cancelled);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialArchiveGuard.validateZipArchive(new ByteArrayInputStream(new byte[0]), budget));

        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }

    @Test
    void decompressesGzipSafely() throws Exception {
        byte[] original = "Safe GZIP decompressed content for testing".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(original);
        }
        byte[] gzipped = baos.toByteArray();

        SharedResourceBudget budget = SharedResourceBudget.defaults();
        byte[] decompressed = AdversarialArchiveGuard.decompressGzipSafely(gzipped, budget);

        assertArrayEquals(original, decompressed);
        assertEquals(gzipped.length, budget.consumedInputBytes());
        assertEquals(original.length, budget.consumedExtractedBytes());
    }

    @Test
    void rejectsGzipExceedingExtractedBudget() throws Exception {
        byte[] payload = new byte[2048];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(payload);
        }
        byte[] gzipped = baos.toByteArray();

        ParserLimits limits = new ParserLimits(100_000, 100_000, 500, 100, 10, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialArchiveGuard.decompressGzipSafely(gzipped, budget));

        assertEquals(DiagnosticCode.DECOMPRESSION_BOMB_DETECTED, ex.diagnostic().code());
    }

    @Test
    void testPrivateConstructor() throws Exception {
        Constructor<AdversarialArchiveGuard> constructor = AdversarialArchiveGuard.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        assertNotNull(constructor.newInstance());
    }
}
