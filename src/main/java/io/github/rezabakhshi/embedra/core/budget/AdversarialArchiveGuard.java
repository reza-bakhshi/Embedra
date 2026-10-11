package io.github.rezabakhshi.embedra.core.budget;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Validates archives against decompression bombs (zip bombs, 42.zip, recursive compression)
 * and Zip Slip path traversal attacks under a SharedResourceBudget (AN-009, Section 5.3).
 */
public final class AdversarialArchiveGuard {

    /** Maximum allowed ratio between uncompressed and compressed size (100:1) for large payloads. */
    public static final double MAX_DECOMPRESSION_RATIO = 100.0;

    /** Minimum size in bytes before decompression ratio enforcement kicks in. */
    public static final long RATIO_CHECK_THRESHOLD_BYTES = 1024 * 1024L;

    private AdversarialArchiveGuard() {
    }

    /**
     * Inspects a ZIP archive from an input stream, verifying entry paths and bounded extraction.
     */
    public static void validateZipArchive(
            InputStream rawZipStream,
            SharedResourceBudget budget) throws DiagnosticException, IOException {
        Objects.requireNonNull(rawZipStream, "rawZipStream must not be null");
        Objects.requireNonNull(budget, "budget must not be null");

        budget.checkLiveness();

        try (ZipInputStream zis = new ZipInputStream(rawZipStream)) {
            ZipEntry entry;
            byte[] buffer = new byte[8192];

            while ((entry = zis.getNextEntry()) != null) {
                budget.checkLiveness();
                budget.trackObjects(1);

                // Check path safety (Zip Slip prevention)
                AdversarialPathGuard.validateRelativePathSafety(entry.getName());

                // If entry uncompressed size is known and suspicious
                long declaredSize = entry.getSize();
                long compressedSize = entry.getCompressedSize();
                if (declaredSize > 0 && compressedSize > 0 && declaredSize > RATIO_CHECK_THRESHOLD_BYTES) {
                    double ratio = (double) declaredSize / (double) compressedSize;
                    if (ratio > MAX_DECOMPRESSION_RATIO) {
                        throw new DiagnosticException(Diagnostic.error(
                                DiagnosticCode.DECOMPRESSION_BOMB_DETECTED,
                                String.format("Decompression bomb detected in entry '%s': ratio %.1f exceeds max %.1f",
                                        entry.getName(), ratio, MAX_DECOMPRESSION_RATIO)));
                    }
                }

                // Decompress bounded bytes
                long entryExtracted = 0;
                int read;
                while ((read = zis.read(buffer)) != -1) {
                    entryExtracted += read;
                    budget.trackExtractedBytes(read);
                }

                zis.closeEntry();
            }
        }
    }

    /**
     * Decompresses GZIP bytes safely under the shared budget.
     */
    public static byte[] decompressGzipSafely(
            byte[] gzipBytes,
            SharedResourceBudget budget) throws DiagnosticException, IOException {
        Objects.requireNonNull(gzipBytes, "gzipBytes must not be null");
        Objects.requireNonNull(budget, "budget must not be null");

        budget.trackInputBytes(gzipBytes.length);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(gzipBytes);
             GZIPInputStream gzis = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int read;
            while ((read = gzis.read(buffer)) != -1) {
                budget.trackExtractedBytes(read);
                baos.write(buffer, 0, read);
            }

            return baos.toByteArray();
        }
    }
}
