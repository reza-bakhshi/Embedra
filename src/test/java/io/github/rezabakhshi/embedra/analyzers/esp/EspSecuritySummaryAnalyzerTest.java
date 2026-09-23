package io.github.rezabakhshi.embedra.analyzers.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.formats.esp.EspFlashRange;
import io.github.rezabakhshi.embedra.formats.esp.EspImageFooter;
import io.github.rezabakhshi.embedra.formats.esp.EspPartitionEntry;
import java.time.Duration;
import java.util.List;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;

class EspSecuritySummaryAnalyzerTest {
    @Test
    void reportsImageEvidenceWithoutClaimingUnavailableEfuseState() throws Exception {
        byte[] signatureSector = secureBootV2RsaSector();
        EspSecurityContext context = new EspSecurityContext(validDigestFooter(),
            signatureSector, 0x21000, List.of(
                partition(0, "factory", 0, 0, 0x10000, 0x10000, 1),
                partition(1, "nvs_keys", 1, 4, 0x9000, 0x1000, 0)));

        EspSecuritySummary report = new EspSecuritySummaryAnalyzer().analyze(context,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals(EspImageHashState.VERIFIED, report.imageHash().state());
        assertEquals(Confidence.VERIFIED, report.imageHash().confidence());
        assertEquals(1, report.signatureBlocks().size());
        EspSecureBootSignatureEvidence signature = report.signatureBlocks().get(0);
        assertEquals(EspSecureBootScheme.RSA_V2, signature.scheme());
        assertEquals(Confidence.DERIVED, signature.confidence());
        assertEquals(EspVerificationState.UNKNOWN,
            signature.cryptographicVerification());
        assertEquals(EspSecurityState.INDICATED,
            report.flashEncryption().state());
        assertEquals(List.of("factory"), report.flashEncryption().partitionLabels());
        assertEquals(EspNvsEncryptionState.KEY_PARTITION_PRESENT,
            report.nvsEncryption().state());
        assertEquals(EspSecurityState.UNAVAILABLE, report.secureBootEfuseState());
        assertEquals(EspSecurityState.UNAVAILABLE,
            report.flashEncryptionEfuseState());
        assertFalse(report.secureBootEnabled());
        assertTrue(report.detectorsRun().contains("secure-boot-v2-signature-blocks"));
        assertThrows(UnsupportedOperationException.class,
            () -> report.signatureBlocks().clear());
    }

    @Test
    void rejectsBadSignatureCrcAndDoesNotPromoteInvalidDigestOrFlags() throws Exception {
        byte[] signatureSector = secureBootV2RsaSector();
        signatureSector[100] ^= 1;
        EspSecurityContext context = new EspSecurityContext(invalidDigestFooter(),
            signatureSector, 0x21000, List.of(
                partition(0, "plain", 0, 0, 0x10000, 0x10000, 0)));

        EspSecuritySummary report = new EspSecuritySummaryAnalyzer().analyze(context,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals(EspImageHashState.INVALID, report.imageHash().state());
        assertTrue(report.signatureBlocks().isEmpty());
        assertEquals(EspSecurityState.NOT_INDICATED,
            report.flashEncryption().state());
        assertEquals(EspNvsEncryptionState.NOT_INDICATED,
            report.nvsEncryption().state());
        assertFalse(report.secureBootEnabled());
    }

    @Test
    void enforcesLimitsCancellationAndDefensiveCopies() throws Exception {
        byte[] sector = secureBootV2RsaSector();
        EspSecurityContext context = new EspSecurityContext(validDigestFooter(), sector,
            0x21000, List.of());
        sector[0] = 0;
        assertEquals(0xe7, context.signatureRegion()[0] & 0xff);
        byte[] returned = context.signatureRegion();
        returned[0] = 0;
        assertEquals(0xe7, context.signatureRegion()[0] & 0xff);

        ParserLimits tiny = new ParserLimits(1024, 1024, 1024, 10, 8,
            Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> new EspSecuritySummaryAnalyzer().analyze(context, tiny,
                CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> new EspSecuritySummaryAnalyzer().analyze(context,
                ParserLimits.defaults(), cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());
    }

    private static EspImageFooter validDigestFooter() {
        byte[] digest = new byte[32];
        digest[0] = 1;
        return footer(digest, digest);
    }

    private static EspImageFooter invalidDigestFooter() {
        byte[] stored = new byte[32];
        byte[] calculated = new byte[32];
        stored[0] = 1;
        calculated[0] = 2;
        return footer(stored, calculated);
    }

    private static EspImageFooter footer(byte[] stored, byte[] calculated) {
        return new EspImageFooter(new byte[0], new SourceRange(0x1df, 0),
            0xef, 0xef, new SourceRange(0x1df, 1), stored, calculated,
            new SourceRange(0x1e0, 32));
    }

    private static EspPartitionEntry partition(int index, String label, int type,
            int subtype, long offset, long length, long flags) {
        return new EspPartitionEntry(index, label, type, subtype,
            new EspFlashRange(offset, length), flags,
            new SourceRange(0x8000L + index * 32L, 32));
    }

    private static byte[] secureBootV2RsaSector() {
        byte[] sector = new byte[4096];
        sector[0] = (byte) 0xe7;
        sector[1] = 2;
        sector[4] = 0x5a;
        CRC32 crc = new CRC32();
        crc.update(sector, 0, 1196);
        long value = crc.getValue();
        sector[1196] = (byte) value;
        sector[1197] = (byte) (value >>> 8);
        sector[1198] = (byte) (value >>> 16);
        sector[1199] = (byte) (value >>> 24);
        return sector;
    }
}
