package io.github.rezabakhshi.embedra.analyzers.yara;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.crypto.tables.CryptoTableDatabase;
import io.github.rezabakhshi.embedra.analyzers.crypto.tables.CryptoTableSignature;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class YaraScannerTest {

    @Test
    void matchesBuiltinCryptoRules() throws Exception {
        CompiledYaraRuleset ruleset = CompiledYaraRuleset.loadBuiltinRules(true, false);
        assertTrue(ruleset.ruleCount() >= 10);

        YaraScanner scanner = new YaraScanner(ruleset);

        // Buffer containing AES Sbox and ChaCha20 constant
        byte[] buffer = new byte[1024];
        // AES forward S-box header
        byte[] aesSbox = new byte[] {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b,
            (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b,
            (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76
        };
        System.arraycopy(aesSbox, 0, buffer, 0x100, aesSbox.length);

        // ChaCha20 constant
        byte[] chacha = "expand 32-byte k".getBytes(StandardCharsets.ISO_8859_1);
        System.arraycopy(chacha, 0, buffer, 0x200, chacha.length);

        List<YaraMatch> matches = scanner.scan(buffer, 0x1000L, CancellationToken.none());
        assertFalse(matches.isEmpty());

        boolean foundAes = false;
        boolean foundChaCha = false;
        for (YaraMatch m : matches) {
            if ("AES_Forward_Sbox".equals(m.ruleName())) {
                foundAes = true;
                assertEquals(0x1100L, m.address());
                assertEquals("CIPHER_SYMMETRIC", m.category());
                assertEquals("AES", m.algorithm());
            } else if ("ChaCha20_Constant".equals(m.ruleName())) {
                foundChaCha = true;
                assertEquals(0x1200L, m.address());
                assertEquals("CIPHER_SYMMETRIC", m.category());
            }
        }
        assertTrue(foundAes, "Should have matched AES_Forward_Sbox");
        assertTrue(foundChaCha, "Should have matched ChaCha20_Constant");
    }

    @Test
    void matchesBuiltinFormatAndContainerRules() throws Exception {
        CompiledYaraRuleset ruleset = CompiledYaraRuleset.loadBuiltinRules(false, true);
        YaraScanner scanner = new YaraScanner(ruleset);

        byte[] buffer = new byte[512];
        // SquashFS little-endian magic 'hsqs' at offset 0
        buffer[0] = 'h';
        buffer[1] = 's';
        buffer[2] = 'q';
        buffer[3] = 's';

        // ELF magic at offset 0x40
        buffer[0x40] = 0x7F;
        buffer[0x41] = 'E';
        buffer[0x42] = 'L';
        buffer[0x43] = 'F';

        // ZIP magic at offset 0x80
        buffer[0x80] = 0x50;
        buffer[0x81] = 0x4B;
        buffer[0x82] = 0x03;
        buffer[0x83] = 0x04;

        List<YaraMatch> matches = scanner.scan(buffer, 0x8000L, CancellationToken.none());
        assertEquals(3, matches.size());

        boolean foundSqsh = false;
        boolean foundElf = false;
        boolean foundZip = false;

        for (YaraMatch m : matches) {
            if ("SquashFS_Superblock".equals(m.ruleName())) {
                foundSqsh = true;
                assertEquals(0x8000L, m.address());
            } else if ("ELF_Header".equals(m.ruleName())) {
                foundElf = true;
                assertEquals(0x8040L, m.address());
            } else if ("ZIP_Archive".equals(m.ruleName())) {
                foundZip = true;
                assertEquals(0x8080L, m.address());
            }
        }

        assertTrue(foundSqsh);
        assertTrue(foundElf);
        assertTrue(foundZip);
    }

    @Test
    void convertsYaraRulesToCryptoTableDatabaseSignatures() throws Exception {
        CompiledYaraRuleset ruleset = CompiledYaraRuleset.loadBuiltinRules(true, false);
        List<CryptoTableSignature> sigs = CryptoTableDatabase.fromYara(ruleset);
        assertFalse(sigs.isEmpty());

        CryptoTableDatabase db = new CryptoTableDatabase(sigs);
        byte[] data = new byte[] {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b,
            (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b,
            (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76
        };

        List<CryptoFinding> findings = db.scan(data, 0x1000L, ParserLimits.defaults(), CancellationToken.none());
        assertFalse(findings.isEmpty());
        assertEquals("AES_128", findings.get(0).algorithm().name());
    }

    @Test
    void enforcesCancellationAndInputLimits() {
        CompiledYaraRuleset ruleset = CompiledYaraRuleset.loadBuiltinRules(true, true);
        YaraScanner scanner = new YaraScanner(ruleset);

        CancellationToken cancelled = () -> true;
        byte[] buf = new byte[100];
        assertThrows(DiagnosticException.class, () -> scanner.scan(buf, 0L, cancelled));

        ParserLimits smallLimit = new ParserLimits(50, 1024, 1024, 100, 10,
                ParserLimits.defaults().maxWallTime());
        YaraScanner smallScanner = new YaraScanner(ruleset, smallLimit);
        assertThrows(DiagnosticException.class, () -> smallScanner.scan(buf, 0L, CancellationToken.none()));
    }
}
