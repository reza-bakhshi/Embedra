package io.github.rezabakhshi.embedra.analyzers.ctf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.StringProvenance;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class CtfEntityScannerTest {

    @Test
    void detectsUrlEndpoints() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x1000L, 26, StringEncoding.ASCII, "https://api.firmware.io/v1",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x1020L, 20, StringEncoding.ASCII, "mqtt://broker.hive.org",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x1040L, 22, StringEncoding.ASCII, "coap://[fe80::1]:5683",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x1060L, 18, StringEncoding.ASCII, "ws://socket.dev:8080",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        List<CtfEntity> entities = scanner.scanStrings(strings, CtfScanOptions.defaults(), CancellationToken.none());

        assertEquals(4, entities.size());
        assertTrue(entities.stream().allMatch(e -> e.category() == CtfEntityCategory.ENDPOINT));
        assertTrue(entities.stream().allMatch(e -> e.type() == CtfEntityType.URL));
    }

    @Test
    void detectsIpAddressesAndDomains() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x2000L, 13, StringEncoding.ASCII, "192.168.1.100",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x2020L, 19, StringEncoding.ASCII, "backend.device.internal",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x2040L, 15, StringEncoding.ASCII, "ota.firmware.com",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        List<CtfEntity> entities = scanner.scanStrings(strings, CtfScanOptions.defaults(), CancellationToken.none());

        assertEquals(3, entities.size());
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.IP_ADDRESS
                && e.value().equals("192.168.1.100")));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.DOMAIN
                && e.value().equals("backend.device.internal")));
    }

    @Test
    void detectsMqttTopics() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x3000L, 17, StringEncoding.ASCII, "device/+/telemetry",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x3020L, 15, StringEncoding.ASCII, "factory/node1/#",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        List<CtfEntity> entities = scanner.scanStrings(strings, CtfScanOptions.defaults(), CancellationToken.none());

        assertEquals(2, entities.size());
        assertTrue(entities.stream().allMatch(e -> e.type() == CtfEntityType.MQTT_TOPIC));
    }

    @Test
    void detectsBleUuidsAndMacAddresses() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x4000L, 36, StringEncoding.ASCII, "0000180d-0000-1000-8000-00805f9b34fb",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x4030L, 6, StringEncoding.ASCII, "0x180D",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x4040L, 17, StringEncoding.ASCII, "AA:BB:CC:DD:EE:FF",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        List<CtfEntity> entities = scanner.scanStrings(strings, CtfScanOptions.defaults(), CancellationToken.none());

        assertEquals(3, entities.size());
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.BLE_UUID
                && e.value().contains("0000180d")));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.BLE_UUID
                && e.value().equals("0x180D")));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.MAC_ADDRESS
                && e.value().equals("AA:BB:CC:DD:EE:FF")));
    }

    @Test
    void detectsCredentialsAndTokens() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x5000L, 25, StringEncoding.ASCII, "ssid=CorpOffice;psk=SecretKey99",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x5020L, 20, StringEncoding.ASCII, "AKIAIOSFODNN7EXAMPLE",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x5040L, 40, StringEncoding.ASCII, "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x5070L, 24, StringEncoding.ASCII, "xoxb-1234567890-abcdef1234",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x5090L, 50, StringEncoding.ASCII,
                        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_signature",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x50F0L, 30, StringEncoding.ASCII, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        List<CtfEntity> entities = scanner.scanStrings(strings, CtfScanOptions.defaults(), CancellationToken.none());

        assertEquals(7, entities.size());
        assertEquals(2, entities.stream().filter(e -> e.type() == CtfEntityType.WIFI_CREDENTIAL).count());
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.API_TOKEN
                && e.value().contains("AKIA") && e.isSecret()));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.API_TOKEN
                && e.value().contains("ghp_") && e.isSecret()));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.API_TOKEN
                && e.value().contains("xoxb-") && e.isSecret()));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.JWT && e.isSecret()));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.SSH_KEY));
    }

    @Test
    void detectsPemCertificatesAndKeys() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        String pemCert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAP1234567890\n-----END CERTIFICATE-----";
        String pemKey = "-----BEGIN RSA PRIVATE KEY-----\n"
                + "MIIEowIBAAKCAQEA0123456789abcdef\n-----END RSA PRIVATE KEY-----";

        List<ExtractedString> strings = List.of(
                new ExtractedString(0x6000L, pemCert.length(), StringEncoding.ASCII, pemCert,
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x6200L, pemKey.length(), StringEncoding.ASCII, pemKey,
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        List<CtfEntity> entities = scanner.scanStrings(strings, CtfScanOptions.defaults(), CancellationToken.none());

        assertEquals(2, entities.size());
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.PEM_CERTIFICATE && !e.isSecret()));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.PEM_KEY && e.isSecret()));
    }

    @Test
    void detectsDerBinaryCertificates() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();

        // Construct synthetic valid X.509 DER header sequence:
        // Tag 0x30, length 0x82 0x01 0x00 (256 bytes)
        // Nested sequence 0x30, length 0x82 0x00 0xF0
        // Version explicit tag [0] 0xA0 0x03 -> 0x02 0x01 0x02 (v3)
        // Serial number 0x02 0x08 ...
        // Algorithm ID 0x30 ... OID 1.2.840.113549.1.1.1 (RSA encryption)
        byte[] derBytes = new byte[300];
        derBytes[10] = 0x30;
        derBytes[11] = (byte) 0x82;
        derBytes[12] = 0x01;
        derBytes[13] = 0x00;
        derBytes[14] = 0x30;
        derBytes[15] = (byte) 0x82;
        derBytes[16] = 0x00;
        derBytes[17] = (byte) 0xF0;
        derBytes[18] = (byte) 0xA0;
        derBytes[19] = 0x03;
        derBytes[20] = 0x02;
        derBytes[21] = 0x01;
        derBytes[22] = 0x02; // v3
        derBytes[23] = 0x02; // serial integer
        derBytes[24] = 0x04;
        derBytes[25] = 0x01;
        derBytes[26] = 0x02;
        derBytes[27] = 0x03;
        derBytes[28] = 0x04;
        // Algorithm Identifier Sequence
        derBytes[29] = 0x30;
        derBytes[30] = 0x0D;
        derBytes[31] = 0x06; // OID tag
        derBytes[32] = 0x09;
        derBytes[33] = 0x2A;
        derBytes[34] = (byte) 0x86;
        derBytes[35] = 0x48;
        derBytes[36] = (byte) 0x86;
        derBytes[37] = (byte) 0xF7;
        derBytes[38] = 0x0D;
        derBytes[39] = 0x01;
        derBytes[40] = 0x01;
        derBytes[41] = 0x01; // RSA OID

        List<CtfEntity> entities = scanner.scanBytes(derBytes, 0x8000L, CtfScanOptions.defaults(),
                CancellationToken.none());

        assertEquals(1, entities.size());
        CtfEntity cert = entities.get(0);
        assertEquals(CtfEntityType.DER_CERTIFICATE, cert.type());
        assertEquals(0x800AL, cert.address());
        assertEquals(260, cert.length());
        assertEquals(CtfSeverity.MEDIUM, cert.severity());
    }

    @Test
    void detectsEncodedBlobs() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x7000L, 32, StringEncoding.ASCII, "dGhpcyBpcyBhIHZhbGlkIGJhc2U2NCBzdHJpbmc=",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x7030L, 64, StringEncoding.ASCII,
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        List<CtfEntity> entities = scanner.scanStrings(strings, CtfScanOptions.defaults(), CancellationToken.none());

        assertEquals(2, entities.size());
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.BASE64_BLOB));
        assertTrue(entities.stream().anyMatch(e -> e.type() == CtfEntityType.HEX_BLOB));
    }

    @Test
    void detectsDefaultAndCustomFlags() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x8000L, 25, StringEncoding.ASCII, "flag{firmware_secret_123}",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x8030L, 21, StringEncoding.ASCII, "CTF{hardware_pwning}",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x8060L, 28, StringEncoding.ASCII, "CUSTOM_FLAG[reverse_success]",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        CtfScanOptions customOptions = CtfScanOptions.builder()
                .addFlagPattern(Pattern.compile("CUSTOM_FLAG\\[[^\\]]+\\]"))
                .build();

        List<CtfEntity> entities = scanner.scanStrings(strings, customOptions, CancellationToken.none());

        assertEquals(3, entities.size());
        assertTrue(entities.stream().allMatch(e -> e.type() == CtfEntityType.FLAG));
        assertTrue(entities.stream().allMatch(CtfEntity::isSecret));
        assertTrue(entities.stream().allMatch(e -> e.severity() == CtfSeverity.HIGH));
    }

    @Test
    void detectsEntitiesInStackStrings() throws Exception {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<RecoveredStackString> stackStrings = List.of(
                new RecoveredStackString(0x08001000L, 0x10, "flag{stack_string_recovered}",
                        StringEncoding.ASCII, StringConfidence.CONFIRMED, 0x08001000L, 0x08001020L,
                        4)
        );

        List<CtfEntity> entities = scanner.scanStackStrings(stackStrings, CtfScanOptions.defaults(),
                CancellationToken.none());

        assertEquals(1, entities.size());
        CtfEntity flag = entities.get(0);
        assertEquals(CtfEntityType.FLAG, flag.type());
        assertEquals(0x08001000L, flag.address());
        assertEquals("flag{stack_string_recovered}", flag.value());
        assertTrue(flag.isSecret());
    }

    @Test
    void enforcesResourceLimits() {
        CtfEntityScanner scanner = new CtfEntityScanner();
        ParserLimits strictLimits = new ParserLimits(
                1024 * 1024L, 1024 * 1024L, 1024 * 1024L, 2, 10, java.time.Duration.ofSeconds(10));
        CtfScanOptions options = CtfScanOptions.builder()
                .limits(strictLimits)
                .build();

        List<ExtractedString> strings = List.of(
                new ExtractedString(0x1000L, 20, StringEncoding.ASCII, "https://url1.com",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x1020L, 20, StringEncoding.ASCII, "https://url2.com",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL),
                new ExtractedString(0x1040L, 20, StringEncoding.ASCII, "https://url3.com",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        assertThrows(DiagnosticException.class, () -> scanner.scanStrings(strings, options, CancellationToken.none()));
    }

    @Test
    void enforcesCancellation() {
        CtfEntityScanner scanner = new CtfEntityScanner();
        List<ExtractedString> strings = List.of(
                new ExtractedString(0x1000L, 20, StringEncoding.ASCII, "https://url1.com",
                        StringConfidence.CONFIRMED, StringProvenance.STATIC_LITERAL)
        );

        assertThrows(DiagnosticException.class,
                () -> scanner.scanStrings(strings, CtfScanOptions.defaults(), () -> true));
    }

    @Test
    void masksSecretsInToStringAndExport() {
        CtfEntity secretEntity = new CtfEntity(
                "cred-1",
                CtfEntityCategory.CREDENTIAL,
                CtfEntityType.API_TOKEN,
                CtfSeverity.HIGH,
                StringConfidence.CONFIRMED,
                0x1000L,
                24,
                "AKIAIOSFODNN7EXAMPLE",
                "Hardcoded AWS access key ID",
                true,
                Map.of("provider", "AWS")
        );

        assertTrue(secretEntity.isSecret());
        String masked = secretEntity.maskedValue();
        assertFalse(masked.contains("EXAMPLE"));
        assertTrue(masked.startsWith("AKIA"));
        assertTrue(secretEntity.toString().contains(masked));
        assertFalse(secretEntity.toString().contains("AKIAIOSFODNN7EXAMPLE"));

        CtfFindingsReport report = new CtfFindingsReport(List.of(secretEntity));
        String jsonRedacted = report.toJson(true);
        assertFalse(jsonRedacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(jsonRedacted.contains(masked));

        String markdownRedacted = report.toMarkdown(true);
        assertFalse(markdownRedacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(markdownRedacted.contains(masked));

        String sarifRedacted = report.toSarif(true);
        assertFalse(sarifRedacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(sarifRedacted.contains(masked));
    }
}
