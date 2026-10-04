package io.github.rezabakhshi.embedra.analyzers.ctf;

import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.RecoveredStackString;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-performance pure scanner for CTF and firmware entities (AN-002, AN-006, AN-008).
 *
 * <p>Identifies endpoints, credentials, certificates, UUIDs, blobs, and flags under cooperative
 * cancellation and strict resource bounds.</p>
 */
public final class CtfEntityScanner {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)\\b(https?|wss?|coaps?|mqtts?|[ts]?ftp)://[^\\s\"'<>`]+");

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}"
                    + "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\b");

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "(?i)\\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+"
                    + "(?:com|org|net|io|co|internal|local|cloud|dev|app|edu|gov|xyz|info)\\b");

    private static final Pattern BLE_UUID_128 = Pattern.compile(
            "(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b");

    private static final Pattern BLE_UUID_16 = Pattern.compile(
            "(?i)\\b0x[0-9a-f]{4}\\b");

    private static final Pattern MAC_PATTERN = Pattern.compile(
            "(?i)\\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\\b");

    private static final Pattern WIFI_PATTERN = Pattern.compile(
            "(?i)\\b(?:wifi[-_]?(?:ssid|password|passphrase|psk|key)?|"
                    + "ssid|wpa2?|psk|passphrase|password)\\s*[:=]\\s*([^\\s,;]+)");

    private static final Pattern FORMAT_SPECIFIER_PATTERN = Pattern.compile(
            "^%[-+0-9.*#lhjztL]*[a-zA-Z%]");

    private static final Set<String> PLACEHOLDER_OR_STATUS_VALUES = Set.of(
            "null", "none", "unknown", "true", "false", "yes", "no",
            "on", "off", "enabled", "disabled", "connected", "disconnected",
            "connecting", "disconnecting", "ready", "init", "ok", "fail", "failed",
            "error", "started", "stopped", "running", "idle", "active", "inactive",
            "up", "down", "open", "closed", "pass", "todo", "changeme", "placeholder",
            "default", "(null)"
    );

    private static final Pattern AWS_KEY_PATTERN = Pattern.compile(
            "\\b(AKIA[0-9A-Z]{16})\\b");

    private static final Pattern GITHUB_TOKEN_PATTERN = Pattern.compile(
            "\\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\\b");

    private static final Pattern SLACK_TOKEN_PATTERN = Pattern.compile(
            "\\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\\b");

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "\\b(ey[A-Za-z0-9_-]{10,}\\.ey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})\\b");

    private static final Pattern SSH_KEY_PATTERN = Pattern.compile(
            "\\b(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9]+)\\s+[A-Za-z0-9+/=]{20,}");

    private static final Pattern BASE64_CANDIDATE = Pattern.compile(
            "^[A-Za-z0-9+/]{20,}={0,2}$");

    private static final Pattern HEX_CANDIDATE = Pattern.compile(
            "^(?:0x)?([0-9a-fA-F]{32,128})$");

    public CtfEntityScanner() {
    }

    /**
     * Scans a collection of extracted static strings for entities.
     */
    public List<CtfEntity> scanStrings(
            List<ExtractedString> strings,
            CtfScanOptions options,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(strings, "strings must not be null");
        Objects.requireNonNull(options, "options must not be null");
        Objects.requireNonNull(token, "token must not be null");

        List<CtfEntity> results = new ArrayList<>();
        int idCounter = 1;

        for (ExtractedString str : strings) {
            token.throwIfCancellationRequested();
            idCounter = scanText(str.content(), str.offset(), str.length(), str.confidence(),
                    options, results, idCounter, token);
        }

        return Collections.unmodifiableList(results);
    }

    /**
     * Scans a collection of recovered stack strings for entities.
     */
    public List<CtfEntity> scanStackStrings(
            List<RecoveredStackString> stackStrings,
            CtfScanOptions options,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(stackStrings, "stackStrings must not be null");
        Objects.requireNonNull(options, "options must not be null");
        Objects.requireNonNull(token, "token must not be null");

        List<CtfEntity> results = new ArrayList<>();
        int idCounter = 1;

        for (RecoveredStackString str : stackStrings) {
            token.throwIfCancellationRequested();
            idCounter = scanText(str.content(), str.functionAddress(), str.content().length(),
                    str.confidence(), options, results, idCounter, token);
        }

        return Collections.unmodifiableList(results);
    }

    /**
     * Scans raw binary bytes for binary-encoded entities such as X.509 DER certificates.
     */
    public List<CtfEntity> scanBytes(
            byte[] bytes,
            long baseAddress,
            CtfScanOptions options,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes must not be null");
        Objects.requireNonNull(options, "options must not be null");
        Objects.requireNonNull(token, "token must not be null");

        List<CtfEntity> results = new ArrayList<>();
        int idCounter = 1;

        if (options.scanCertificates()) {
            idCounter = scanDerCertificates(bytes, baseAddress, options, results, idCounter, token);
        }

        return Collections.unmodifiableList(results);
    }

    /**
     * Performs a combined scan across raw bytes, static strings, and recovered stack strings.
     */
    public CtfFindingsReport scan(
            byte[] bytes,
            long baseAddress,
            List<ExtractedString> strings,
            List<RecoveredStackString> stackStrings,
            CtfScanOptions options,
            CancellationToken token) throws DiagnosticException {
        List<CtfEntity> allEntities = new ArrayList<>();
        allEntities.addAll(scanStrings(strings, options, token));
        allEntities.addAll(scanStackStrings(stackStrings, options, token));
        if (bytes != null && bytes.length > 0) {
            allEntities.addAll(scanBytes(bytes, baseAddress, options, token));
        }
        return new CtfFindingsReport(allEntities);
    }

    private int scanText(
            String text,
            long address,
            int length,
            StringConfidence confidence,
            CtfScanOptions options,
            List<CtfEntity> results,
            int idCounter,
            CancellationToken token) throws DiagnosticException {

        // 1. Flags (Highest priority in CTF context)
        if (options.scanFlags()) {
            for (Pattern flagPattern : options.flagPatterns()) {
                token.throwIfCancellationRequested();
                Matcher m = flagPattern.matcher(text);
                while (m.find()) {
                    checkLimits(results, options);
                    results.add(new CtfEntity(
                            "flag-" + idCounter++,
                            CtfEntityCategory.FLAG,
                            CtfEntityType.FLAG,
                            CtfSeverity.HIGH,
                            confidence,
                            address,
                            length,
                            m.group(),
                            "CTF Flag match",
                            true
                    ));
                }
            }
        }

        // 2. Endpoints: URLs, IPs, Domains, MQTT topics
        if (options.scanEndpoints()) {
            Matcher urlMatcher = URL_PATTERN.matcher(text);
            while (urlMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "endpoint-url-" + idCounter++,
                        CtfEntityCategory.ENDPOINT,
                        CtfEntityType.URL,
                        CtfSeverity.LOW,
                        confidence,
                        address,
                        length,
                        urlMatcher.group(),
                        "Network service URL endpoint",
                        false
                ));
            }

            Matcher ipMatcher = IPV4_PATTERN.matcher(text);
            while (ipMatcher.find()) {
                token.throwIfCancellationRequested();
                String ip = ipMatcher.group();
                if (!ip.equals("0.0.0.0") && !ip.equals("255.255.255.255") && !text.contains("://" + ip)) {
                    checkLimits(results, options);
                    results.add(new CtfEntity(
                            "endpoint-ip-" + idCounter++,
                            CtfEntityCategory.ENDPOINT,
                            CtfEntityType.IP_ADDRESS,
                            CtfSeverity.LOW,
                            confidence,
                            address,
                            length,
                            ip,
                            "IPv4 address reference",
                            false
                    ));
                }
            }

            Matcher domainMatcher = DOMAIN_PATTERN.matcher(text);
            while (domainMatcher.find()) {
                token.throwIfCancellationRequested();
                String domain = domainMatcher.group();
                if (!text.contains("://" + domain) && !domain.startsWith(".")) {
                    checkLimits(results, options);
                    results.add(new CtfEntity(
                            "endpoint-domain-" + idCounter++,
                            CtfEntityCategory.ENDPOINT,
                            CtfEntityType.DOMAIN,
                            CtfSeverity.LOW,
                            confidence,
                            address,
                            length,
                            domain,
                            "Internet or internal domain name",
                            false
                    ));
                }
            }

            if (isMqttTopic(text)) {
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "endpoint-mqtt-" + idCounter++,
                        CtfEntityCategory.ENDPOINT,
                        CtfEntityType.MQTT_TOPIC,
                        CtfSeverity.LOW,
                        confidence,
                        address,
                        length,
                        text,
                        "MQTT communication topic",
                        false
                ));
            }
        }

        // 3. Credentials & Tokens
        if (options.scanCredentials()) {
            Matcher wifiMatcher = WIFI_PATTERN.matcher(text);
            while (wifiMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                String val = wifiMatcher.group(1);
                if (!isValidWifiCredential(text, wifiMatcher.start(), val)) {
                    continue;
                }
                results.add(new CtfEntity(
                        "cred-wifi-" + idCounter++,
                        CtfEntityCategory.CREDENTIAL,
                        CtfEntityType.WIFI_CREDENTIAL,
                        CtfSeverity.HIGH,
                        confidence,
                        address,
                        length,
                        text,
                        "Hardcoded Wi-Fi configuration credential",
                        true
                ));
            }

            Matcher awsMatcher = AWS_KEY_PATTERN.matcher(text);
            while (awsMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "token-aws-" + idCounter++,
                        CtfEntityCategory.CREDENTIAL,
                        CtfEntityType.API_TOKEN,
                        CtfSeverity.HIGH,
                        confidence,
                        address,
                        length,
                        awsMatcher.group(),
                        "Hardcoded AWS Access Key ID",
                        true
                ));
            }

            Matcher ghMatcher = GITHUB_TOKEN_PATTERN.matcher(text);
            while (ghMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "token-gh-" + idCounter++,
                        CtfEntityCategory.CREDENTIAL,
                        CtfEntityType.API_TOKEN,
                        CtfSeverity.HIGH,
                        confidence,
                        address,
                        length,
                        ghMatcher.group(),
                        "Hardcoded GitHub Personal Access Token",
                        true
                ));
            }

            Matcher slackMatcher = SLACK_TOKEN_PATTERN.matcher(text);
            while (slackMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "token-slack-" + idCounter++,
                        CtfEntityCategory.CREDENTIAL,
                        CtfEntityType.API_TOKEN,
                        CtfSeverity.HIGH,
                        confidence,
                        address,
                        length,
                        slackMatcher.group(),
                        "Hardcoded Slack API Token",
                        true
                ));
            }

            Matcher jwtMatcher = JWT_PATTERN.matcher(text);
            while (jwtMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "token-jwt-" + idCounter++,
                        CtfEntityCategory.CREDENTIAL,
                        CtfEntityType.JWT,
                        CtfSeverity.HIGH,
                        confidence,
                        address,
                        length,
                        jwtMatcher.group(),
                        "Hardcoded JSON Web Token (JWT)",
                        true
                ));
            }

            Matcher sshMatcher = SSH_KEY_PATTERN.matcher(text);
            while (sshMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "key-ssh-" + idCounter++,
                        CtfEntityCategory.CREDENTIAL,
                        CtfEntityType.SSH_KEY,
                        CtfSeverity.MEDIUM,
                        confidence,
                        address,
                        length,
                        sshMatcher.group(),
                        "OpenSSH public/authorized key",
                        false
                ));
            }
        }

        // 4. Certificates & PEM Keys
        if (options.scanCertificates()) {
            if (text.contains("-----BEGIN CERTIFICATE-----") && text.contains("-----END CERTIFICATE-----")) {
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "cert-pem-" + idCounter++,
                        CtfEntityCategory.CERTIFICATE_KEY,
                        CtfEntityType.PEM_CERTIFICATE,
                        CtfSeverity.MEDIUM,
                        confidence,
                        address,
                        length,
                        text,
                        "PEM-encoded X.509 Certificate",
                        false
                ));
            } else if (text.contains("PRIVATE KEY-----") && text.contains("END")) {
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "key-pem-priv-" + idCounter++,
                        CtfEntityCategory.CERTIFICATE_KEY,
                        CtfEntityType.PEM_KEY,
                        CtfSeverity.HIGH,
                        confidence,
                        address,
                        length,
                        text,
                        "PEM-encoded Private Key",
                        true
                ));
            } else if (text.contains("PUBLIC KEY-----") && text.contains("END")) {
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "key-pem-pub-" + idCounter++,
                        CtfEntityCategory.CERTIFICATE_KEY,
                        CtfEntityType.PEM_KEY,
                        CtfSeverity.MEDIUM,
                        confidence,
                        address,
                        length,
                        text,
                        "PEM-encoded Public Key",
                        false
                ));
            }
        }

        // 5. UUIDs & MAC addresses
        if (options.scanUuids()) {
            Matcher uuid128Matcher = BLE_UUID_128.matcher(text);
            while (uuid128Matcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "uuid-128-" + idCounter++,
                        CtfEntityCategory.UUID,
                        CtfEntityType.BLE_UUID,
                        CtfSeverity.INFO,
                        confidence,
                        address,
                        length,
                        uuid128Matcher.group(),
                        "128-bit UUID (BLE service or characteristic)",
                        false
                ));
            }

            Matcher uuid16Matcher = BLE_UUID_16.matcher(text);
            while (uuid16Matcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "uuid-16-" + idCounter++,
                        CtfEntityCategory.UUID,
                        CtfEntityType.BLE_UUID,
                        CtfSeverity.INFO,
                        confidence,
                        address,
                        length,
                        uuid16Matcher.group(),
                        "16-bit BLE Assigned Number / UUID",
                        false
                ));
            }

            Matcher macMatcher = MAC_PATTERN.matcher(text);
            while (macMatcher.find()) {
                token.throwIfCancellationRequested();
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "mac-" + idCounter++,
                        CtfEntityCategory.UUID,
                        CtfEntityType.MAC_ADDRESS,
                        CtfSeverity.INFO,
                        confidence,
                        address,
                        length,
                        macMatcher.group(),
                        "Ethernet / Wi-Fi / Bluetooth MAC Address",
                        false
                ));
            }
        }

        // 6. Encoded Blobs (Base64 & Hex)
        if (options.scanBlobs()) {
            if (text.length() >= options.minBase64Length() && isBase64Blob(text)) {
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "blob-b64-" + idCounter++,
                        CtfEntityCategory.ENCODED_BLOB,
                        CtfEntityType.BASE64_BLOB,
                        CtfSeverity.INFO,
                        confidence,
                        address,
                        length,
                        text,
                        "Base64 encoded binary payload or structure",
                        false
                ));
            }

            if (text.length() >= options.minHexBlobLength() && isHexBlob(text)) {
                checkLimits(results, options);
                results.add(new CtfEntity(
                        "blob-hex-" + idCounter++,
                        CtfEntityCategory.ENCODED_BLOB,
                        CtfEntityType.HEX_BLOB,
                        CtfSeverity.INFO,
                        confidence,
                        address,
                        length,
                        text,
                        "Continuous hexadecimal encoded data",
                        false
                ));
            }
        }

        return idCounter;
    }

    private static boolean isMqttTopic(String text) {
        if (!text.contains("/")) {
            return false;
        }
        if (text.startsWith("http:") || text.startsWith("https:") || text.startsWith("file:")) {
            return false;
        }
        return (text.contains("/#") || text.contains("/+")
                || text.startsWith("device/") || text.startsWith("factory/")
                || text.startsWith("sensor/") || text.startsWith("tele/")
                || text.startsWith("stat/") || text.startsWith("cmnd/"))
                && !text.contains(" ") && !text.contains("\n");
    }

    private static boolean isBase64Blob(String text) {
        if (text.length() % 4 != 0) {
            return false;
        }
        if (text.matches("^[0-9a-fA-F]+$")) {
            return false;
        }
        if (!BASE64_CANDIDATE.matcher(text).matches()) {
            return false;
        }
        int upper = 0;
        int lower = 0;
        int digit = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isUpperCase(c)) {
                upper++;
            } else if (Character.isLowerCase(c)) {
                lower++;
            } else if (Character.isDigit(c)) {
                digit++;
            }
        }
        int classes = (upper > 0 ? 1 : 0) + (lower > 0 ? 1 : 0) + (digit > 0 ? 1 : 0);
        if (classes < 2) {
            return false;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(text);
            return decoded.length >= 16;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean isHexBlob(String text) {
        Matcher m = HEX_CANDIDATE.matcher(text);
        if (!m.matches()) {
            return false;
        }
        String hex = m.group(1);
        if (hex.length() % 2 != 0) {
            return false;
        }
        char first = hex.charAt(0);
        boolean allSame = true;
        for (int i = 1; i < hex.length(); i++) {
            if (hex.charAt(i) != first) {
                allSame = false;
                break;
            }
        }
        return !allSame;
    }

    private int scanDerCertificates(
            byte[] bytes,
            long baseAddress,
            CtfScanOptions options,
            List<CtfEntity> results,
            int idCounter,
            CancellationToken token) throws DiagnosticException {
        int limit = bytes.length - 32;
        for (int i = 0; i < limit; i++) {
            token.throwIfCancellationRequested();
            if (bytes[i] == 0x30) {
                int certLen = parseDerLength(bytes, i + 1);
                if (certLen > 64 && certLen <= 4096 && i + certLen + 4 <= bytes.length) {
                    int headerOffset = bytes[i + 1] == (byte) 0x82 ? 4 : (bytes[i + 1] == (byte) 0x81 ? 3 : 2);
                    int innerSeq = i + headerOffset;
                    if (bytes[innerSeq] == 0x30) {
                        int innerLen = parseDerLength(bytes, innerSeq + 1);
                        if (innerLen > 32 && innerLen < certLen) {
                            int versionTagOffset = innerSeq
                                    + (bytes[innerSeq + 1] == (byte) 0x82 ? 4
                                    : (bytes[innerSeq + 1] == (byte) 0x81 ? 3 : 2));
                            if (versionTagOffset + 4 < bytes.length
                                    && bytes[versionTagOffset] == (byte) 0xA0
                                    && bytes[versionTagOffset + 1] == 0x03
                                    && bytes[versionTagOffset + 2] == 0x02
                                    && bytes[versionTagOffset + 3] == 0x01) {

                                checkLimits(results, options);
                                results.add(new CtfEntity(
                                        "cert-der-" + idCounter++,
                                        CtfEntityCategory.CERTIFICATE_KEY,
                                        CtfEntityType.DER_CERTIFICATE,
                                        CtfSeverity.MEDIUM,
                                        StringConfidence.CONFIRMED,
                                        baseAddress + i,
                                        certLen + headerOffset,
                                        "X.509 DER Certificate (" + (certLen + headerOffset) + " bytes)",
                                        "Binary DER encoded X.509 Certificate structure",
                                        false
                                ));
                                i += certLen + headerOffset - 1;
                            }
                        }
                    }
                }
            }
        }
        return idCounter;
    }

    private static int parseDerLength(byte[] bytes, int offset) {
        if (offset >= bytes.length) {
            return -1;
        }
        int b = bytes[offset] & 0xFF;
        if ((b & 0x80) == 0) {
            return b;
        }
        int lenBytes = b & 0x7F;
        if (lenBytes == 1 && offset + 1 < bytes.length) {
            return bytes[offset + 1] & 0xFF;
        }
        if (lenBytes == 2 && offset + 2 < bytes.length) {
            return ((bytes[offset + 1] & 0xFF) << 8) | (bytes[offset + 2] & 0xFF);
        }
        return -1;
    }

    static boolean isValidWifiCredential(String fullText, int matchStart, String value) {
        if (value == null) {
            return false;
        }
        String cleanValue = value.trim().replaceAll("[\"';,\r\n]", "");
        if (cleanValue.length() <= 2) {
            return false;
        }
        // Reject format specifiers like %s, %d, %u, %02x, etc.
        if (cleanValue.contains("%") || FORMAT_SPECIFIER_PATTERN.matcher(cleanValue).find()) {
            return false;
        }
        // Reject status or placeholder values
        if (PLACEHOLDER_OR_STATUS_VALUES.contains(cleanValue.toLowerCase())) {
            return false;
        }
        // Reject placeholders enclosed in brackets or angle brackets
        if ((cleanValue.startsWith("<") && cleanValue.endsWith(">"))
                || (cleanValue.startsWith("[") && cleanValue.endsWith("]"))
                || (cleanValue.startsWith("{") && cleanValue.endsWith("}"))) {
            return false;
        }
        // Reject frequency band descriptions like "2.4GHz WiFi" or "5GHz WiFi"
        if (fullText != null && matchStart > 0) {
            String prefix = fullText.substring(0, matchStart).toLowerCase().trim();
            if (prefix.endsWith("ghz") || prefix.endsWith("2.4ghz") || prefix.endsWith("5ghz")) {
                return false;
            }
        }
        return true;
    }

    private static void checkLimits(List<CtfEntity> results, CtfScanOptions options) throws DiagnosticException {
        if (results.size() >= options.limits().maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Discovered entities exceeded limit: " + options.limits().maxObjects(),
                    null
            ));
        }
    }
}
