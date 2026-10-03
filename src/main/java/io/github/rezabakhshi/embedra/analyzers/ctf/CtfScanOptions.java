package io.github.rezabakhshi.embedra.analyzers.ctf;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Configuration options for CTF entity and artifact scanning.
 *
 * @param flagPatterns customizable regex patterns for CTF flag detection
 * @param minBase64Length minimum character length for candidate Base64 blobs
 * @param minHexBlobLength minimum character length for candidate Hex blobs
 * @param scanEndpoints whether to scan for URLs, IPs, domains, and MQTT topics
 * @param scanCredentials whether to scan for Wi-Fi credentials, tokens, and SSH keys
 * @param scanCertificates whether to scan for PEM/DER certificates and keys
 * @param scanUuids whether to scan for BLE UUIDs and MAC addresses
 * @param scanBlobs whether to scan for Base64 and Hex blobs
 * @param scanFlags whether to scan for CTF flags
 * @param limits resource budget and limit configuration
 */
public record CtfScanOptions(
        List<Pattern> flagPatterns,
        int minBase64Length,
        int minHexBlobLength,
        boolean scanEndpoints,
        boolean scanCredentials,
        boolean scanCertificates,
        boolean scanUuids,
        boolean scanBlobs,
        boolean scanFlags,
        ParserLimits limits) {

    public static final List<Pattern> DEFAULT_FLAG_PATTERNS = List.of(
            Pattern.compile("flag\\{[^}\\r\\n]+\\}"),
            Pattern.compile("CTF\\{[^}\\r\\n]+\\}"),
            Pattern.compile("embedra\\{[^}\\r\\n]+\\}")
    );

    public CtfScanOptions {
        Objects.requireNonNull(flagPatterns, "flagPatterns must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        flagPatterns = List.copyOf(flagPatterns);
    }

    public static CtfScanOptions defaults() {
        return new CtfScanOptions(
                DEFAULT_FLAG_PATTERNS,
                24,
                32,
                true,
                true,
                true,
                true,
                true,
                true,
                ParserLimits.defaults()
        );
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for constructing custom {@link CtfScanOptions}.
     */
    public static final class Builder {
        private final List<Pattern> flagPatterns = new ArrayList<>(DEFAULT_FLAG_PATTERNS);

        private int minBase64Length = 24;

        private int minHexBlobLength = 32;

        private boolean scanEndpoints = true;

        private boolean scanCredentials = true;

        private boolean scanCertificates = true;

        private boolean scanUuids = true;

        private boolean scanBlobs = true;

        private boolean scanFlags = true;

        private ParserLimits limits = ParserLimits.defaults();

        public Builder addFlagPattern(Pattern pattern) {
            Objects.requireNonNull(pattern, "pattern must not be null");
            this.flagPatterns.add(pattern);
            return this;
        }

        public Builder minBase64Length(int minBase64Length) {
            this.minBase64Length = minBase64Length;
            return this;
        }

        public Builder minHexBlobLength(int minHexBlobLength) {
            this.minHexBlobLength = minHexBlobLength;
            return this;
        }

        public Builder scanEndpoints(boolean scanEndpoints) {
            this.scanEndpoints = scanEndpoints;
            return this;
        }

        public Builder scanCredentials(boolean scanCredentials) {
            this.scanCredentials = scanCredentials;
            return this;
        }

        public Builder scanCertificates(boolean scanCertificates) {
            this.scanCertificates = scanCertificates;
            return this;
        }

        public Builder scanUuids(boolean scanUuids) {
            this.scanUuids = scanUuids;
            return this;
        }

        public Builder scanBlobs(boolean scanBlobs) {
            this.scanBlobs = scanBlobs;
            return this;
        }

        public Builder scanFlags(boolean scanFlags) {
            this.scanFlags = scanFlags;
            return this;
        }

        public Builder limits(ParserLimits limits) {
            this.limits = Objects.requireNonNull(limits, "limits must not be null");
            return this;
        }

        public CtfScanOptions build() {
            return new CtfScanOptions(
                    flagPatterns,
                    minBase64Length,
                    minHexBlobLength,
                    scanEndpoints,
                    scanCredentials,
                    scanCertificates,
                    scanUuids,
                    scanBlobs,
                    scanFlags,
                    limits
            );
        }
    }
}
