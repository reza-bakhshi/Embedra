package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.Objects;

/** Version/toolchain/optimization-indexed byte signature from a licensed pack. */
public final class EspLibrarySignature {
    private final String signatureId;

    private final String library;

    private final String functionName;

    private final String deviceId;

    private final String idfVersion;

    private final String toolchain;

    private final String optimization;

    private final byte[] pattern;

    private final byte[] mask;

    public EspLibrarySignature(String signatureId, String library, String functionName,
            String deviceId, String idfVersion, String toolchain, String optimization,
            byte[] pattern, byte[] mask) {
        this.signatureId = requireText(signatureId, "signatureId");
        this.library = requireText(library, "library");
        this.functionName = requireText(functionName, "functionName");
        this.deviceId = requireText(deviceId, "deviceId");
        this.idfVersion = requireText(idfVersion, "idfVersion");
        this.toolchain = requireText(toolchain, "toolchain");
        this.optimization = requireText(optimization, "optimization");
        this.pattern = Objects.requireNonNull(pattern, "pattern").clone();
        this.mask = Objects.requireNonNull(mask, "mask").clone();
        if (this.pattern.length < 8 || this.pattern.length != this.mask.length) {
            throw new IllegalArgumentException("Signature pattern and mask lengths are invalid");
        }
        boolean significant = false;
        for (byte value : this.mask) {
            if (value != 0 && value != (byte) 0xff) {
                throw new IllegalArgumentException("Signature masks must contain only 00 or ff");
            }
            significant |= value != 0;
        }
        if (!significant) {
            throw new IllegalArgumentException("Signature must contain significant bytes");
        }
    }

    public String signatureId() { return signatureId; }

    public String library() { return library; }

    public String functionName() { return functionName; }

    public String deviceId() { return deviceId; }

    public String idfVersion() { return idfVersion; }

    public String toolchain() { return toolchain; }

    public String optimization() { return optimization; }

    public byte[] pattern() { return pattern.clone(); }

    public byte[] mask() { return mask.clone(); }

    boolean isFullySpecified() {
        for (byte value : mask) {
            if (value != (byte) 0xff) {
                return false;
            }
        }
        return true;
    }

    boolean matches(byte[] candidate) {
        if (candidate.length < pattern.length) {
            return false;
        }
        for (int index = 0; index < pattern.length; index++) {
            if ((candidate[index] & mask[index]) != (pattern[index] & mask[index])) {
                return false;
            }
        }
        return true;
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
