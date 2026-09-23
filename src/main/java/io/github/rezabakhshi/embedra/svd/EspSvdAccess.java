package io.github.rezabakhshi.embedra.svd;

/** Normalized CMSIS-SVD register or field access mode. */
public enum EspSvdAccess {
    READ_ONLY,
    WRITE_ONLY,
    READ_WRITE,
    WRITE_ONCE,
    READ_WRITE_ONCE,
    UNKNOWN;

    public static EspSvdAccess parse(String value, EspSvdAccess inherited) {
        if (value == null || value.isBlank()) {
            return inherited;
        }
        return switch (value) {
            case "read-only" -> READ_ONLY;
            case "write-only" -> WRITE_ONLY;
            case "read-write" -> READ_WRITE;
            case "writeOnce" -> WRITE_ONCE;
            case "read-writeOnce" -> READ_WRITE_ONCE;
            case "UNKNOWN" -> UNKNOWN;
            case "INHERITED" -> inherited;
            default -> throw new IllegalArgumentException(
                "Unsupported SVD access value: " + value);
        };
    }
}
