package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.security.MessageDigest;
import java.util.List;
import java.util.Objects;

/** Immutable partition table exposed only after structural and MD5 validation. */
public final class EspPartitionTable {
    private final EspPartitionDiscoveryMethod discoveryMethod;

    private final EspFlashRange tableFlashRange;

    private final SourceRange sourceRange;

    private final List<EspPartitionEntry> entries;

    private final byte[] storedMd5;

    private final byte[] calculatedMd5;

    private final SourceRange md5SourceRange;

    public EspPartitionTable(EspPartitionDiscoveryMethod discoveryMethod,
            EspFlashRange tableFlashRange, SourceRange sourceRange,
            List<EspPartitionEntry> entries, byte[] storedMd5, byte[] calculatedMd5,
            SourceRange md5SourceRange) {
        this.discoveryMethod = Objects.requireNonNull(discoveryMethod,
            "discoveryMethod");
        this.tableFlashRange = Objects.requireNonNull(tableFlashRange,
            "tableFlashRange");
        this.sourceRange = Objects.requireNonNull(sourceRange, "sourceRange");
        this.entries = List.copyOf(entries);
        this.storedMd5 = Objects.requireNonNull(storedMd5, "storedMd5").clone();
        this.calculatedMd5 = Objects.requireNonNull(calculatedMd5,
            "calculatedMd5").clone();
        this.md5SourceRange = Objects.requireNonNull(md5SourceRange,
            "md5SourceRange");
        if (tableFlashRange.length() != EspPartitionTableDiscovery.TABLE_SIZE
            || sourceRange.offset() != tableFlashRange.offset()
            || sourceRange.length() != tableFlashRange.length() || entries.isEmpty()
            || this.storedMd5.length != 16 || this.calculatedMd5.length != 16
            || md5SourceRange.length() != 16) {
            throw new IllegalArgumentException("Invalid ESP partition table model");
        }
    }

    public EspPartitionDiscoveryMethod discoveryMethod() {
        return discoveryMethod;
    }

    public EspFlashRange tableFlashRange() {
        return tableFlashRange;
    }

    public SourceRange sourceRange() {
        return sourceRange;
    }

    public List<EspPartitionEntry> entries() {
        return entries;
    }

    public byte[] storedMd5() {
        return storedMd5.clone();
    }

    public byte[] calculatedMd5() {
        return calculatedMd5.clone();
    }

    public SourceRange md5SourceRange() {
        return md5SourceRange;
    }

    public boolean md5Valid() {
        return MessageDigest.isEqual(storedMd5, calculatedMd5);
    }
}
