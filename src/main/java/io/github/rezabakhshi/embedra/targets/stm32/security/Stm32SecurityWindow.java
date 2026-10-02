package io.github.rezabakhshi.embedra.targets.stm32.security;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * One pinned security window for an exact part.
 *
 * <p>An {@code ALIAS_APERTURE} window is the architecturally fixed secure (or
 * non-secure) address view of a physical bank. Its extent is the paired T039
 * alias extent; the secure/non-secure split inside the bank is not implied and
 * stays {@code UNRESOLVED_CONFIGURATION_DEPENDENT} until supplied explicitly.
 * A {@code PARTITION} window is a non-secure-callable boundary and must cite an
 * evidence symbol; no partition, NSC address, or veneer address is fabricated
 * here.</p>
 */
public record Stm32SecurityWindow(
        String id,
        Kind kind,
        Stm32SecurityAttribute attribute,
        BoundaryKind boundaryKind,
        long start,
        long size,
        String pairedRegionId,
        List<String> pairedAliasIds,
        String baseSymbol,
        int baseLine,
        String baseDeclaration,
        String headerPath,
        PartitionState partitionState) {

    /** The address space shared by every MCU alias window. */
    public static final String ADDRESS_SPACE = "mcu";

    /** Physical bank kind of the window, never a CPU or external memory kind. */
    public enum Kind {
        FLASH, RAM, SYSTEM, PERIPHERAL
    }

    /** An alias aperture is a fixed view; a partition is an attributed boundary. */
    public enum BoundaryKind {
        ALIAS_APERTURE, PARTITION
    }

    /** Runtime partition resolution; unresolved facts are never guessed. */
    public enum PartitionState {
        UNRESOLVED_CONFIGURATION_DEPENDENT, CONFIGURATION_INPUT, FIXED
    }

    public Stm32SecurityWindow {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(attribute, "attribute");
        Objects.requireNonNull(boundaryKind, "boundaryKind");
        Objects.requireNonNull(pairedRegionId, "pairedRegionId");
        Objects.requireNonNull(baseSymbol, "baseSymbol");
        Objects.requireNonNull(baseDeclaration, "baseDeclaration");
        Objects.requireNonNull(headerPath, "headerPath");
        Objects.requireNonNull(partitionState, "partitionState");
        pairedAliasIds = List.copyOf(pairedAliasIds);
        if (id.isBlank() || pairedRegionId.isBlank() || baseSymbol.isBlank()
                || baseDeclaration.isBlank() || headerPath.isBlank()) {
            throw new IllegalArgumentException("Security window identity is incomplete");
        }
        if (headerPath.startsWith("/") || headerPath.contains("..")) {
            throw new IllegalArgumentException("Security window header path is unsafe");
        }
        if (start < 0 || size <= 0 || start > 0x1_0000_0000L - size) {
            throw new IllegalArgumentException("Security window must fit the 32-bit space");
        }
        if (baseLine <= 0) {
            throw new IllegalArgumentException("Security window base line must be positive");
        }
        Set<String> aliases = new TreeSet<>();
        for (String alias : pairedAliasIds) {
            if (alias == null || alias.isBlank() || !aliases.add(alias)) {
                throw new IllegalArgumentException("Security window aliases must be unique");
            }
        }
        if (boundaryKind == BoundaryKind.ALIAS_APERTURE) {
            if (attribute == Stm32SecurityAttribute.NON_SECURE_CALLABLE) {
                throw new IllegalArgumentException(
                    "An alias aperture is never a non-secure-callable boundary");
            }
            if (pairedAliasIds.isEmpty()) {
                throw new IllegalArgumentException(
                    "A secure/non-secure alias aperture requires its T039 aliases");
            }
        }
        else if (attribute != Stm32SecurityAttribute.NON_SECURE_CALLABLE) {
            throw new IllegalArgumentException("A partition must be non-secure-callable");
        }
    }

    /** The checked half-open address range of this window. */
    public AddressRange range() {
        return new AddressRange(ADDRESS_SPACE, start, size);
    }

    public long endExclusive() {
        return start + size;
    }

    /** True when the window covers the address. */
    public boolean contains(long address) {
        return address >= start && address < endExclusive();
    }

    /** True when this window fully covers the checked range. */
    public boolean covers(AddressRange other) {
        return ADDRESS_SPACE.equals(other.addressSpace())
            && other.start() >= start && other.endExclusive() <= endExclusive();
    }
}
