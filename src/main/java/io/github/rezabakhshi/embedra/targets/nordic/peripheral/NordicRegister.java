package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable definition of a 32-bit word-aligned memory-mapped register on Nordic nRF devices.
 */
public record NordicRegister(
        String name,
        long address,
        long offset,
        int widthBits,
        String description,
        List<NordicBitField> bitfields,
        boolean isEasyDma,
        NordicEasyDmaType easyDmaType) {

    public NordicRegister {
        Objects.requireNonNull(name, "name must not be null");
        description = description == null ? "" : description;
        bitfields = bitfields == null ? List.of() : List.copyOf(bitfields);

        if (name.isBlank()) {
            throw new IllegalArgumentException("Register name must not be blank");
        }
        if (widthBits != 32) {
            throw new IllegalArgumentException("Nordic registers must have 32-bit width, got: " + widthBits);
        }
        if (offset < 0) {
            throw new IllegalArgumentException("Offset must be non-negative: " + offset);
        }
        if ((address & 0x03L) != 0L || (offset & 0x03L) != 0L) {
            throw new IllegalArgumentException(String.format(
                "Register %s address (0x%08X) or offset (0x%04X) is not 32-bit word aligned",
                name, address, offset));
        }

        // Validate MMIO aperture: 0x40000000-0x4FFFFFFF (Non-Secure) or 0x50000000-0x5FFFFFFF (Secure)
        boolean inNonSecureMmio = address >= 0x40000000L && address <= 0x4FFFFFFFL;
        boolean inSecureMmio = address >= 0x50000000L && address <= 0x5FFFFFFFL;
        if (!inNonSecureMmio && !inSecureMmio) {
            throw new IllegalArgumentException(String.format(
                "Register %s address 0x%08X is outside Nordic peripheral MMIO apertures (0x40000000-0x5FFFFFFF)",
                name, address));
        }

        // Validate non-overlapping bitfields
        for (int i = 0; i < bitfields.size(); i++) {
            NordicBitField b1 = bitfields.get(i);
            for (int j = i + 1; j < bitfields.size(); j++) {
                NordicBitField b2 = bitfields.get(j);
                if ((b1.mask() & b2.mask()) != 0L) {
                    throw new IllegalArgumentException(String.format(
                        "Bitfield collision in register %s: %s (0x%08X) overlaps %s (0x%08X)",
                        name, b1.name(), b1.mask(), b2.name(), b2.mask()));
                }
            }
        }
    }

    public NordicRegister(
            String name,
            long address,
            long offset,
            int widthBits,
            String description,
            List<NordicBitField> bitfields) {
        this(name, address, offset, widthBits, description, bitfields, false, null);
    }

    public static NordicRegister easyDma(
            String name,
            long address,
            long offset,
            String description,
            NordicEasyDmaType dmaType) {
        return new NordicRegister(name, address, offset, 32, description, List.of(), true, dmaType);
    }
}
