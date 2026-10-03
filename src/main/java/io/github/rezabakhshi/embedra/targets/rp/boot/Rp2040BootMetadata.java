package io.github.rezabakhshi.embedra.targets.rp.boot;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parsed boot metadata for RP2040 firmware containing boot2 checksum and vector table entries.
 */
public record Rp2040BootMetadata(
        long flashBaseAddress,
        long storedCrc,
        long calculatedCrc,
        boolean isCrcValid,
        boolean isPlaceholder,
        long initialSp,
        long resetVector,
        long entryPoint,
        boolean isVectorTableValid) implements RpBootMetadata {

    @Override
    public String series() {
        return "RP2040";
    }

    @Override
    public boolean isValid() {
        return isVectorTableValid;
    }

    @Override
    public Map<String, Object> metadataProperties() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("Series", "RP2040");
        props.put("Flash Base Address", String.format("0x%08x", flashBaseAddress));
        props.put("Boot2 Stored CRC", String.format("0x%08x", storedCrc));
        props.put("Boot2 Calculated CRC", String.format("0x%08x", calculatedCrc));
        props.put("Boot2 CRC Valid", isCrcValid);
        props.put("Boot2 Placeholder", isPlaceholder);
        props.put("Initial SP", String.format("0x%08x", initialSp));
        props.put("Reset Vector", String.format("0x%08x", resetVector));
        props.put("Entry Point", String.format("0x%08x", entryPoint));
        props.put("Vector Table Valid", isVectorTableValid);
        return Map.copyOf(props);
    }
}
