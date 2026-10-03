package io.github.rezabakhshi.embedra.targets.rp.boot;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Parsed boot metadata for RP2350 / RP2354 firmware containing IMAGE_DEF information.
 */
public record Rp2350BootMetadata(
        long flashBaseAddress,
        long imageDefOffset,
        boolean hasImageDef,
        Rp2350Architecture architecture,
        Rp2350SecurityDomain securityDomain,
        OptionalLong vectorTableAddress,
        long entryPoint,
        OptionalLong initialSp,
        boolean isStackedFlash,
        List<Rp2350BlockItem> items) implements RpBootMetadata {

    public Rp2350BootMetadata {
        Objects.requireNonNull(architecture, "architecture must not be null");
        Objects.requireNonNull(securityDomain, "securityDomain must not be null");
        Objects.requireNonNull(vectorTableAddress, "vectorTableAddress must not be null");
        Objects.requireNonNull(initialSp, "initialSp must not be null");
        items = List.copyOf(items != null ? items : List.of());
    }

    @Override
    public String series() {
        return isStackedFlash ? "RP2354" : "RP2350";
    }

    @Override
    public boolean isValid() {
        return hasImageDef && entryPoint != 0;
    }

    @Override
    public Map<String, Object> metadataProperties() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("Series", series());
        props.put("Flash Base Address", String.format("0x%08x", flashBaseAddress));
        props.put("IMAGE_DEF Present", hasImageDef);
        props.put("IMAGE_DEF Offset", String.format("0x%08x", imageDefOffset));
        props.put("Architecture", architecture.description());
        props.put("ISA", architecture.isa());
        props.put("Security Domain", securityDomain.description());
        if (vectorTableAddress.isPresent()) {
            props.put("Vector Table Address", String.format("0x%08x", vectorTableAddress.getAsLong()));
        }
        props.put("Entry Point", String.format("0x%08x", entryPoint));
        if (initialSp.isPresent()) {
            props.put("Initial SP", String.format("0x%08x", initialSp.getAsLong()));
        }
        props.put("Stacked Flash", isStackedFlash);
        props.put("Block Items Count", items.size());
        return Map.copyOf(props);
    }
}
