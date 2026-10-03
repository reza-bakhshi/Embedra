package io.github.rezabakhshi.embedra.formats.rp.uf2;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Address-based reconstruction engine for UF2 container blocks.
 * <p>
 * Reconstructs continuous or sparse memory segments from valid UF2 blocks sorted by target CPU address,
 * handling out-of-order blocks, sparse gaps, and multiple family IDs.
 */
public final class RpUf2Reconstructor {

    private RpUf2Reconstructor() {
    }

    /**
     * Reconstructs memory segments from blocks, auto-detecting the single family or preserving all blocks.
     */
    public static List<RpUf2Segment> reconstruct(List<RpUf2Block> blocks) {
        Objects.requireNonNull(blocks, "blocks must not be null");
        if (blocks.isEmpty()) {
            return List.of();
        }

        Set<RpUf2Family> families = detectFamilies(blocks);
        if (families.size() == 1) {
            return reconstruct(blocks, families.iterator().next());
        } else if (families.isEmpty()) {
            return reconstruct(blocks, (RpUf2Family) null);
        }

        // Multiple families present: coalesce segments per family in order of appearance
        List<RpUf2Segment> allSegments = new ArrayList<>();
        for (RpUf2Family family : families) {
            allSegments.addAll(reconstruct(blocks, family));
        }
        return Collections.unmodifiableList(allSegments);
    }

    /**
     * Reconstructs memory segments from blocks filtered to a specific target family.
     */
    public static List<RpUf2Segment> reconstruct(List<RpUf2Block> blocks, RpUf2Family targetFamily) {
        Objects.requireNonNull(blocks, "blocks must not be null");
        if (blocks.isEmpty()) {
            return List.of();
        }

        List<RpUf2Block> filtered = new ArrayList<>();
        for (RpUf2Block block : blocks) {
            if (targetFamily == null) {
                filtered.add(block);
            } else if (block.hasFamilyId()) {
                if (block.familyId() == targetFamily.familyId()) {
                    filtered.add(block);
                }
            } else {
                // If block does not declare family ID, include it when no conflicting families exist
                filtered.add(block);
            }
        }

        if (filtered.isEmpty()) {
            return List.of();
        }

        // Sort blocks primarily by target address, secondarily by block number
        filtered.sort(Comparator.comparingLong(RpUf2Block::targetAddress)
                .thenComparingInt(RpUf2Block::blockNumber));

        List<RpUf2Segment> segments = new ArrayList<>();
        long currentStart = filtered.get(0).targetAddress();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        for (RpUf2Block block : filtered) {
            long blockStart = block.targetAddress();
            byte[] payload = block.payload();
            long currentEnd = currentStart + buffer.size();

            if (buffer.size() == 0) {
                currentStart = blockStart;
                buffer.write(payload, 0, payload.length);
            } else if (blockStart == currentEnd) {
                // Contiguous block
                buffer.write(payload, 0, payload.length);
            } else if (blockStart > currentEnd) {
                // Sparse gap: finish current segment and begin new segment
                segments.add(new RpUf2Segment(currentStart, buffer.toByteArray(), Optional.ofNullable(targetFamily)));
                buffer.reset();
                currentStart = blockStart;
                buffer.write(payload, 0, payload.length);
            } else {
                // Overlapping or duplicate block
                long overlap = currentEnd - blockStart;
                if (payload.length > overlap) {
                    buffer.write(payload, (int) overlap, payload.length - (int) overlap);
                }
            }
        }

        if (buffer.size() > 0) {
            segments.add(new RpUf2Segment(currentStart, buffer.toByteArray(), Optional.ofNullable(targetFamily)));
        }

        return Collections.unmodifiableList(segments);
    }

    /**
     * Reconstructs memory segments partitioned by family ID.
     */
    public static Map<RpUf2Family, List<RpUf2Segment>> reconstructByFamily(List<RpUf2Block> blocks) {
        Objects.requireNonNull(blocks, "blocks must not be null");
        Set<RpUf2Family> families = detectFamilies(blocks);
        Map<RpUf2Family, List<RpUf2Segment>> map = new LinkedHashMap<>();
        for (RpUf2Family family : families) {
            map.put(family, reconstruct(blocks, family));
        }
        return Collections.unmodifiableMap(map);
    }

    private static Set<RpUf2Family> detectFamilies(List<RpUf2Block> blocks) {
        Set<RpUf2Family> set = new LinkedHashSet<>();
        for (RpUf2Block block : blocks) {
            if (block.hasFamilyId()) {
                RpUf2Family.fromFamilyId(block.familyId()).ifPresent(set::add);
            }
        }
        return set;
    }
}
