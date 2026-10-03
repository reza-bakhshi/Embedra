package io.github.rezabakhshi.embedra.formats.rp.uf2;

import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Validated decoded UF2 firmware image containing an ordered sequence of blocks.
 */
public final class RpUf2Image {

    private final List<RpUf2Block> blocks;

    private final Set<RpUf2Family> families;

    private final RpUf2Family family;

    private final long baseTargetAddress;

    private final long totalPayloadBytes;

    public RpUf2Image(List<RpUf2Block> blocks, RpUf2Family family) {
        this(blocks, family != null ? Set.of(family) : Set.of());
    }

    public RpUf2Image(List<RpUf2Block> blocks, Set<RpUf2Family> families) {
        Objects.requireNonNull(blocks, "blocks must not be null");
        Objects.requireNonNull(families, "families must not be null");
        if (blocks.isEmpty()) {
            throw new IllegalArgumentException("UF2 image must have at least one block");
        }
        if (families.isEmpty()) {
            throw new IllegalArgumentException("UF2 image must have at least one recognized family");
        }
        this.blocks = List.copyOf(blocks);
        this.families = Collections.unmodifiableSet(new LinkedHashSet<>(families));
        this.family = this.families.iterator().next();

        long minAddr = Long.MAX_VALUE;
        long totalBytes = 0;
        for (RpUf2Block block : this.blocks) {
            minAddr = Math.min(minAddr, block.targetAddress());
            totalBytes += block.payloadSize();
        }
        this.baseTargetAddress = minAddr;
        this.totalPayloadBytes = totalBytes;
    }

    public List<RpUf2Block> blocks() {
        return blocks;
    }

    public RpUf2Family family() {
        return family;
    }

    public Set<RpUf2Family> families() {
        return families;
    }

    public boolean hasMultipleFamilies() {
        return families.size() > 1;
    }

    public long baseTargetAddress() {
        return baseTargetAddress;
    }

    public long totalPayloadBytes() {
        return totalPayloadBytes;
    }

    /**
     * Reconstructs contiguous and sparse memory segments from all blocks for the primary family.
     */
    public List<RpUf2Segment> segments() {
        return RpUf2Reconstructor.reconstruct(blocks, family);
    }

    /**
     * Reconstructs contiguous and sparse memory segments for a specific target family.
     */
    public List<RpUf2Segment> segments(RpUf2Family targetFamily) {
        return RpUf2Reconstructor.reconstruct(blocks, targetFamily);
    }

    /**
     * Reconstructs contiguous and sparse memory segments partitioned by family.
     */
    public Map<RpUf2Family, List<RpUf2Segment>> segmentsByFamily() {
        return RpUf2Reconstructor.reconstructByFamily(blocks);
    }

    /**
     * Extracts a continuous flat binary image by laying out all blocks according to their targetAddress.
     */
    public byte[] extractContinuousBinary() {
        List<RpUf2Block> sorted = blocks.stream()
                .sorted(Comparator.comparingLong(RpUf2Block::targetAddress))
                .toList();

        long minAddr = sorted.get(0).targetAddress();
        RpUf2Block lastBlock = sorted.get(sorted.size() - 1);
        long maxAddr = lastBlock.targetAddress() + lastBlock.payloadSize();
        int totalSize = (int) (maxAddr - minAddr);

        byte[] flat = new byte[totalSize];
        for (RpUf2Block block : sorted) {
            int offset = (int) (block.targetAddress() - minAddr);
            byte[] payload = block.payload();
            System.arraycopy(payload, 0, flat, offset, payload.length);
        }
        return flat;
    }
}
