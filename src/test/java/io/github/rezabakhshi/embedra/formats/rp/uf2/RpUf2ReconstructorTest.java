package io.github.rezabakhshi.embedra.formats.rp.uf2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class RpUf2ReconstructorTest {

    private static RpUf2Block makeBlock(long targetAddr, int blockNo, int numBlocks, long familyId, byte[] payload) {
        return new RpUf2Block(
                RpUf2Block.EXPECTED_MAGIC_START0,
                RpUf2Block.EXPECTED_MAGIC_START1,
                RpUf2Block.FLAG_FAMILY_ID_PRESENT,
                targetAddr,
                payload.length,
                blockNo,
                numBlocks,
                familyId,
                payload,
                RpUf2Block.EXPECTED_MAGIC_END);
    }

    @Test
    void testContinuousReconstruction() {
        byte[] p0 = new byte[]{1, 2, 3, 4};
        byte[] p1 = new byte[]{5, 6, 7, 8};

        RpUf2Block b0 = makeBlock(0x10000000L, 0, 2, RpUf2Family.RP2040.familyId(), p0);
        RpUf2Block b1 = makeBlock(0x10000004L, 1, 2, RpUf2Family.RP2040.familyId(), p1);

        List<RpUf2Segment> segments = RpUf2Reconstructor.reconstruct(List.of(b0, b1));
        assertEquals(1, segments.size());

        RpUf2Segment seg = segments.get(0);
        assertEquals(0x10000000L, seg.targetAddress());
        assertEquals(8, seg.length());
        assertEquals(0x10000008L, seg.endAddress());
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}, seg.data());
        assertTrue(seg.contains(0x10000000L));
        assertTrue(seg.contains(0x10000007L));
        assertFalse(seg.contains(0x10000008L));
        assertEquals(0x04030201L, seg.readU32Le(0));
        assertEquals(0x0201, seg.readU16Le(0));
    }

    @Test
    void testOutOfOrderBlocksReconstructedInAddressOrder() {
        byte[] p0 = new byte[]{10, 20};
        byte[] p1 = new byte[]{30, 40};
        byte[] p2 = new byte[]{50, 60};

        // Out of order: block 2, then block 0, then block 1
        RpUf2Block b2 = makeBlock(0x10000004L, 2, 3, RpUf2Family.RP2040.familyId(), p2);
        RpUf2Block b0 = makeBlock(0x10000000L, 0, 3, RpUf2Family.RP2040.familyId(), p0);
        RpUf2Block b1 = makeBlock(0x10000002L, 1, 3, RpUf2Family.RP2040.familyId(), p1);

        List<RpUf2Segment> segments = RpUf2Reconstructor.reconstruct(List.of(b2, b0, b1));
        assertEquals(1, segments.size());

        RpUf2Segment seg = segments.get(0);
        assertEquals(0x10000000L, seg.targetAddress());
        assertEquals(6, seg.length());
        assertArrayEquals(new byte[]{10, 20, 30, 40, 50, 60}, seg.data());
    }

    @Test
    void testSparseGapsProduceDistinctSegments() {
        byte[] p0 = new byte[256];
        Arrays.fill(p0, (byte) 0xAA);
        byte[] p1 = new byte[256];
        Arrays.fill(p1, (byte) 0xBB);

        // Gap of 0x1000 bytes between blocks
        RpUf2Block b0 = makeBlock(0x10000000L, 0, 2, RpUf2Family.RP2040.familyId(), p0);
        RpUf2Block b1 = makeBlock(0x10001000L, 1, 2, RpUf2Family.RP2040.familyId(), p1);

        List<RpUf2Segment> segments = RpUf2Reconstructor.reconstruct(List.of(b0, b1));
        assertEquals(2, segments.size());

        assertEquals(0x10000000L, segments.get(0).targetAddress());
        assertEquals(256, segments.get(0).length());
        assertArrayEquals(p0, segments.get(0).data());

        assertEquals(0x10001000L, segments.get(1).targetAddress());
        assertEquals(256, segments.get(1).length());
        assertArrayEquals(p1, segments.get(1).data());
    }

    @Test
    void testMultipleFamilyIsolationAndPartitioning() {
        byte[] pRp2040 = new byte[]{1, 1, 1, 1};
        byte[] pRp2350 = new byte[]{2, 2, 2, 2};

        RpUf2Block b0 = makeBlock(0x10000000L, 0, 2, RpUf2Family.RP2040.familyId(), pRp2040);
        RpUf2Block b1 = makeBlock(0x10000000L, 1, 2, RpUf2Family.RP2350_ARM_SECURE.familyId(), pRp2350);

        List<RpUf2Block> mixedBlocks = List.of(b0, b1);

        // Filter by RP2040
        List<RpUf2Segment> rp2040Segs = RpUf2Reconstructor.reconstruct(mixedBlocks, RpUf2Family.RP2040);
        assertEquals(1, rp2040Segs.size());
        assertArrayEquals(pRp2040, rp2040Segs.get(0).data());

        // Filter by RP2350
        List<RpUf2Segment> rp2350Segs = RpUf2Reconstructor.reconstruct(mixedBlocks, RpUf2Family.RP2350_ARM_SECURE);
        assertEquals(1, rp2350Segs.size());
        assertArrayEquals(pRp2350, rp2350Segs.get(0).data());

        // Partition by family
        Map<RpUf2Family, List<RpUf2Segment>> partitioned = RpUf2Reconstructor.reconstructByFamily(mixedBlocks);
        assertEquals(2, partitioned.size());
        assertTrue(partitioned.containsKey(RpUf2Family.RP2040));
        assertTrue(partitioned.containsKey(RpUf2Family.RP2350_ARM_SECURE));
    }

    @Test
    void testEmptyAndBoundaryHandling() {
        assertTrue(RpUf2Reconstructor.reconstruct(List.of()).isEmpty());
        assertTrue(RpUf2Reconstructor.reconstruct(List.of(), RpUf2Family.RP2040).isEmpty());
        assertTrue(RpUf2Reconstructor.reconstructByFamily(List.of()).isEmpty());

        RpUf2Segment seg = new RpUf2Segment(0x10000000L, new byte[]{1, 2, 3}, java.util.Optional.empty());
        assertThrows(IndexOutOfBoundsException.class, () -> seg.readU32Le(0));
        assertThrows(IndexOutOfBoundsException.class, () -> seg.readU16Le(2));
    }
}
