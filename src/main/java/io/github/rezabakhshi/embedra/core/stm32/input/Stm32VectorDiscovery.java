package io.github.rezabakhshi.embedra.core.stm32.input;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/** Finds heuristic Cortex-M vector tables using caller-supplied address evidence. */
public final class Stm32VectorDiscovery {
    private static final long END = 0x1_0000_0000L;

    private static final int WORDS = 16;

    private Stm32VectorDiscovery() {
    }

    /** Half-open known RAM interval; an initial stack pointer may equal its end. */
    public record AddressRange(long start, long end) {
        public AddressRange {
            if (start < 0 || end > END || start >= end) {
                throw new IllegalArgumentException("Invalid 32-bit RAM interval");
            }
        }

        boolean containsStackTop(long value) {
            return value > start && value <= end;
        }
    }

    public record Candidate(long sourceOffset, long tableAddress, long initialStackPointer,
            long resetHandler, List<Long> words, int score, String inputSha256) {
        public Candidate {
            words = List.copyOf(words);
            if (words.size() != WORDS) {
                throw new IllegalArgumentException("Candidate must retain 16 vector words");
            }
        }
    }

    /** Only explicit selection of a reported address creates this confirmation. */
    public static final class Confirmed {
        private final Candidate candidate;

        private Confirmed(Candidate candidate) {
            this.candidate = Objects.requireNonNull(candidate, "candidate");
        }

        public Candidate candidate() {
            return candidate;
        }
    }

    public static List<Candidate> discover(byte[] bytes, long imageBase,
            List<AddressRange> ramRanges, ParserLimits limits, CancellationToken cancellation)
            throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes");
        Objects.requireNonNull(ramRanges, "ramRanges");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        if (imageBase < 0 || imageBase >= END || bytes.length > END - imageBase
                || bytes.length > limits.maxInputBytes()) {
            throw new IllegalArgumentException("Image base or length is outside 32-bit limits");
        }
        if (ramRanges.isEmpty() || ramRanges.size() > limits.maxObjects()) {
            throw new IllegalArgumentException("Known RAM ranges are required and bounded");
        }
        List<AddressRange> ranges = List.copyOf(ramRanges);
        String digest = sha256(bytes, cancellation);
        long deadline = System.nanoTime() + limits.maxWallTime().toNanos();
        List<Candidate> candidates = new ArrayList<>();
        for (int offset = 0; offset <= bytes.length - WORDS * 4; offset += 4) {
            if ((offset & 0xfff) == 0) {
                cancellation.throwIfCancellationRequested();
                if (System.nanoTime() - deadline >= 0) {
                    throw new IllegalArgumentException("Vector scan exceeded time limit");
                }
            }
            long sp = word(bytes, offset);
            if ((sp & 7) != 0 || ranges.stream().noneMatch(range ->
                    range.containsStackTop(sp))) {
                continue;
            }
            long reset = word(bytes, offset + 4);
            if (!handlerInImage(reset, imageBase, bytes.length)) {
                continue;
            }
            List<Long> words = new ArrayList<>(WORDS);
            int valid = 0;
            int invalid = 0;
            for (int index = 0; index < WORDS; index++) {
                long value = word(bytes, offset + index * 4);
                words.add(value);
                if (index >= 2 && value != 0) {
                    if (handlerInImage(value, imageBase, bytes.length)) {
                        valid++;
                    }
                    else {
                        invalid++;
                    }
                }
            }
            if (valid < 3 || invalid > 2) {
                continue;
            }
            int score = 40 + valid * 3 - invalid * 5
                + ((imageBase + offset) % 128 == 0 ? 10 : 0);
            candidates.add(new Candidate(offset, imageBase + offset, sp, reset,
                words, score, digest));
            if (candidates.size() > limits.maxObjects()) {
                throw new IllegalArgumentException("Vector candidates exceed object limit");
            }
        }
        candidates.sort(Comparator.comparingInt(Candidate::score).reversed()
            .thenComparingLong(Candidate::sourceOffset));
        return List.copyOf(candidates);
    }

    public static Confirmed confirm(List<Candidate> candidates, long selectedAddress) {
        Objects.requireNonNull(candidates, "candidates");
        return candidates.stream().filter(candidate ->
                candidate.tableAddress() == selectedAddress).findFirst()
            .map(Confirmed::new)
            .orElseThrow(() -> new IllegalArgumentException(
                "Selected address is not a discovered vector candidate"));
    }

    private static boolean handlerInImage(long thumbAddress, long base, long length) {
        long address = thumbAddress & ~1L;
        return (thumbAddress & 1) == 1 && address >= base && address < base + length;
    }

    private static long word(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffL) | ((bytes[offset + 1] & 0xffL) << 8)
            | ((bytes[offset + 2] & 0xffL) << 16)
            | ((bytes[offset + 3] & 0xffL) << 24);
    }

    private static String sha256(byte[] bytes, CancellationToken cancellation)
            throws DiagnosticException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (int offset = 0; offset < bytes.length; offset += 4096) {
                cancellation.throwIfCancellationRequested();
                digest.update(bytes, offset, Math.min(4096, bytes.length - offset));
            }
            cancellation.throwIfCancellationRequested();
            return HexFormat.of().formatHex(digest.digest());
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }
}
