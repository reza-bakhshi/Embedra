package io.github.rezabakhshi.embedra.core.stm32.input;

import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/** ELF/AXF header facts; native Ghidra loaders remain responsible for import. */
public record Stm32ElfInput(long encodedEntry, List<LoadSegment> loadSegments,
        List<Section> sections) implements Stm32AddressedInput {
    private static final long ADDRESS_SPACE_END = 0x1_0000_0000L;

    public Stm32ElfInput {
        checkAddress(encodedEntry, 0);
        loadSegments = List.copyOf(Objects.requireNonNull(loadSegments, "loadSegments"));
        sections = List.copyOf(Objects.requireNonNull(sections, "sections"));
    }

    @Override
    public Format format() {
        return Format.ELF;
    }

    @Override
    public OptionalLong encodedEntryPoint() {
        return OptionalLong.of(encodedEntry);
    }

    public record LoadSegment(long virtualAddress, long physicalAddress,
            long memorySize, long fileOffset, long fileSize, int flags) {
        public LoadSegment {
            checkAddress(virtualAddress, memorySize);
            checkAddress(physicalAddress, memorySize);
            checkSource(fileOffset, fileSize);
            if (fileSize > memorySize) {
                throw new IllegalArgumentException("ELF segment file size exceeds memory size");
            }
        }
    }

    public record Section(String name, long encodedAddress, long size,
            long fileOffset, long flags, int type) {
        public Section {
            Objects.requireNonNull(name, "name");
            checkAddress(encodedAddress, size);
            checkSource(fileOffset, 0);
        }

        public boolean allocatable() {
            return (flags & 2L) != 0;
        }
    }

    private static void checkAddress(long address, long length) {
        if (address < 0 || length < 0 || address >= ADDRESS_SPACE_END
            || length > ADDRESS_SPACE_END - address) {
            throw new IllegalArgumentException("ELF address exceeds the 32-bit target space");
        }
    }

    private static void checkSource(long offset, long length) {
        if (offset < 0 || length < 0) {
            throw new IllegalArgumentException("ELF source range must be non-negative");
        }
        Math.addExact(offset, length);
    }
}
