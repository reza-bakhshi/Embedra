package io.github.rezabakhshi.embedra.targets.stm32.board;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable board-profile facts layered over one exact MCU record.
 *
 * <p>A profile never mutates an MCU pack. External regions, their controllers,
 * devices, and memory-mapped CPU bases, plus optional boot offsets, are additive
 * board facts derived only from a pinned redistributable ST source. A profile
 * whose external facts are unavailable carries a reason and no regions; it does
 * not fabricate a size, address, device, or board-to-part link.</p>
 */
public record Stm32BoardProfile(
        String board,
        String category,
        String exactPart,
        Status status,
        BoardSource boardSource,
        BoardBsp bsp,
        String cmsisFamily,
        List<ExternalRegion> externalRegions,
        List<BootOffset> bootOffsets,
        String reason) {

    /** A reviewed profile with concrete facts, or an explicit unavailable one. */
    public enum Status {
        EXTERNAL_MEMORY_REVIEWED, UNAVAILABLE
    }

    /** The reviewed board-index entry that links this board to its exact part. */
    public record BoardSource(String sourcePath, String sha256) {
        public BoardSource {
            Objects.requireNonNull(sourcePath, "sourcePath");
            Objects.requireNonNull(sha256, "sha256");
            if (!sourcePath.startsWith("boards/") || sourcePath.contains("..")) {
                throw new IllegalArgumentException("Board source path is unsafe");
            }
            if (!sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Board source digest is not SHA-256");
            }
        }
    }

    /** The pinned per-board ST BSP repository that states the external facts. */
    public record BoardBsp(String repository, String revision, String note) {
        public BoardBsp {
            Objects.requireNonNull(repository, "repository");
            Objects.requireNonNull(revision, "revision");
            Objects.requireNonNull(note, "note");
            if (!revision.matches("[0-9a-f]{40}")) {
                throw new IllegalArgumentException("BSP revision is not a pinned commit");
            }
            if (repository.isBlank() || repository.startsWith("/")
                    || repository.contains("..")) {
                throw new IllegalArgumentException("BSP repository name is unsafe");
            }
        }
    }

    /** One external, memory-mapped board memory region. */
    public record ExternalRegion(String id, Kind kind, String controller, String device,
            AddressRange range, boolean writable, String startEvidence, String sizeEvidence) {
        public ExternalRegion {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(controller, "controller");
            Objects.requireNonNull(device, "device");
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(startEvidence, "startEvidence");
            Objects.requireNonNull(sizeEvidence, "sizeEvidence");
            if (id.isBlank() || controller.isBlank() || device.isBlank()
                    || startEvidence.isBlank() || sizeEvidence.isBlank()) {
                throw new IllegalArgumentException("External region identity is incomplete");
            }
            if (range.length() <= 0) {
                throw new IllegalArgumentException("External region must have a positive size");
            }
            if (!"ext-mem".equals(range.addressSpace())) {
                throw new IllegalArgumentException(
                    "External region must use the external-memory address space");
            }
        }

        /** Physical external memory is read-only flash or writable RAM. */
        public boolean executable() {
            return false;
        }
    }

    /** External memory device kind; never a CPU address or flash source offset. */
    public enum Kind {
        EXTERNAL_FLASH_MEMORY_MAPPED, EXTERNAL_RAM_MEMORY_MAPPED
    }

    /** An explicit boot offset fact, kept separate from a CPU-mapped address. */
    public record BootOffset(String id, String description, long offset) {
        public BootOffset {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(description, "description");
            if (id.isBlank() || description.isBlank()) {
                throw new IllegalArgumentException("Boot offset identity is incomplete");
            }
            if (offset < 0) {
                throw new IllegalArgumentException("Boot offset must be non-negative");
            }
        }
    }

    public Stm32BoardProfile {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(status, "status");
        externalRegions = List.copyOf(externalRegions);
        bootOffsets = List.copyOf(bootOffsets);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Board profile requires an exact part");
        }
        if (status == Status.EXTERNAL_MEMORY_REVIEWED) {
            if (board == null || board.isBlank() || boardSource == null || bsp == null
                    || cmsisFamily == null || cmsisFamily.isBlank()
                    || externalRegions.isEmpty() || reason != null) {
                throw new IllegalArgumentException(
                    "Reviewed board profile requires a board, sources, regions, and no reason");
            }
        }
        else {
            if (!externalRegions.isEmpty() || !bootOffsets.isEmpty()
                    || reason == null || reason.isBlank() || bsp != null) {
                throw new IllegalArgumentException(
                    "Unavailable board profile must carry a reason and no data");
            }
        }
        Set<String> ids = new java.util.HashSet<>();
        for (ExternalRegion region : externalRegions) {
            if (!ids.add(region.id())) {
                throw new IllegalArgumentException("Duplicate external region id");
            }
        }
        for (int left = 0; left < externalRegions.size(); left++) {
            for (int right = left + 1; right < externalRegions.size(); right++) {
                if (externalRegions.get(left).range()
                        .overlaps(externalRegions.get(right).range())) {
                    throw new IllegalArgumentException("Overlapping external board regions");
                }
            }
        }
    }

    public boolean reviewed() {
        return status == Status.EXTERNAL_MEMORY_REVIEWED;
    }

    /** Total external RAM bytes, excluding flash. */
    public long externalRamBytes() {
        return externalRegions.stream()
            .filter(region -> region.kind() == Kind.EXTERNAL_RAM_MEMORY_MAPPED)
            .mapToLong(region -> region.range().length()).sum();
    }

    /** Total external flash bytes. */
    public long externalFlashBytes() {
        return externalRegions.stream()
            .filter(region -> region.kind() == Kind.EXTERNAL_FLASH_MEMORY_MAPPED)
            .mapToLong(region -> region.range().length()).sum();
    }

    /** Diagnostic detail map for provenance consumers; never contains a fabricated fact. */
    public Map<String, String> provenance() {
        return Map.of("exactPart", exactPart, "board", board == null ? "" : board,
            "status", status.name());
    }
}
