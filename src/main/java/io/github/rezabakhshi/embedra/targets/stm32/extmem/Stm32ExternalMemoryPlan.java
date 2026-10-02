package io.github.rezabakhshi.embedra.targets.stm32.extmem;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardProfile;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable external-memory mapping plan for one exact curated part.
 *
 * <p>The plan references the validated T039 MCU plan without mutating it and
 * pairs it with one confirmed board fact source. A mapped plan carries one
 * {@link MappingWindow} per external device: the pinned CPU-mapped aperture,
 * its controller, and the mechanical controller-family projection. An
 * unavailable plan carries only a pinned reason. Windows must be numerically
 * disjoint and inside the 32-bit space; no window, alias, size, or permission
 * is ever invented here.</p>
 */
public record Stm32ExternalMemoryPlan(
        String exactPart,
        Status status,
        String reason,
        Source source,
        String board,
        Stm32MemoryPlanner.Plan mcuPlan,
        List<MappingWindow> windows,
        List<Stm32BoardProfile.BootOffset> bootOffsets,
        List<Evidence> evidence) {

    /** Whether external memory is mapped for the part, or explicitly unavailable. */
    public enum Status {
        EXTERNAL_MEMORY_MAPPED, UNAVAILABLE
    }

    /** Which confirmed fact source supplied the windows; never a fabricated link. */
    public enum Source {
        PINNED_T042_BOARD_PROFILE, CONFIRMED_CUSTOM_PROFILE
    }

    public Stm32ExternalMemoryPlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(mcuPlan, "mcuPlan");
        windows = List.copyOf(windows);
        bootOffsets = List.copyOf(bootOffsets);
        evidence = List.copyOf(evidence);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("External-memory plan requires an exact part");
        }
        if (!exactPart.equals(mcuPlan.exactPart())) {
            throw new IllegalArgumentException(
                "External-memory plan does not match its MCU plan");
        }
        Set<String> ids = new java.util.HashSet<>();
        for (MappingWindow window : windows) {
            if (!ids.add(window.id())) {
                throw new IllegalArgumentException("Duplicate external-memory window");
            }
        }
        for (int left = 0; left < windows.size(); left++) {
            for (int right = left + 1; right < windows.size(); right++) {
                if (windows.get(left).numericallyOverlaps(windows.get(right))) {
                    throw new IllegalArgumentException("Overlapping external-memory windows");
                }
            }
        }
        if (status == Status.EXTERNAL_MEMORY_MAPPED) {
            if (reason != null || source == null || board == null || board.isBlank()
                    || windows.isEmpty()) {
                throw new IllegalArgumentException(
                    "A mapped external-memory plan requires a source, a board, and windows");
            }
        }
        else {
            if (reason == null || reason.isBlank() || source != null || board != null
                    || !windows.isEmpty() || !bootOffsets.isEmpty()) {
                throw new IllegalArgumentException(
                    "An unavailable external-memory plan requires a reason and no data");
            }
        }
    }

    /** True when this part has mapped external memory from a confirmed source. */
    public boolean mapped() {
        return status == Status.EXTERNAL_MEMORY_MAPPED;
    }

    /** Every exact STM32 part remains PLANNED; external-memory planning never promotes. */
    public String supportState() {
        return "PLANNED";
    }

    /**
     * One controller window: the CPU-mapped aperture of one external device.
     *
     * <p>The {@code mappedRange} is the pinned T042 fact: an {@code ext-mem}
     * tagged range whose numeric start is the CPU aperture base and whose length
     * is the mapped device extent. Device offsets are plain indices into
     * {@code [0, length)} of that extent; they are never CPU addresses. The
     * {@code controllerFamily} is the mechanical projection of the pinned
     * controller name onto the modeled OCTOSPI/XSPI/QUADSPI/FMC families.</p>
     *
     * @param id the pinned window id, unique inside the plan
     * @param kind the pinned physical kind: external flash or external RAM
     * @param device the pinned external device name
     * @param controller the pinned controller name, e.g. {@code OCTOSPI1}
     * @param controllerFamily the mechanical controller-family projection
     * @param mappedRange the pinned aperture in the {@code ext-mem} space
     * @param writable the pinned writability of the mapped window
     * @param startEvidence the pinned quoted evidence for the aperture base
     * @param sizeEvidence the pinned quoted evidence for the device extent
     */
    public record MappingWindow(String id, Stm32BoardProfile.Kind kind, String device,
            String controller, ControllerFamily controllerFamily, AddressRange mappedRange,
            boolean writable, String startEvidence, String sizeEvidence) {

        public MappingWindow {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(device, "device");
            Objects.requireNonNull(controller, "controller");
            Objects.requireNonNull(controllerFamily, "controllerFamily");
            Objects.requireNonNull(mappedRange, "mappedRange");
            Objects.requireNonNull(startEvidence, "startEvidence");
            Objects.requireNonNull(sizeEvidence, "sizeEvidence");
            if (id.isBlank() || device.isBlank() || controller.isBlank()
                    || startEvidence.isBlank() || sizeEvidence.isBlank()) {
                throw new IllegalArgumentException("External-memory window identity is incomplete");
            }
            if (mappedRange.length() <= 0 || mappedRange.endExclusive() > 0x1_0000_0000L) {
                throw new IllegalArgumentException(
                    "External-memory window must fit the 32-bit space");
            }
        }

        /** True when the numeric CPU address falls inside this aperture. */
        public boolean coversCpuAddress(long address) {
            return mappedRange.start() <= address && address < mappedRange.endExclusive();
        }

        /** True when the device offset falls inside this device extent. */
        public boolean coversDeviceOffset(long offset) {
            return offset >= 0 && offset < mappedRange.length();
        }

        /** Translates a covered CPU aperture address into its device offset. */
        public long deviceOffsetOfCpuAddress(long address) {
            if (!coversCpuAddress(address)) {
                throw new IllegalArgumentException(
                    "Address " + address + " is outside window " + id);
            }
            return address - mappedRange.start();
        }

        /** Translates a covered device offset into its CPU aperture address. */
        public long cpuAddressOfDeviceOffset(long offset) {
            if (!coversDeviceOffset(offset)) {
                throw new IllegalArgumentException(
                    "Device offset " + offset + " is outside window " + id);
            }
            return mappedRange.start() + offset;
        }

        /** Numeric overlap check across the shared 32-bit space, ignoring tags. */
        public boolean numericallyOverlaps(MappingWindow other) {
            Objects.requireNonNull(other, "other");
            return mappedRange.start() < other.mappedRange.endExclusive()
                && other.mappedRange.start() < mappedRange.endExclusive();
        }

        /** True when two windows belong to the same physical controller. */
        public boolean sameController(MappingWindow other) {
            return controller.equals(other.controller);
        }
    }

    /** The modeled memory-controller families; unknown names fail closed. */
    public enum ControllerFamily {
        OCTOSPI, XSPI, QUADSPI, FMC;

        /** Projects the confirmed controller name mechanically; no invention. */
        public static ControllerFamily of(String controller) {
            Objects.requireNonNull(controller, "controller");
            String name = controller.toUpperCase(Locale.ROOT);
            if (name.startsWith("OCTOSPI")) {
                return OCTOSPI;
            }
            if (name.startsWith("XSPI")) {
                return XSPI;
            }
            if (name.startsWith("QUADSPI")) {
                return QUADSPI;
            }
            if (name.startsWith("FMC")) {
                return FMC;
            }
            throw new IllegalArgumentException(
                "Controller " + controller + " is outside the modeled OCTOSPI/XSPI/QUADSPI/FMC "
                    + "families");
        }
    }
}
