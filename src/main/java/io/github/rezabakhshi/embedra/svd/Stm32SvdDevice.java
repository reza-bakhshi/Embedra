package io.github.rezabakhshi.embedra.svd;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Immutable, provenance-bearing representation of an STM32 CMSIS-SVD device. */
public final class Stm32SvdDevice {
    private final String name;

    private final String sourceRevision;

    private final List<Stm32SvdPeripheral> peripherals;

    private final List<Stm32SvdInterrupt> interrupts;

    private final Map<String, Stm32SvdPeripheral> peripheralsByName;

    private final Set<String> ambiguousInterruptNames;

    public Stm32SvdDevice(String name, String sourceRevision,
            List<Stm32SvdPeripheral> peripherals) {
        this.name = requireText(name, "device name");
        this.sourceRevision = requireText(sourceRevision, "source revision");
        this.peripherals = List.copyOf(peripherals);
        if (this.peripherals.isEmpty()) {
            throw new IllegalArgumentException("SVD device must contain peripherals");
        }
        Map<String, Stm32SvdPeripheral> indexed = new HashMap<>();
        List<Stm32SvdInterrupt> flattened = new ArrayList<>();
        Set<String> seenPairs = new TreeSet<>();
        Map<String, Set<Integer>> numbersByName = new LinkedHashMap<>();
        for (Stm32SvdPeripheral peripheral : this.peripherals) {
            if (indexed.put(peripheral.name(), peripheral) != null) {
                throw new IllegalArgumentException("Duplicate SVD peripheral name");
            }
            for (Stm32SvdInterrupt interrupt : peripheral.interrupts()) {
                numbersByName.computeIfAbsent(interrupt.name(),
                    key -> new TreeSet<>()).add(interrupt.number());
                if (seenPairs.add(interrupt.name() + '\0' + interrupt.number())) {
                    flattened.add(interrupt);
                }
            }
        }
        flattened.sort(Comparator.comparingInt(Stm32SvdInterrupt::number)
            .thenComparing(Stm32SvdInterrupt::name));
        this.interrupts = List.copyOf(flattened);
        this.peripheralsByName = Map.copyOf(indexed);
        Set<String> ambiguous = new TreeSet<>();
        numbersByName.forEach((interruptName, numbers) -> {
            if (numbers.size() > 1) {
                ambiguous.add(interruptName);
            }
        });
        this.ambiguousInterruptNames = Set.copyOf(ambiguous);
    }

    public String name() {
        return name;
    }

    public String sourceRevision() {
        return sourceRevision;
    }

    public List<Stm32SvdPeripheral> peripherals() {
        return peripherals;
    }

    /** Distinct interrupt lines across peripherals, ordered by encoded number then name. */
    public List<Stm32SvdInterrupt> interrupts() {
        return interrupts;
    }

    /** Names that resolve to more than one encoded number and must not be applied blindly. */
    public Set<String> ambiguousInterruptNames() {
        return ambiguousInterruptNames;
    }

    public Stm32SvdPeripheral requirePeripheral(String peripheralName) {
        Stm32SvdPeripheral peripheral = peripheralsByName.get(peripheralName);
        if (peripheral == null) {
            throw new IllegalArgumentException("Unknown SVD peripheral: " + peripheralName);
        }
        return peripheral;
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
