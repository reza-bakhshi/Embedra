package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Validated device tree model covering remoteproc, mailbox, semaphore, and memory reserves.
 *
 * <p>Captures Linux and U-Boot device tree nodes that bind heterogeneous coprocessors
 * to dedicated hardware controllers and reserved memory windows.</p>
 */
public record Stm32MpDeviceTreePlan(
        String exactPart,
        String dtsSource,
        String license,
        List<RemoteProcNode> remoteProcNodes,
        List<MailboxBinding> mailboxControllers,
        List<SemaphoreBinding> semaphoreControllers,
        List<ReservedMemoryNode> reservedMemoryNodes,
        Confidence confidence,
        List<Evidence> evidence) {

    public Stm32MpDeviceTreePlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(dtsSource, "dtsSource");
        Objects.requireNonNull(license, "license");
        Objects.requireNonNull(confidence, "confidence");
        remoteProcNodes = List.copyOf(remoteProcNodes);
        mailboxControllers = List.copyOf(mailboxControllers);
        semaphoreControllers = List.copyOf(semaphoreControllers);
        reservedMemoryNodes = List.copyOf(reservedMemoryNodes);
        evidence = List.copyOf(evidence);

        if (exactPart.isBlank() || dtsSource.isBlank() || license.isBlank()) {
            throw new IllegalArgumentException("Device tree plan string metadata must not be blank");
        }

        Set<String> nodeNames = new HashSet<>();
        for (RemoteProcNode rproc : remoteProcNodes) {
            if (!nodeNames.add(rproc.nodeName())) {
                throw new IllegalArgumentException("Duplicate remoteproc node name: " + rproc.nodeName());
            }
        }
        for (MailboxBinding mbox : mailboxControllers) {
            if (!nodeNames.add(mbox.nodeName())) {
                throw new IllegalArgumentException("Duplicate mailbox node name: " + mbox.nodeName());
            }
        }
        for (SemaphoreBinding sem : semaphoreControllers) {
            if (!nodeNames.add(sem.nodeName())) {
                throw new IllegalArgumentException("Duplicate semaphore node name: " + sem.nodeName());
            }
        }
        Set<String> memNames = new HashSet<>();
        for (int i = 0; i < reservedMemoryNodes.size(); i++) {
            ReservedMemoryNode left = reservedMemoryNodes.get(i);
            if (!memNames.add(left.nodeName())) {
                throw new IllegalArgumentException("Duplicate reserved memory node: " + left.nodeName());
            }
            for (int j = i + 1; j < reservedMemoryNodes.size(); j++) {
                ReservedMemoryNode right = reservedMemoryNodes.get(j);
                if (left.range().overlaps(right.range())) {
                    throw new IllegalArgumentException("Overlapping reserved memory regions: "
                        + left.nodeName() + " and " + right.nodeName());
                }
            }
        }
    }

    /** Remoteproc node configuration binding a coprocessor. */
    public record RemoteProcNode(
            String nodeName,
            String coreId,
            List<String> reservedMemoryRegions,
            List<MailboxChannel> mailboxChannels,
            Optional<String> hwlockReference,
            Confidence confidence,
            List<Evidence> evidence) {

        public RemoteProcNode {
            Objects.requireNonNull(nodeName, "nodeName");
            Objects.requireNonNull(coreId, "coreId");
            Objects.requireNonNull(hwlockReference, "hwlockReference");
            Objects.requireNonNull(confidence, "confidence");
            reservedMemoryRegions = List.copyOf(reservedMemoryRegions);
            mailboxChannels = List.copyOf(mailboxChannels);
            evidence = List.copyOf(evidence);
            if (nodeName.isBlank() || coreId.isBlank()) {
                throw new IllegalArgumentException("Remoteproc node fields must not be blank");
            }
        }
    }

    /** Logical mailbox channel reference. */
    public record MailboxChannel(String name, String mailboxNode, int channelIndex) {
        public MailboxChannel {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(mailboxNode, "mailboxNode");
            if (name.isBlank() || mailboxNode.isBlank() || channelIndex < 0) {
                throw new IllegalArgumentException("Mailbox channel parameters are invalid");
            }
        }
    }

    /** Hardware mailbox controller binding (IPCC). */
    public record MailboxBinding(
            String nodeName,
            AddressRange registerRange,
            int numChannels,
            List<String> channelNames,
            Confidence confidence,
            List<Evidence> evidence) {

        public MailboxBinding {
            Objects.requireNonNull(nodeName, "nodeName");
            Objects.requireNonNull(registerRange, "registerRange");
            Objects.requireNonNull(confidence, "confidence");
            channelNames = List.copyOf(channelNames);
            evidence = List.copyOf(evidence);
            if (nodeName.isBlank() || numChannels <= 0) {
                throw new IllegalArgumentException("Mailbox binding parameters are invalid");
            }
        }
    }

    /** Hardware semaphore controller binding (HSEM). */
    public record SemaphoreBinding(
            String nodeName,
            AddressRange registerRange,
            int numSemaphores,
            Confidence confidence,
            List<Evidence> evidence) {

        public SemaphoreBinding {
            Objects.requireNonNull(nodeName, "nodeName");
            Objects.requireNonNull(registerRange, "registerRange");
            Objects.requireNonNull(confidence, "confidence");
            evidence = List.copyOf(evidence);
            if (nodeName.isBlank() || numSemaphores <= 0) {
                throw new IllegalArgumentException("Semaphore binding parameters are invalid");
            }
        }
    }

    /** Reserved physical memory region for DMA, vrings, or coprocessor firmware. */
    public record ReservedMemoryNode(
            String nodeName,
            AddressRange range,
            boolean noMap,
            String poolUsage,
            Confidence confidence,
            List<Evidence> evidence) {

        public ReservedMemoryNode {
            Objects.requireNonNull(nodeName, "nodeName");
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(poolUsage, "poolUsage");
            Objects.requireNonNull(confidence, "confidence");
            evidence = List.copyOf(evidence);
            if (nodeName.isBlank() || poolUsage.isBlank()) {
                throw new IllegalArgumentException("Reserved memory node fields must not be blank");
            }
        }
    }
}
