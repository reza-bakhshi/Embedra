package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure parser for representative STM32MP Device Tree Source (DTS) excerpts.
 *
 * <p>Extracts remoteproc, mailbox, semaphore, and reserved-memory nodes under
 * shared {@link ParserLimits} and cooperative {@link CancellationToken}.</p>
 */
public final class Stm32MpDeviceTreeParser {
    private static final Pattern RESERVED_MEM_PATTERN = Pattern.compile(
        "([a-zA-Z0-9_]+):\\s*([a-zA-Z0-9_@]+)\\s*\\{([^}]+)\\}"
    );

    private static final Pattern REG_PATTERN = Pattern.compile(
        "reg\\s*=\\s*<\\s*(0x[0-9a-fA-F]+|[0-9]+)\\s+(0x[0-9a-fA-F]+|[0-9]+)\\s*>"
    );

    private static final Pattern MEMORY_REGION_PATTERN = Pattern.compile(
        "memory-region\\s*=\\s*([^;]+);"
    );

    private static final Pattern MBOXES_PATTERN = Pattern.compile(
        "mboxes\\s*=\\s*([^;]+);"
    );

    private static final Pattern MBOX_CELL_PATTERN = Pattern.compile(
        "<\\s*&([a-zA-Z0-9_]+)\\s+([0-9]+)\\s*>"
    );

    private static final Pattern HWLOCKS_PATTERN = Pattern.compile(
        "hwlocks\\s*=\\s*<\\s*&([a-zA-Z0-9_]+)\\s+([0-9]+)\\s*>;"
    );

    private Stm32MpDeviceTreeParser() {
    }

    public static Stm32MpDeviceTreePlan parse(
            String exactPart,
            String dtsContent,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(dtsContent, "dtsContent");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");

        token.throwIfCancellationRequested();

        long byteLength = dtsContent.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (byteLength > limits.maxInputBytes() || byteLength > limits.maxAllocationBytes()) {
            throw new IllegalArgumentException("DTS input exceeds byte limits: " + byteLength);
        }

        // Check nesting depth
        int currentDepth = 0;
        int maxObservedDepth = 0;
        for (int i = 0; i < dtsContent.length(); i++) {
            char c = dtsContent.charAt(i);
            if (c == '{') {
                currentDepth++;
                if (currentDepth > maxObservedDepth) {
                    maxObservedDepth = currentDepth;
                }
                if (currentDepth > limits.maxNestingDepth()) {
                    throw new IllegalArgumentException("DTS exceeds max nesting depth: " + currentDepth);
                }
            } else if (c == '}') {
                currentDepth--;
            }
        }

        token.throwIfCancellationRequested();

        List<Evidence> evidence = List.of(
            new Evidence(EvidenceKind.DOCUMENTED_FIELD, "DTS", "Parsed from DTS input for target " + exactPart)
        );

        List<Stm32MpDeviceTreePlan.ReservedMemoryNode> reservedNodes = new ArrayList<>();
        List<Stm32MpDeviceTreePlan.MailboxBinding> mailboxBindings = new ArrayList<>();
        List<Stm32MpDeviceTreePlan.SemaphoreBinding> semaphoreBindings = new ArrayList<>();
        List<Stm32MpDeviceTreePlan.RemoteProcNode> remoteProcNodes = new ArrayList<>();

        // Locate reserved-memory block
        int resMemStart = dtsContent.indexOf("reserved-memory");
        if (resMemStart >= 0) {
            int openBrace = dtsContent.indexOf('{', resMemStart);
            if (openBrace > 0) {
                int closeBrace = findMatchingBrace(dtsContent, openBrace);
                if (closeBrace > openBrace) {
                    String block = dtsContent.substring(openBrace + 1, closeBrace);
                    Matcher m = RESERVED_MEM_PATTERN.matcher(block);
                    while (m.find()) {
                        token.throwIfCancellationRequested();
                        String label = m.group(1);
                        String body = m.group(3);
                        Matcher regMatcher = REG_PATTERN.matcher(body);
                        if (regMatcher.find()) {
                            long start = parseNumber(regMatcher.group(1));
                            long len = parseNumber(regMatcher.group(2));
                            boolean noMap = body.contains("no-map");
                            reservedNodes.add(new Stm32MpDeviceTreePlan.ReservedMemoryNode(
                                label,
                                new AddressRange("ram", start, len),
                                noMap,
                                "reserved-pool",
                                Confidence.VERIFIED,
                                evidence
                            ));
                        }
                    }
                }
            }
        }

        token.throwIfCancellationRequested();

        // Scan for mailbox nodes
        Pattern mboxDefPattern = Pattern.compile("([a-zA-Z0-9_]+):\\s*(mailbox@[0-9a-fA-F]+)\\s*\\{([^}]+)\\}");
        Matcher mboxMatcher = mboxDefPattern.matcher(dtsContent);
        while (mboxMatcher.find()) {
            token.throwIfCancellationRequested();
            String name = mboxMatcher.group(1);
            String body = mboxMatcher.group(3);
            Matcher regMatcher = REG_PATTERN.matcher(body);
            if (regMatcher.find()) {
                long start = parseNumber(regMatcher.group(1));
                long len = parseNumber(regMatcher.group(2));
                mailboxBindings.add(new Stm32MpDeviceTreePlan.MailboxBinding(
                    name,
                    new AddressRange("periph", start, len),
                    2,
                    List.of("rx", "tx"),
                    Confidence.VERIFIED,
                    evidence
                ));
            }
        }

        token.throwIfCancellationRequested();

        // Scan for semaphore / hwspinlock nodes
        Pattern semDefPattern = Pattern.compile("([a-zA-Z0-9_]+):\\s*(hwspinlock@[0-9a-fA-F]+)\\s*\\{([^}]+)\\}");
        Matcher semMatcher = semDefPattern.matcher(dtsContent);
        while (semMatcher.find()) {
            token.throwIfCancellationRequested();
            String name = semMatcher.group(1);
            String body = semMatcher.group(3);
            Matcher regMatcher = REG_PATTERN.matcher(body);
            if (regMatcher.find()) {
                long start = parseNumber(regMatcher.group(1));
                long len = parseNumber(regMatcher.group(2));
                semaphoreBindings.add(new Stm32MpDeviceTreePlan.SemaphoreBinding(
                    name,
                    new AddressRange("periph", start, len),
                    32,
                    Confidence.VERIFIED,
                    evidence
                ));
            }
        }

        token.throwIfCancellationRequested();

        // Scan for remoteproc nodes (e.g. m4_rproc: m4@0 or m33_rproc: m33@0)
        Pattern rprocDefPattern = Pattern.compile("([a-zA-Z0-9_]+):\\s*(m[0-9_]+@[0-9a-fA-F]+)\\s*\\{([^}]+)\\}");
        Matcher rprocMatcher = rprocDefPattern.matcher(dtsContent);
        while (rprocMatcher.find()) {
            token.throwIfCancellationRequested();
            String nodeName = rprocMatcher.group(1);
            String body = rprocMatcher.group(3);

            List<String> memRegions = new ArrayList<>();
            Matcher memMatcher = MEMORY_REGION_PATTERN.matcher(body);
            if (memMatcher.find()) {
                String refs = memMatcher.group(1);
                Matcher refMatcher = Pattern.compile("<&([a-zA-Z0-9_]+)>").matcher(refs);
                while (refMatcher.find()) {
                    memRegions.add(refMatcher.group(1));
                }
            }

            List<Stm32MpDeviceTreePlan.MailboxChannel> channels = new ArrayList<>();
            Matcher mboxesMatcher = MBOXES_PATTERN.matcher(body);
            if (mboxesMatcher.find()) {
                String refs = mboxesMatcher.group(1);
                Matcher cellMatcher = MBOX_CELL_PATTERN.matcher(refs);
                int channelIdx = 0;
                while (cellMatcher.find()) {
                    String controller = cellMatcher.group(1);
                    int idx = Integer.parseInt(cellMatcher.group(2));
                    channels.add(new Stm32MpDeviceTreePlan.MailboxChannel("chan" + channelIdx++, controller, idx));
                }
            }

            Optional<String> hwlock = Optional.empty();
            Matcher hwlockMatcher = HWLOCKS_PATTERN.matcher(body);
            if (hwlockMatcher.find()) {
                hwlock = Optional.of(hwlockMatcher.group(1));
            }

            String coreId = nodeName.contains("m33") ? "cm33" : "cm4";
            remoteProcNodes.add(new Stm32MpDeviceTreePlan.RemoteProcNode(
                nodeName,
                coreId,
                memRegions,
                channels,
                hwlock,
                Confidence.VERIFIED,
                evidence
            ));
        }

        return new Stm32MpDeviceTreePlan(
            exactPart,
            "parsed-dts",
            "BSD-3-Clause",
            remoteProcNodes,
            mailboxBindings,
            semaphoreBindings,
            reservedNodes,
            Confidence.VERIFIED,
            evidence
        );
    }

    private static int findMatchingBrace(String content, int openIndex) {
        int depth = 1;
        for (int i = openIndex + 1; i < content.length(); i++) {
            char c = content.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static long parseNumber(String text) {
        String trimmed = text.trim();
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            return Long.parseUnsignedLong(trimmed.substring(2), 16);
        }
        return Long.parseUnsignedLong(trimmed);
    }
}
