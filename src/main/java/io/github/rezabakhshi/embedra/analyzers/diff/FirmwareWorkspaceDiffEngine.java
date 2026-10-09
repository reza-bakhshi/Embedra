package io.github.rezabakhshi.embedra.analyzers.diff;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure engine for computing multi-view firmware and workspace differences.
 * Analyzes functions, symbols, strings, metadata, memory blocks, and partition layouts.
 */
public final class FirmwareWorkspaceDiffEngine {

    public FirmwareWorkspaceDiff compare(WorkspaceSnapshot source, WorkspaceSnapshot target)
            throws DiagnosticException {
        return compare(source, target, ParserLimits.defaults(), CancellationToken.none());
    }

    public FirmwareWorkspaceDiff compare(
            WorkspaceSnapshot source,
            WorkspaceSnapshot target,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        Objects.requireNonNull(source, "source snapshot cannot be null");
        Objects.requireNonNull(target, "target snapshot cannot be null");
        ParserLimits effectiveLimits = limits != null ? limits : ParserLimits.defaults();
        CancellationToken effectiveToken = token != null ? token : CancellationToken.none();

        effectiveToken.throwIfCancellationRequested();

        long totalObjects = (long) source.functions().size() + target.functions().size()
                + source.symbols().size() + target.symbols().size()
                + source.strings().size() + target.strings().size()
                + source.metadata().size() + target.metadata().size()
                + source.memoryBlocks().size() + target.memoryBlocks().size()
                + source.partitions().size() + target.partitions().size();

        if (totalObjects > effectiveLimits.maxObjects()) {
            String msg = "Total workspace objects (" + totalObjects + ") exceeds limit ("
                    + effectiveLimits.maxObjects() + ")";
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED, msg, null));
        }

        List<FunctionDiffEntry> functionDiffs = diffFunctions(source.functions(), target.functions(), effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<SymbolDiffEntry> symbolDiffs = diffSymbols(source.symbols(), target.symbols(), effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<StringDiffEntry> stringDiffs = diffStrings(source.strings(), target.strings(), effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<MetadataDiffEntry> metadataDiffs = diffMetadata(source.metadata(), target.metadata(), effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<MemoryDiffEntry> memoryDiffs = diffMemoryBlocks(
                source.memoryBlocks(), target.memoryBlocks(), effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        List<PartitionDiffEntry> partitionDiffs = diffPartitions(
                source.partitions(), target.partitions(), effectiveToken);
        effectiveToken.throwIfCancellationRequested();

        return new FirmwareWorkspaceDiff(
                source.workspaceName(),
                target.workspaceName(),
                functionDiffs,
                symbolDiffs,
                stringDiffs,
                metadataDiffs,
                memoryDiffs,
                partitionDiffs);
    }

    private List<FunctionDiffEntry> diffFunctions(
            List<FunctionSnapshot> sourceFuncs,
            List<FunctionSnapshot> targetFuncs,
            CancellationToken token) throws DiagnosticException {

        List<FunctionDiffEntry> entries = new ArrayList<>();
        Map<String, FunctionSnapshot> targetMap = new LinkedHashMap<>();
        for (FunctionSnapshot f : targetFuncs) {
            targetMap.put(f.name(), f);
        }

        Set<String> matchedTargetNames = new HashSet<>();

        for (FunctionSnapshot src : sourceFuncs) {
            token.throwIfCancellationRequested();
            FunctionSnapshot tgt = targetMap.get(src.name());
            if (tgt != null) {
                matchedTargetNames.add(tgt.name());
                boolean sameAddr = src.address() == tgt.address();
                boolean sameLen = src.length() == tgt.length();
                boolean sameHash = Objects.equals(src.bodyHash(), tgt.bodyHash());
                boolean sameSig = Objects.equals(src.signature(), tgt.signature());

                if (sameAddr && sameLen && sameHash && sameSig) {
                    entries.add(new FunctionDiffEntry(
                            src.name(), DiffChangeKind.UNCHANGED,
                            src.address(), tgt.address(),
                            src.length(), tgt.length(),
                            src.bodyHash(), tgt.bodyHash(),
                            "Identical function"));
                } else if (!sameAddr && sameLen && sameHash && sameSig) {
                    entries.add(new FunctionDiffEntry(
                            src.name(), DiffChangeKind.MOVED,
                            src.address(), tgt.address(),
                            src.length(), tgt.length(),
                            src.bodyHash(), tgt.bodyHash(),
                            String.format("Relocated from 0x%x to 0x%x", src.address(), tgt.address())));
                } else {
                    List<String> changes = new ArrayList<>();
                    if (!sameAddr) {
                        changes.add(String.format("address 0x%x -> 0x%x", src.address(), tgt.address()));
                    }
                    if (!sameLen) {
                        changes.add(String.format("length %d -> %d", src.length(), tgt.length()));
                    }
                    if (!sameHash) {
                        changes.add("body hash changed");
                    }
                    if (!sameSig) {
                        changes.add("signature changed");
                    }
                    entries.add(new FunctionDiffEntry(
                            src.name(), DiffChangeKind.MODIFIED,
                            src.address(), tgt.address(),
                            src.length(), tgt.length(),
                            src.bodyHash(), tgt.bodyHash(),
                            String.join(", ", changes)));
                }
            } else {
                entries.add(new FunctionDiffEntry(
                        src.name(), DiffChangeKind.REMOVED,
                        src.address(), null,
                        src.length(), 0L,
                        src.bodyHash(), null,
                        "Function removed in target"));
            }
        }

        for (FunctionSnapshot tgt : targetFuncs) {
            token.throwIfCancellationRequested();
            if (!matchedTargetNames.contains(tgt.name())) {
                entries.add(new FunctionDiffEntry(
                        tgt.name(), DiffChangeKind.ADDED,
                        null, tgt.address(),
                        0L, tgt.length(),
                        null, tgt.bodyHash(),
                        "Function added in target"));
            }
        }

        entries.sort(Comparator.comparing(FunctionDiffEntry::functionName));
        return Collections.unmodifiableList(entries);
    }

    private List<SymbolDiffEntry> diffSymbols(
            List<SymbolSnapshot> sourceSymbols,
            List<SymbolSnapshot> targetSymbols,
            CancellationToken token) throws DiagnosticException {

        List<SymbolDiffEntry> entries = new ArrayList<>();
        Map<String, SymbolSnapshot> targetMap = new LinkedHashMap<>();
        for (SymbolSnapshot s : targetSymbols) {
            targetMap.put(symbolKey(s), s);
        }

        Set<String> matched = new HashSet<>();

        for (SymbolSnapshot src : sourceSymbols) {
            token.throwIfCancellationRequested();
            String key = symbolKey(src);
            SymbolSnapshot tgt = targetMap.get(key);
            if (tgt != null) {
                matched.add(key);
                boolean sameAddr = src.address() == tgt.address();
                boolean sameType = Objects.equals(src.type(), tgt.type());
                if (sameAddr && sameType) {
                    entries.add(new SymbolDiffEntry(
                            src.name(), src.type(), DiffChangeKind.UNCHANGED,
                            src.address(), tgt.address(),
                            src.namespace(), tgt.namespace(),
                            "Identical symbol"));
                } else if (!sameAddr && sameType) {
                    entries.add(new SymbolDiffEntry(
                            src.name(), src.type(), DiffChangeKind.MOVED,
                            src.address(), tgt.address(),
                            src.namespace(), tgt.namespace(),
                            String.format("Moved from 0x%x to 0x%x", src.address(), tgt.address())));
                } else {
                    entries.add(new SymbolDiffEntry(
                            src.name(), tgt.type(), DiffChangeKind.MODIFIED,
                            src.address(), tgt.address(),
                            src.namespace(), tgt.namespace(),
                            String.format("Type changed from %s to %s", src.type(), tgt.type())));
                }
            } else {
                entries.add(new SymbolDiffEntry(
                        src.name(), src.type(), DiffChangeKind.REMOVED,
                        src.address(), null,
                        src.namespace(), null,
                        "Symbol removed in target"));
            }
        }

        for (SymbolSnapshot tgt : targetSymbols) {
            token.throwIfCancellationRequested();
            String key = symbolKey(tgt);
            if (!matched.contains(key)) {
                entries.add(new SymbolDiffEntry(
                        tgt.name(), tgt.type(), DiffChangeKind.ADDED,
                        null, tgt.address(),
                        null, tgt.namespace(),
                        "Symbol added in target"));
            }
        }

        entries.sort(Comparator.comparing(SymbolDiffEntry::symbolName));
        return Collections.unmodifiableList(entries);
    }

    private String symbolKey(SymbolSnapshot s) {
        return (s.namespace() != null ? s.namespace() + "::" : "") + s.name();
    }

    private List<StringDiffEntry> diffStrings(
            List<StringSnapshot> sourceStrings,
            List<StringSnapshot> targetStrings,
            CancellationToken token) throws DiagnosticException {

        List<StringDiffEntry> entries = new ArrayList<>();
        Map<String, List<StringSnapshot>> targetByVal = new HashMap<>();
        for (StringSnapshot s : targetStrings) {
            targetByVal.computeIfAbsent(s.value(), k -> new ArrayList<>()).add(s);
        }

        Set<StringSnapshot> matchedTargets = new HashSet<>();

        for (StringSnapshot src : sourceStrings) {
            token.throwIfCancellationRequested();
            List<StringSnapshot> candidates = targetByVal.get(src.value());
            StringSnapshot matched = null;
            if (candidates != null) {
                // Find matching address first
                for (StringSnapshot cand : candidates) {
                    if (!matchedTargets.contains(cand) && cand.address() == src.address()) {
                        matched = cand;
                        break;
                    }
                }
                // Otherwise find first unmatched candidate
                if (matched == null) {
                    for (StringSnapshot cand : candidates) {
                        if (!matchedTargets.contains(cand)) {
                            matched = cand;
                            break;
                        }
                    }
                }
            }

            if (matched != null) {
                matchedTargets.add(matched);
                if (matched.address() == src.address()) {
                    entries.add(new StringDiffEntry(
                            src.value(), DiffChangeKind.UNCHANGED,
                            src.address(), matched.address(),
                            src.encoding(), src.secret() || matched.secret(),
                            "Identical string at same address"));
                } else {
                    entries.add(new StringDiffEntry(
                            src.value(), DiffChangeKind.MOVED,
                            src.address(), matched.address(),
                            src.encoding(), src.secret() || matched.secret(),
                            String.format("Moved from 0x%x to 0x%x", src.address(), matched.address())));
                }
            } else {
                entries.add(new StringDiffEntry(
                        src.value(), DiffChangeKind.REMOVED,
                        src.address(), null,
                        src.encoding(), src.secret(),
                        "String removed in target"));
            }
        }

        for (StringSnapshot tgt : targetStrings) {
            token.throwIfCancellationRequested();
            if (!matchedTargets.contains(tgt)) {
                entries.add(new StringDiffEntry(
                        tgt.value(), DiffChangeKind.ADDED,
                        null, tgt.address(),
                        tgt.encoding(), tgt.secret(),
                        "String added in target"));
            }
        }

        entries.sort(Comparator.comparing(StringDiffEntry::stringValue));
        return Collections.unmodifiableList(entries);
    }

    private List<MetadataDiffEntry> diffMetadata(
            List<MetadataSnapshot> sourceMeta,
            List<MetadataSnapshot> targetMeta,
            CancellationToken token) throws DiagnosticException {

        List<MetadataDiffEntry> entries = new ArrayList<>();
        Map<String, MetadataSnapshot> targetMap = new LinkedHashMap<>();
        for (MetadataSnapshot m : targetMeta) {
            targetMap.put(m.key(), m);
        }

        Set<String> matched = new HashSet<>();

        for (MetadataSnapshot src : sourceMeta) {
            token.throwIfCancellationRequested();
            MetadataSnapshot tgt = targetMap.get(src.key());
            if (tgt != null) {
                matched.add(tgt.key());
                boolean isSecret = src.secret() || tgt.secret();
                if (Objects.equals(src.value(), tgt.value())) {
                    entries.add(new MetadataDiffEntry(
                            src.key(), DiffChangeKind.UNCHANGED,
                            src.value(), tgt.value(),
                            isSecret, "Identical property"));
                } else {
                    entries.add(new MetadataDiffEntry(
                            src.key(), DiffChangeKind.MODIFIED,
                            src.value(), tgt.value(),
                            isSecret, "Property value changed"));
                }
            } else {
                entries.add(new MetadataDiffEntry(
                        src.key(), DiffChangeKind.REMOVED,
                        src.value(), null,
                        src.secret(), "Property removed in target"));
            }
        }

        for (MetadataSnapshot tgt : targetMeta) {
            token.throwIfCancellationRequested();
            if (!matched.contains(tgt.key())) {
                entries.add(new MetadataDiffEntry(
                        tgt.key(), DiffChangeKind.ADDED,
                        null, tgt.value(),
                        tgt.secret(), "Property added in target"));
            }
        }

        entries.sort(Comparator.comparing(MetadataDiffEntry::propertyKey));
        return Collections.unmodifiableList(entries);
    }

    private List<MemoryDiffEntry> diffMemoryBlocks(
            List<MemoryBlockSnapshot> sourceBlocks,
            List<MemoryBlockSnapshot> targetBlocks,
            CancellationToken token) throws DiagnosticException {

        List<MemoryDiffEntry> entries = new ArrayList<>();
        Map<String, MemoryBlockSnapshot> targetMap = new LinkedHashMap<>();
        for (MemoryBlockSnapshot b : targetBlocks) {
            targetMap.put(b.name(), b);
        }

        Set<String> matched = new HashSet<>();

        for (MemoryBlockSnapshot src : sourceBlocks) {
            token.throwIfCancellationRequested();
            MemoryBlockSnapshot tgt = targetMap.get(src.name());
            if (tgt != null) {
                matched.add(tgt.name());
                boolean sameAddr = src.startAddress() == tgt.startAddress();
                boolean sameSize = src.size() == tgt.size();
                boolean samePerms = Objects.equals(src.permissions(), tgt.permissions());
                boolean sameHash = Objects.equals(src.blockHash(), tgt.blockHash());

                if (sameAddr && sameSize && samePerms && sameHash) {
                    entries.add(new MemoryDiffEntry(
                            src.name(), DiffChangeKind.UNCHANGED,
                            src.startAddress(), tgt.startAddress(),
                            src.size(), tgt.size(),
                            src.permissions(), tgt.permissions(),
                            src.blockHash(), tgt.blockHash(),
                            "Identical memory block"));
                } else if (!sameAddr && sameSize && samePerms && sameHash) {
                    entries.add(new MemoryDiffEntry(
                            src.name(), DiffChangeKind.MOVED,
                            src.startAddress(), tgt.startAddress(),
                            src.size(), tgt.size(),
                            src.permissions(), tgt.permissions(),
                            src.blockHash(), tgt.blockHash(),
                            String.format("Moved from 0x%x to 0x%x", src.startAddress(), tgt.startAddress())));
                } else {
                    List<String> changes = new ArrayList<>();
                    if (!sameAddr) {
                        changes.add(String.format("address 0x%x -> 0x%x", src.startAddress(), tgt.startAddress()));
                    }
                    if (!sameSize) {
                        changes.add(String.format("size %d -> %d", src.size(), tgt.size()));
                    }
                    if (!samePerms) {
                        changes.add(String.format("permissions %s -> %s", src.permissions(), tgt.permissions()));
                    }
                    if (!sameHash) {
                        changes.add("content hash changed");
                    }
                    entries.add(new MemoryDiffEntry(
                            src.name(), DiffChangeKind.MODIFIED,
                            src.startAddress(), tgt.startAddress(),
                            src.size(), tgt.size(),
                            src.permissions(), tgt.permissions(),
                            src.blockHash(), tgt.blockHash(),
                            String.join(", ", changes)));
                }
            } else {
                entries.add(new MemoryDiffEntry(
                        src.name(), DiffChangeKind.REMOVED,
                        src.startAddress(), null,
                        src.size(), 0L,
                        src.permissions(), null,
                        src.blockHash(), null,
                        "Memory block removed in target"));
            }
        }

        for (MemoryBlockSnapshot tgt : targetBlocks) {
            token.throwIfCancellationRequested();
            if (!matched.contains(tgt.name())) {
                entries.add(new MemoryDiffEntry(
                        tgt.name(), DiffChangeKind.ADDED,
                        null, tgt.startAddress(),
                        0L, tgt.size(),
                        null, tgt.permissions(),
                        null, tgt.blockHash(),
                        "Memory block added in target"));
            }
        }

        entries.sort(Comparator.comparing(MemoryDiffEntry::blockName));
        return Collections.unmodifiableList(entries);
    }

    private List<PartitionDiffEntry> diffPartitions(
            List<PartitionSnapshot> sourceParts,
            List<PartitionSnapshot> targetParts,
            CancellationToken token) throws DiagnosticException {

        List<PartitionDiffEntry> entries = new ArrayList<>();
        Map<String, PartitionSnapshot> targetMap = new LinkedHashMap<>();
        for (PartitionSnapshot p : targetParts) {
            targetMap.put(p.name(), p);
        }

        Set<String> matched = new HashSet<>();

        for (PartitionSnapshot src : sourceParts) {
            token.throwIfCancellationRequested();
            PartitionSnapshot tgt = targetMap.get(src.name());
            if (tgt != null) {
                matched.add(tgt.name());
                boolean sameOffset = src.offset() == tgt.offset();
                boolean sameSize = src.size() == tgt.size();
                boolean sameType = Objects.equals(src.type(), tgt.type());
                boolean sameSub = Objects.equals(src.subtype(), tgt.subtype());
                boolean sameFlags = Objects.equals(src.flags(), tgt.flags());

                if (sameOffset && sameSize && sameType && sameSub && sameFlags) {
                    entries.add(new PartitionDiffEntry(
                            src.name(), DiffChangeKind.UNCHANGED,
                            src.type(), src.subtype(),
                            src.offset(), tgt.offset(),
                            src.size(), tgt.size(),
                            src.flags(), tgt.flags(),
                            "Identical partition"));
                } else if (!sameOffset && sameSize && sameType && sameSub && sameFlags) {
                    entries.add(new PartitionDiffEntry(
                            src.name(), DiffChangeKind.MOVED,
                            src.type(), src.subtype(),
                            src.offset(), tgt.offset(),
                            src.size(), tgt.size(),
                            src.flags(), tgt.flags(),
                            String.format("Offset shifted from 0x%x to 0x%x", src.offset(), tgt.offset())));
                } else {
                    List<String> changes = new ArrayList<>();
                    if (!sameOffset) {
                        changes.add(String.format("offset 0x%x -> 0x%x", src.offset(), tgt.offset()));
                    }
                    if (!sameSize) {
                        changes.add(String.format("size %d -> %d", src.size(), tgt.size()));
                    }
                    if (!sameType || !sameSub) {
                        String typeChange = String.format("type %s/%s -> %s/%s",
                                src.type(), src.subtype(), tgt.type(), tgt.subtype());
                        changes.add(typeChange);
                    }
                    if (!sameFlags) {
                        changes.add(String.format("flags %s -> %s", src.flags(), tgt.flags()));
                    }
                    entries.add(new PartitionDiffEntry(
                            src.name(), DiffChangeKind.MODIFIED,
                            tgt.type(), tgt.subtype(),
                            src.offset(), tgt.offset(),
                            src.size(), tgt.size(),
                            src.flags(), tgt.flags(),
                            String.join(", ", changes)));
                }
            } else {
                entries.add(new PartitionDiffEntry(
                        src.name(), DiffChangeKind.REMOVED,
                        src.type(), src.subtype(),
                        src.offset(), null,
                        src.size(), 0L,
                        src.flags(), null,
                        "Partition removed in target"));
            }
        }

        for (PartitionSnapshot tgt : targetParts) {
            token.throwIfCancellationRequested();
            if (!matched.contains(tgt.name())) {
                entries.add(new PartitionDiffEntry(
                        tgt.name(), DiffChangeKind.ADDED,
                        tgt.type(), tgt.subtype(),
                        null, tgt.offset(),
                        0L, tgt.size(),
                        null, tgt.flags(),
                        "Partition added in target"));
            }
        }

        entries.sort(Comparator.comparing(PartitionDiffEntry::partitionName));
        return Collections.unmodifiableList(entries);
    }
}
