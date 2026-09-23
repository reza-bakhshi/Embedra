package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticSeverity;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Deterministic registry for T021 partition handlers and conservative inspections. */
public final class EspPartitionHandlerRegistry {
    private final List<EspPartitionHandler> handlers;

    private EspPartitionHandlerRegistry(List<EspPartitionHandler> handlers) {
        this.handlers = List.copyOf(handlers);
    }

    public static EspPartitionHandlerRegistry defaults() {
        return new EspPartitionHandlerRegistry(List.of(
            new EncryptedHandler(),
            new EspOtaStateHandler(),
            new SimpleHandler(EspPartitionHandlerKind.PHY, 1, 0x01,
                EspPartitionDisposition.OPAQUE, false),
            new NvsHandler(),
            new CoreDumpHandler(),
            new NvsKeysHandler(),
            new FatHandler(),
            new FileSystemHandler(EspPartitionHandlerKind.SPIFFS, 0x82),
            new FileSystemHandler(EspPartitionHandlerKind.LITTLEFS, 0x83),
            new InactiveApplicationHandler(),
            new CustomHandler()));
    }

    public EspPartitionHandler handlerFor(EspPartitionEntry entry) {
        Objects.requireNonNull(entry, "entry");
        return handlers.stream().filter(handler -> handler.supports(entry))
            .findFirst().orElseThrow(() -> new IllegalStateException(
                "Default custom handler did not accept partition"));
    }

    public EspPartitionAnalysis analyze(EspPartitionTable table,
            List<EspExtractedPartition> partitions,
            List<String> populatedApplicationLabels, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        Objects.requireNonNull(table, "table");
        Objects.requireNonNull(partitions, "partitions");
        Objects.requireNonNull(populatedApplicationLabels,
            "populatedApplicationLabels");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        if (partitions.size() > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Partition-handler count exceeds the configured object limit",
                table.sourceRange()));
        }
        List<EspPartitionInspection> inspections = new ArrayList<>();
        Optional<EspOtaSelection> otaSelection = Optional.empty();
        for (EspExtractedPartition partition : partitions) {
            cancellation.throwIfCancellationRequested();
            EspPartitionHandler handler = handlerFor(partition.entry());
            inspections.add(handler.inspect(partition, limits, cancellation));
            if (handler instanceof EspOtaStateHandler otaHandler
                && partition.payload().length >= 2 * 4096) {
                otaSelection = Optional.of(otaHandler.select(partition, table,
                    populatedApplicationLabels, cancellation));
            }
        }
        return new EspPartitionAnalysis(inspections, otaSelection);
    }

    private abstract static class BaseHandler implements EspPartitionHandler {
        protected EspPartitionInspection result(EspExtractedPartition partition,
                EspPartitionDisposition disposition, Map<String, String> metadata,
                List<Diagnostic> diagnostics, boolean sensitive) {
            return new EspPartitionInspection(partition.entry(), kind(), disposition,
                partition.sourceRange(), metadata, diagnostics, sensitive);
        }

        protected EspPartitionInspection erased(EspExtractedPartition partition,
                CancellationToken cancellation, boolean sensitive)
                throws DiagnosticException {
            if (isErased(partition.payload(), cancellation)) {
                return result(partition, EspPartitionDisposition.ERASED, Map.of(),
                    List.of(), sensitive);
            }
            return null;
        }
    }

    private static final class EncryptedHandler extends BaseHandler {
        @Override
        public EspPartitionHandlerKind kind() {
            return EspPartitionHandlerKind.ENCRYPTED;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return entry.encrypted();
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            cancellation.throwIfCancellationRequested();
            return result(partition, EspPartitionDisposition.OPAQUE, Map.of(),
                List.of(), true);
        }
    }

    private static class SimpleHandler extends BaseHandler {
        private final EspPartitionHandlerKind kind;

        private final int type;

        private final int subtype;

        private final EspPartitionDisposition disposition;

        private final boolean sensitive;

        private SimpleHandler(EspPartitionHandlerKind kind, int type, int subtype,
                EspPartitionDisposition disposition, boolean sensitive) {
            this.kind = kind;
            this.type = type;
            this.subtype = subtype;
            this.disposition = disposition;
            this.sensitive = sensitive;
        }

        @Override
        public EspPartitionHandlerKind kind() {
            return kind;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return !entry.encrypted() && entry.type() == type
                && entry.subtype() == subtype;
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            EspPartitionInspection erased = erased(partition, cancellation, sensitive);
            return erased != null ? erased : result(partition, disposition, Map.of(),
                List.of(), sensitive);
        }
    }

    private static final class NvsHandler extends BaseHandler {
        private static final int PAGE_SIZE = 4096;

        @Override
        public EspPartitionHandlerKind kind() {
            return EspPartitionHandlerKind.NVS;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return !entry.encrypted() && entry.type() == 1 && entry.subtype() == 2;
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            EspPartitionInspection erased = erased(partition, cancellation, false);
            if (erased != null) {
                return erased;
            }
            byte[] payload = partition.payload();
            if (payload.length % PAGE_SIZE != 0) {
                return invalid(partition, kind(),
                    "NVS partition is not page aligned");
            }
            int initialized = 0;
            int uninitialized = 0;
            int unknown = 0;
            for (int offset = 0; offset < payload.length; offset += PAGE_SIZE) {
                cancellation.throwIfCancellationRequested();
                long state = unsignedInt(payload, offset);
                if (state == 0xffff_ffffL) {
                    uninitialized++;
                }
                else if (state == 0xffff_fffeL || state == 0xffff_fffcL
                    || state == 0xffff_fff8L || state == 0xffff_fff0L) {
                    initialized++;
                }
                else {
                    unknown++;
                }
            }
            Map<String, String> metadata = new LinkedHashMap<>();
            metadata.put("pageCount", Integer.toString(payload.length / PAGE_SIZE));
            metadata.put("initializedPages", Integer.toString(initialized));
            metadata.put("uninitializedPages", Integer.toString(uninitialized));
            if (unknown != 0) {
                metadata.put("unknownStatePages", Integer.toString(unknown));
                return result(partition, EspPartitionDisposition.INVALID, metadata,
                    List.of(warning("NVS contains unknown page states",
                        partition.sourceRange())), false);
            }
            return result(partition, EspPartitionDisposition.VALIDATED_METADATA,
                metadata, List.of(), false);
        }
    }

    private static final class NvsKeysHandler extends BaseHandler {
        @Override
        public EspPartitionHandlerKind kind() {
            return EspPartitionHandlerKind.NVS_KEYS;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return !entry.encrypted() && entry.type() == 1 && entry.subtype() == 4;
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            EspPartitionInspection erased = erased(partition, cancellation, true);
            return erased != null ? erased : result(partition,
                EspPartitionDisposition.SENSITIVE_REDACTED,
                Map.of("content", "redacted"), List.of(), true);
        }
    }

    private static final class CoreDumpHandler extends BaseHandler {
        @Override
        public EspPartitionHandlerKind kind() {
            return EspPartitionHandlerKind.COREDUMP;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return !entry.encrypted() && entry.type() == 1 && entry.subtype() == 3;
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            EspPartitionInspection erased = erased(partition, cancellation, true);
            if (erased != null) {
                return erased;
            }
            byte[] payload = partition.payload();
            if (payload.length < 12) {
                return invalid(partition, kind(), "Core dump header is truncated");
            }
            long dataLength = unsignedInt(payload, 0);
            long version = unsignedInt(payload, 4);
            long chipRevision = unsignedInt(payload, 8);
            if (dataLength < 12 || dataLength > payload.length) {
                return invalid(partition, kind(), "Core dump length is invalid");
            }
            Map<String, String> metadata = new LinkedHashMap<>();
            metadata.put("dataLength", Long.toString(dataLength));
            metadata.put("chipId", Long.toString(version >>> 16));
            metadata.put("formatMajor", Long.toString((version >>> 8) & 0xff));
            metadata.put("formatMinor", Long.toString(version & 0xff));
            metadata.put("chipRevision", Long.toString(chipRevision));
            metadata.put("elfPresent", Boolean.toString(hasElf(payload,
                Math.toIntExact(Math.min(dataLength, 64)))));
            return result(partition, EspPartitionDisposition.VALIDATED_METADATA,
                metadata, List.of(), true);
        }
    }

    private static final class FatHandler extends BaseHandler {
        @Override
        public EspPartitionHandlerKind kind() {
            return EspPartitionHandlerKind.FAT;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return !entry.encrypted() && entry.type() == 1 && entry.subtype() == 0x81;
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            EspPartitionInspection erased = erased(partition, cancellation, false);
            if (erased != null) {
                return erased;
            }
            byte[] payload = partition.payload();
            boolean rawSignature = payload.length >= 512
                && Byte.toUnsignedInt(payload[510]) == 0x55
                && Byte.toUnsignedInt(payload[511]) == 0xaa;
            return result(partition, rawSignature
                    ? EspPartitionDisposition.VALIDATED_METADATA
                    : EspPartitionDisposition.CONFIGURATION_REQUIRED,
                Map.of("rawBootSignature", Boolean.toString(rawSignature)),
                List.of(), false);
        }
    }

    private static final class FileSystemHandler extends SimpleHandler {
        private FileSystemHandler(EspPartitionHandlerKind kind, int subtype) {
            super(kind, 1, subtype,
                EspPartitionDisposition.CONFIGURATION_REQUIRED, false);
        }
    }

    private static final class InactiveApplicationHandler extends BaseHandler {
        @Override
        public EspPartitionHandlerKind kind() {
            return EspPartitionHandlerKind.INACTIVE_APPLICATION;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return !entry.encrypted() && entry.type() == 0;
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            EspPartitionInspection erased = erased(partition, cancellation, false);
            return erased != null ? erased : invalid(partition, kind(),
                "Non-erased application bytes were not a validated image");
        }
    }

    private static final class CustomHandler extends BaseHandler {
        @Override
        public EspPartitionHandlerKind kind() {
            return EspPartitionHandlerKind.CUSTOM;
        }

        @Override
        public boolean supports(EspPartitionEntry entry) {
            return true;
        }

        @Override
        public EspPartitionInspection inspect(EspExtractedPartition partition,
                ParserLimits limits, CancellationToken cancellation)
                throws DiagnosticException {
            EspPartitionInspection erased = erased(partition, cancellation, false);
            return erased != null ? erased : result(partition,
                EspPartitionDisposition.OPAQUE, Map.of(), List.of(), false);
        }
    }

    private static EspPartitionInspection invalid(EspExtractedPartition partition,
            EspPartitionHandlerKind kind, String message) {
        return new EspPartitionInspection(partition.entry(), kind,
            EspPartitionDisposition.INVALID, partition.sourceRange(), Map.of(),
            List.of(warning(message, partition.sourceRange())), false);
    }

    private static Diagnostic warning(String message, SourceRange range) {
        return new Diagnostic(DiagnosticCode.ESP_PARTITION_HANDLER_INVALID,
            DiagnosticSeverity.WARNING, message, Optional.of(range));
    }

    private static boolean isErased(byte[] payload, CancellationToken cancellation)
            throws DiagnosticException {
        for (int index = 0; index < payload.length; index++) {
            if ((index & 0xfff) == 0) {
                cancellation.throwIfCancellationRequested();
            }
            if (Byte.toUnsignedInt(payload[index]) != 0xff) {
                return false;
            }
        }
        return true;
    }

    private static long unsignedInt(byte[] input, int offset) {
        return Integer.toUnsignedLong(Byte.toUnsignedInt(input[offset])
            | Byte.toUnsignedInt(input[offset + 1]) << 8
            | Byte.toUnsignedInt(input[offset + 2]) << 16
            | Byte.toUnsignedInt(input[offset + 3]) << 24);
    }

    private static boolean hasElf(byte[] payload, int limit) {
        for (int offset = 0; offset + 3 < limit; offset++) {
            if (Byte.toUnsignedInt(payload[offset]) == 0x7f
                && payload[offset + 1] == 'E' && payload[offset + 2] == 'L'
                && payload[offset + 3] == 'F') {
                return true;
            }
        }
        return false;
    }
}
