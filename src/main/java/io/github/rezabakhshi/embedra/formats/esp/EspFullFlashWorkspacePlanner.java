package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.HexFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.github.rezabakhshi.embedra.formats.esp.layout.Esp32S3FlashLayoutProvider;
import io.github.rezabakhshi.embedra.formats.esp.layout.EspFlashLayoutProvider;
import io.github.rezabakhshi.embedra.formats.esp.layout.EspFlashLayoutRegistry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.HexFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Validates and extracts an ESP full flash image into independent workspace objects using a layout provider. */
public final class EspFullFlashWorkspacePlanner {
    private static final int SEGMENT_HEADER_LENGTH = 8;

    private static final int DIGEST_LENGTH = 32;

    private static final int APP_TYPE = 0;

    private static final int FACTORY_SUBTYPE = 0;

    private static final int OTA_MIN_SUBTYPE = 0x10;

    private static final int OTA_MAX_SUBTYPE = 0x1f;

    private EspFullFlashWorkspacePlanner() {
    }

    public static EspFullFlashWorkspace plan(byte[] flash, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        return plan(flash, resolveProvider(flash), limits, cancellation);
    }

    public static EspFullFlashWorkspace plan(byte[] flash, EspFlashLayoutProvider provider,
            ParserLimits limits, CancellationToken cancellation) throws DiagnosticException {
        Objects.requireNonNull(flash, "flash");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        EspPartitionTable table = EspPartitionTableDiscovery.discover(flash,
            provider.defaultPartitionTableOffset(),
            provider.profile().minPartitionTableOffset(),
            provider.profile().maxPartitionTableOffset(),
            limits, cancellation);
        List<EspExtractedExecutable> executables = new ArrayList<>();
        List<EspExtractedPartition> dataPartitions = new ArrayList<>();
        long extractedBytes = 0;

        long bootloaderOffset = provider.bootloaderOffset();
        long availableBootloader = table.tableFlashRange().offset() - bootloaderOffset;
        EspExtractedExecutable bootloader = extractExecutable(flash, bootloaderOffset,
            availableBootloader, "bootloader",
            EspExecutableRole.BOOTLOADER, Optional.empty(), provider, limits, cancellation);
        extractedBytes = accountExtraction(extractedBytes,
            bootloader.flashRange().length(), limits, bootloader.sourceRange());
        executables.add(bootloader);

        for (EspPartitionEntry entry : table.entries()) {
            cancellation.throwIfCancellationRequested();
            if (executables.size() + dataPartitions.size() >= limits.maxObjects()) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "ESP workspace object count exceeds the configured limit",
                    entry.sourceRange());
            }
            if (entry.type() == APP_TYPE && !entry.encrypted()) {
                SourceRange partitionRange = sourceRange(entry.flashRange());
                if (isErased(flash, partitionRange, cancellation)) {
                    byte[] payload = extract(flash, partitionRange, limits);
                    extractedBytes = accountExtraction(extractedBytes,
                        payload.length, limits, partitionRange);
                    dataPartitions.add(new EspExtractedPartition(entry,
                        EspPartitionPayloadKind.ERASED_APPLICATION_SLOT,
                        partitionRange, payload));
                }
                else {
                    EspExecutableRole role = executableRole(entry.subtype());
                    EspExtractedExecutable executable = extractExecutable(flash,
                        entry.flashRange().offset(), entry.flashRange().length(),
                        entry.label(), role, Optional.of(entry.label()), provider, limits,
                        cancellation);
                    extractedBytes = accountExtraction(extractedBytes,
                        executable.flashRange().length(), limits,
                        executable.sourceRange());
                    executables.add(executable);
                }
            }
            else {
                SourceRange range = sourceRange(entry.flashRange());
                byte[] payload = extract(flash, range, limits);
                extractedBytes = accountExtraction(extractedBytes, payload.length,
                    limits, range);
                dataPartitions.add(new EspExtractedPartition(entry,
                    payloadKind(entry), range, payload));
            }
        }
        List<String> populatedApplications = executables.stream()
            .map(EspExtractedExecutable::partitionLabel)
            .flatMap(Optional::stream).toList();
        EspPartitionAnalysis analysis = EspPartitionHandlerRegistry.defaults()
            .analyze(table, dataPartitions, populatedApplications, limits,
                cancellation);
        return new EspFullFlashWorkspace(table, executables, dataPartitions,
            ProgramStrategy.SEPARATE_PROGRAMS, sha256(flash), analysis);
    }

    private static EspFlashLayoutProvider resolveProvider(byte[] flash) {
        if (flash != null && flash.length >= EspImageDetector.HEADER_LENGTH) {
            // Check candidate offset 0x0000 first
            if (Byte.toUnsignedInt(flash[0]) == EspImageDetector.MAGIC) {
                int chipId = Byte.toUnsignedInt(flash[12]) | (Byte.toUnsignedInt(flash[13]) << 8);
                Optional<EspFlashLayoutProvider> match = EspFlashLayoutRegistry.defaults().findByChipId(chipId);
                if (match.isPresent()) {
                    return match.get();
                }
            }
            // Check candidate offset 0x1000 (ESP32 original bootloader start)
            if (flash.length >= 0x1000 + EspImageDetector.HEADER_LENGTH
                    && Byte.toUnsignedInt(flash[0x1000]) == EspImageDetector.MAGIC) {
                int chipId = Byte.toUnsignedInt(flash[0x1000 + 12]) | (Byte.toUnsignedInt(flash[0x1000 + 13]) << 8);
                Optional<EspFlashLayoutProvider> match = EspFlashLayoutRegistry.defaults().findByChipId(chipId);
                if (match.isPresent()) {
                    return match.get();
                }
            }
        }
        return Esp32S3FlashLayoutProvider.INSTANCE;
    }

    private static EspExtractedExecutable extractExecutable(byte[] flash, long offset,
            long available, String name, EspExecutableRole role,
            Optional<String> partitionLabel, EspFlashLayoutProvider provider, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        SourceRange range = encodedImageRange(flash, offset, available, cancellation);
        byte[] bytes = extract(flash, range, limits);
        try {
            EspImage image = EspImageParser.parseForChip(bytes, provider.chipId(),
                limits, cancellation);
            if (role == EspExecutableRole.BOOTLOADER) {
                provider.validateBootloader(image);
            }
            else {
                provider.validateApplication(image);
            }
            return new EspExtractedExecutable(name, role, partitionLabel,
                new EspFlashRange(range.offset(), range.length()), range, image, bytes);
        }
        catch (DiagnosticException failure) {
            throw translate(failure, offset);
        }
    }

    private static SourceRange encodedImageRange(byte[] flash, long offset,
            long available, CancellationToken cancellation) throws DiagnosticException {
        if (offset < 0 || available < EspImageDetector.HEADER_LENGTH
            || offset > flash.length || available > flash.length - offset
            || offset > Integer.MAX_VALUE) {
            throw failure(DiagnosticCode.ESP_HEADER_TRUNCATED,
                "Embedded ESP image header is outside its validated container",
                new SourceRange(Math.min(Math.max(offset, 0), flash.length), 0));
        }
        int start = (int) offset;
        int segmentCount = Byte.toUnsignedInt(flash[start + 1]);
        int digestFlag = Byte.toUnsignedInt(flash[start + 23]);
        if (Byte.toUnsignedInt(flash[start]) != EspImageDetector.MAGIC
            || segmentCount == 0 || segmentCount > EspImageDetector.MAX_SEGMENTS
            || digestFlag > 1) {
            throw failure(DiagnosticCode.ESP_HEADER_INVALID,
                "Embedded ESP image header is invalid",
                new SourceRange(offset, EspImageDetector.HEADER_LENGTH));
        }
        long position = EspImageDetector.HEADER_LENGTH;
        for (int index = 0; index < segmentCount; index++) {
            cancellation.throwIfCancellationRequested();
            if (position > available - SEGMENT_HEADER_LENGTH) {
                throw failure(DiagnosticCode.ESP_SEGMENT_HEADER_TRUNCATED,
                    "Embedded ESP segment header exceeds its container",
                    new SourceRange(offset + position,
                        Math.max(0, available - position)));
            }
            long length = unsignedInt(flash,
                Math.toIntExact(offset + position + 4));
            position = checkedAdd(position, SEGMENT_HEADER_LENGTH, offset);
            if (length > available - position) {
                throw failure(DiagnosticCode.ESP_SEGMENT_TRUNCATED,
                    "Embedded ESP segment exceeds its container",
                    new SourceRange(offset + position,
                        Math.max(0, available - position)));
            }
            position = checkedAdd(position, length, offset);
        }
        long paddingLength = 15 - (position % 16);
        long footerLength = paddingLength + 1 + (digestFlag == 1 ? DIGEST_LENGTH : 0);
        long total = checkedAdd(position, footerLength, offset);
        if (total > available) {
            throw failure(DiagnosticCode.ESP_SEGMENT_TRUNCATED,
                "Embedded ESP image footer exceeds its container",
                new SourceRange(offset + position, Math.max(0, available - position)));
        }
        return new SourceRange(offset, total);
    }

    private static long checkedAdd(long left, long right, long sourceOffset)
            throws DiagnosticException {
        try {
            return Math.addExact(left, right);
        }
        catch (ArithmeticException failure) {
            throw failure(DiagnosticCode.ESP_SEGMENT_LENGTH_INVALID,
                "Embedded ESP image length overflows",
                new SourceRange(sourceOffset, 0));
        }
    }

    private static byte[] extract(byte[] flash, SourceRange range,
            ParserLimits limits) throws DiagnosticException {
        if (range.length() > limits.maxAllocationBytes()
            || range.length() > Integer.MAX_VALUE) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP extracted object exceeds the configured allocation limit", range);
        }
        int start = Math.toIntExact(range.offset());
        return Arrays.copyOfRange(flash, start,
            Math.toIntExact(range.endExclusive()));
    }

    private static long accountExtraction(long current, long added,
            ParserLimits limits, SourceRange range) throws DiagnosticException {
        long total;
        try {
            total = Math.addExact(current, added);
        }
        catch (ArithmeticException failure) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP extracted-byte count overflows", range);
        }
        if (total > limits.maxExtractedBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP workspace exceeds the configured extracted-byte limit", range);
        }
        return total;
    }

    private static EspExecutableRole executableRole(int subtype) {
        if (subtype == FACTORY_SUBTYPE) {
            return EspExecutableRole.FACTORY;
        }
        if (subtype >= OTA_MIN_SUBTYPE && subtype <= OTA_MAX_SUBTYPE) {
            return EspExecutableRole.OTA;
        }
        return EspExecutableRole.APPLICATION;
    }

    private static EspPartitionPayloadKind payloadKind(EspPartitionEntry entry) {
        if (entry.encrypted()) {
            return EspPartitionPayloadKind.ENCRYPTED_OPAQUE;
        }
        return entry.type() == 1 ? EspPartitionPayloadKind.DATA
            : EspPartitionPayloadKind.CUSTOM;
    }

    private static SourceRange sourceRange(EspFlashRange range) {
        return new SourceRange(range.offset(), range.length());
    }

    private static boolean isErased(byte[] flash, SourceRange range,
            CancellationToken cancellation) throws DiagnosticException {
        int start = Math.toIntExact(range.offset());
        int end = Math.toIntExact(range.endExclusive());
        for (int index = start; index < end; index++) {
            if (((index - start) & 0xfff) == 0) {
                cancellation.throwIfCancellationRequested();
            }
            if (Byte.toUnsignedInt(flash[index]) != 0xff) {
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

    private static DiagnosticException translate(DiagnosticException failure,
            long baseOffset) {
        Diagnostic diagnostic = failure.diagnostic();
        SourceRange translated = diagnostic.sourceRange()
            .map(range -> new SourceRange(baseOffset + range.offset(), range.length()))
            .orElse(null);
        return new DiagnosticException(new Diagnostic(diagnostic.code(),
            diagnostic.severity(), diagnostic.message(), Optional.ofNullable(translated)));
    }

    private static DiagnosticException failure(DiagnosticCode code, String message,
            SourceRange range) {
        return new DiagnosticException(Diagnostic.error(code, message, range));
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(input));
        }
        catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("Required SHA-256 implementation unavailable",
                failure);
        }
    }
}
