package io.github.rezabakhshi.embedra.targets.rp.boot;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Variant-aware parser for RP2040 and RP2350/RP2354 boot metadata from raw XIP and internal flash.
 */
public final class RpBootMetadataParser {

    public static final long FLASH_BASE = 0x10000000L;

    public static final long IMAGE_DEF_START_MAGIC = 0xFFFFDED3L;

    public static final long IMAGE_DEF_END_MAGIC = 0xAB123579L;

    private RpBootMetadataParser() {
    }

    /**
     * Parses boot metadata from reconstructed UF2 segments, using the segment at flash base.
     */
    public static RpBootMetadata parse(List<RpUf2Segment> segments, String targetPart)
            throws DiagnosticException {
        Objects.requireNonNull(segments, "segments must not be null");
        if (segments.isEmpty()) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID, "No segments available for boot metadata parsing");
        }

        RpUf2Segment baseSegment = segments.stream()
                .filter(s -> s.targetAddress() == FLASH_BASE)
                .findFirst()
                .orElse(segments.get(0));

        return parse(baseSegment.data(), baseSegment.targetAddress(), targetPart);
    }

    /**
     * Variant-aware parse of raw flash bytes with target part guidance or auto-detection.
     */
    public static RpBootMetadata parse(byte[] data, long baseAddress, String targetPart)
            throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        if (data.length == 0) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID, "Empty flash data");
        }

        String partUpper = targetPart != null ? targetPart.trim().toUpperCase(Locale.ROOT) : "";

        if (partUpper.contains("RP2040")) {
            return parseRp2040(data, baseAddress);
        } else if (partUpper.contains("RP2354")) {
            return parseRp2350(data, baseAddress, true);
        } else if (partUpper.contains("RP2350")) {
            return parseRp2350(data, baseAddress, false);
        }

        // Auto-detect based on binary contents
        if (findImageDefOffset(data) >= 0) {
            boolean isStacked = partUpper.contains("2354");
            return parseRp2350(data, baseAddress, isStacked);
        }
        return parseRp2040(data, baseAddress);
    }

    /**
     * Parses RP2040 boot2 stage and vector table at baseAddress with strict CRC and vector validation.
     */
    public static Rp2040BootMetadata parseRp2040Strict(byte[] data, long baseAddress)
            throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        if (data.length < Rp2040Boot2Checksum.BOOT2_SIZE) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "RP2040 flash data (" + data.length + " bytes) is smaller than 256-byte boot2 stage");
        }

        long calculatedCrc = Rp2040Boot2Checksum.calculate(data, 0, Rp2040Boot2Checksum.CHECKSUMMED_SIZE);
        long storedCrc = readU32Le(data, Rp2040Boot2Checksum.CHECKSUMMED_SIZE);
        boolean isCrcValid = (calculatedCrc == storedCrc);
        boolean isPlaceholder = (storedCrc == Rp2040Boot2Checksum.PLACEHOLDER_CRC2);
        if (!isCrcValid && !isPlaceholder) {
            throw failure(DiagnosticCode.RP_BOOT_CRC_MISMATCH,
                    "RP2040 boot2 CRC mismatch: calculated 0x" + Long.toHexString(calculatedCrc)
                            + ", stored 0x" + Long.toHexString(storedCrc));
        }

        if (data.length < 264) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "RP2040 flash data (" + data.length + " bytes) truncated before vector table");
        }

        long initialSp = readU32Le(data, 256);
        long resetVector = readU32Le(data, 260);

        if (initialSp < 0x20000000L || initialSp > 0x20042000L) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "RP2040 initial SP out of valid SRAM range: 0x" + Long.toHexString(initialSp));
        }
        if ((resetVector & 1) != 1 || resetVector < FLASH_BASE || resetVector >= 0x14000000L) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "RP2040 reset vector invalid or outside flash range: 0x" + Long.toHexString(resetVector));
        }

        return new Rp2040BootMetadata(
                baseAddress,
                storedCrc,
                calculatedCrc,
                isCrcValid,
                isPlaceholder,
                initialSp,
                resetVector,
                resetVector,
                true);
    }

    /**
     * Parses RP2040 boot2 stage and vector table at baseAddress.
     */
    public static Rp2040BootMetadata parseRp2040(byte[] data, long baseAddress)
            throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        if (data.length < Rp2040Boot2Checksum.BOOT2_SIZE) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "RP2040 flash data (" + data.length + " bytes) is smaller than 256-byte boot2 stage");
        }

        long calculatedCrc = Rp2040Boot2Checksum.calculate(data, 0, Rp2040Boot2Checksum.CHECKSUMMED_SIZE);
        long storedCrc = readU32Le(data, Rp2040Boot2Checksum.CHECKSUMMED_SIZE);
        boolean isCrcValid = (calculatedCrc == storedCrc);
        boolean isPlaceholder = (storedCrc == Rp2040Boot2Checksum.PLACEHOLDER_CRC2);

        long initialSp = 0;
        long resetVector = 0;
        long entryPoint = 0;
        boolean vectorTableValid = false;

        // Check if vector table at 0x100 is present
        if (data.length >= 264) {
            initialSp = readU32Le(data, 256);
            resetVector = readU32Le(data, 260);
            entryPoint = resetVector;

            // In Thumb mode, bit 0 must be 1 and address must be in flash window
            boolean validSp = (initialSp >= 0x20000000L && initialSp <= 0x20082000L);
            boolean validReset = ((resetVector & 1) == 1 && resetVector >= FLASH_BASE && resetVector < 0x14000000L);
            vectorTableValid = validSp && validReset;
        }

        return new Rp2040BootMetadata(
                baseAddress,
                storedCrc,
                calculatedCrc,
                isCrcValid,
                isPlaceholder,
                initialSp,
                resetVector,
                entryPoint,
                vectorTableValid);
    }

    /**
     * Parses RP2350 / RP2354 IMAGE_DEF block and architecture/security metadata.
     */
    public static Rp2350BootMetadata parseRp2350(byte[] data, long baseAddress, boolean isStackedFlash)
            throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        int offset = findImageDefOffset(data);
        if (offset < 0) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "RP2350 IMAGE_DEF marker (0xffffded3) not found within search window");
        }

        int pos = offset + 4;
        List<Rp2350BlockItem> items = new ArrayList<>();
        Rp2350Architecture architecture = Rp2350Architecture.ARM;
        Rp2350SecurityDomain securityDomain = Rp2350SecurityDomain.SECURE;
        OptionalLong vectorTableAddress = OptionalLong.empty();
        long entryPoint = 0;
        OptionalLong initialSp = OptionalLong.empty();
        boolean endMarkerFound = false;

        while (pos + 4 <= data.length) {
            long word = readU32Le(data, pos);
            pos += 4;

            if (word == IMAGE_DEF_END_MAGIC) {
                endMarkerFound = true;
                break;
            }

            int tag = (int) (word & 0xFF);
            if (tag == Rp2350BlockItem.TAG_IMAGE_TYPE) {
                int typeVal = (int) ((word >> 8) & 0xFF);
                if (typeVal == 2) {
                    architecture = Rp2350Architecture.RISCV;
                } else if (typeVal == 3) {
                    architecture = Rp2350Architecture.ARM;
                    securityDomain = Rp2350SecurityDomain.NON_SECURE;
                } else {
                    architecture = Rp2350Architecture.ARM;
                    securityDomain = Rp2350SecurityDomain.SECURE;
                }
                items.add(new Rp2350BlockItem(tag, word, new long[0]));
            } else if (tag == Rp2350BlockItem.TAG_VECTOR_TABLE_OR_ENTRY) {
                if (pos + 4 > data.length) {
                    throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                            "Truncated pointer payload for IMAGE_DEF item 0x43");
                }
                long pointer = readU32Le(data, pos);
                pos += 4;
                if (pointer < FLASH_BASE || pointer >= 0x20082000L) {
                    throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                            "RP2350 vector table/entry pointer out of range: 0x" + Long.toHexString(pointer));
                }
                items.add(new Rp2350BlockItem(tag, word, new long[]{pointer}));

                if (architecture == Rp2350Architecture.ARM) {
                    vectorTableAddress = OptionalLong.of(pointer);
                    // Extract initial SP and Reset Handler from vector table if data contains it
                    int vtOffset = (int) (pointer - baseAddress);
                    if (vtOffset >= 0 && vtOffset + 8 <= data.length) {
                        initialSp = OptionalLong.of(readU32Le(data, vtOffset));
                        entryPoint = readU32Le(data, vtOffset + 4);
                    }
                } else {
                    // RISC-V direct entry pointer
                    entryPoint = pointer;
                }
            } else if (tag == Rp2350BlockItem.TAG_LAST) {
                items.add(new Rp2350BlockItem(tag, word, new long[0]));
                break;
            } else if (word == 0) {
                // Zero padding
                break;
            } else if (tag == Rp2350BlockItem.TAG_BLOCK_SIZE
                    || tag == 0x45 || tag == 0x46 || tag == 0x47) {
                items.add(new Rp2350BlockItem(tag, word, new long[0]));
            } else {
                throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                        "Unknown RP2350 IMAGE_DEF item tag: 0x" + Integer.toHexString(tag));
            }
        }

        if (!endMarkerFound) {
            throw failure(DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "RP2350 IMAGE_DEF block incomplete or missing end marker");
        }

        return new Rp2350BootMetadata(
                baseAddress,
                offset,
                true,
                architecture,
                securityDomain,
                vectorTableAddress,
                entryPoint,
                initialSp,
                isStackedFlash,
                items);
    }

    private static int findImageDefOffset(byte[] data) {
        int maxScan = Math.min(data.length - 4, 4096);
        for (int i = 0; i <= maxScan; i += 4) {
            if (readU32Le(data, i) == IMAGE_DEF_START_MAGIC) {
                return i;
            }
        }
        return -1;
    }

    private static long readU32Le(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF))
                | ((long) (data[offset + 1] & 0xFF) << 8)
                | ((long) (data[offset + 2] & 0xFF) << 16)
                | ((long) (data[offset + 3] & 0xFF) << 24);
    }

    private static DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, null));
    }
}
