package io.github.rezabakhshi.embedra.targets.nordic.softdevice;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure analyzer for discovering Nordic SoftDevice protocol stacks, MBR, and vector relocation offsets.
 */
public final class NordicSoftDeviceDetector {

    public static final long MBR_BASE = 0x00000000L;

    public static final long MBR_SIZE = 0x00001000L; // 4 KiB

    public static final long SOFTDEVICE_BASE = 0x00001000L;

    public static final long S112_V7_APP_OFFSET = 0x00019000L;

    public static final long S132_V7_APP_OFFSET = 0x00026000L;

    public static final long S140_V7_APP_OFFSET = 0x00027000L;

    public static final long S110_V8_APP_OFFSET = 0x00018000L;

    public static final long S130_V2_APP_OFFSET = 0x0001C000L;

    private NordicSoftDeviceDetector() {
    }

    public static boolean hasMbr(byte[] flashBytes, long baseAddress) {
        if (flashBytes == null || flashBytes.length < 64 || baseAddress != MBR_BASE) {
            return false;
        }
        ByteBuffer buf = ByteBuffer.wrap(flashBytes).order(ByteOrder.LITTLE_ENDIAN);
        int initialSp = buf.getInt(0);
        int resetVector = buf.getInt(4);

        // MBR initial SP must point to SRAM and reset vector must be in MBR region (< 0x1000)
        boolean validSp = (initialSp & 0xFFF00000) == 0x20000000;
        boolean validReset = (resetVector & ~1) >= 0 && (resetVector & ~1) < MBR_SIZE;
        boolean thumbBit = (resetVector & 1) != 0;

        return validSp && validReset && thumbBit;
    }

    public static Optional<NordicSoftDeviceInfo> detect(byte[] flashBytes, long baseAddress) {
        Objects.requireNonNull(flashBytes, "flashBytes must not be null");
        if (flashBytes.length < (SOFTDEVICE_BASE + 64)) {
            return Optional.empty();
        }

        boolean mbrPresent = hasMbr(flashBytes, baseAddress);
        int sdOffset = (int) (SOFTDEVICE_BASE - baseAddress);
        if (sdOffset < 0 || sdOffset + 64 > flashBytes.length) {
            return Optional.empty();
        }

        ByteBuffer buf = ByteBuffer.wrap(flashBytes).order(ByteOrder.LITTLE_ENDIAN);

        int sdSp = buf.getInt(sdOffset);
        int sdReset = buf.getInt(sdOffset + 4);
        int sdSvc = buf.getInt(sdOffset + 11 * 4); // SVC handler vector is slot 11

        boolean validSdSp = (sdSp & 0xFFF00000) == 0x20000000;
        boolean validSdReset = (sdReset & ~1) >= SOFTDEVICE_BASE;
        boolean thumbBit = (sdReset & 1) != 0;

        if (!validSdSp || !validSdReset || !thumbBit) {
            return Optional.empty();
        }

        // Fingerprint SoftDevice type by inspecting application offset or known ranges
        NordicSoftDeviceType type = NordicSoftDeviceType.UNKNOWN;
        long appOffset = 0L;
        String version = "v7.x";
        int fwid = 0;

        // Check for application vector table at S140 offset (0x00027000)
        if (hasValidApplicationVector(flashBytes, baseAddress, S140_V7_APP_OFFSET)) {
            type = NordicSoftDeviceType.S140;
            appOffset = S140_V7_APP_OFFSET;
            version = "v7.2.0";
            fwid = 0x0100;
        } else if (hasValidApplicationVector(flashBytes, baseAddress, S132_V7_APP_OFFSET)) {
            type = NordicSoftDeviceType.S132;
            appOffset = S132_V7_APP_OFFSET;
            version = "v7.2.0";
            fwid = 0x00EB;
        } else if (hasValidApplicationVector(flashBytes, baseAddress, S112_V7_APP_OFFSET)) {
            type = NordicSoftDeviceType.S112;
            appOffset = S112_V7_APP_OFFSET;
            version = "v7.2.0";
            fwid = 0x00B7;
        } else if (hasValidApplicationVector(flashBytes, baseAddress, S130_V2_APP_OFFSET)) {
            type = NordicSoftDeviceType.S130;
            appOffset = S130_V2_APP_OFFSET;
            version = "v2.0.1";
            fwid = 0x0080;
        } else if (hasValidApplicationVector(flashBytes, baseAddress, S110_V8_APP_OFFSET)) {
            type = NordicSoftDeviceType.S110;
            appOffset = S110_V8_APP_OFFSET;
            version = "v8.0.0";
            fwid = 0x0064;
        } else {
            // Heuristic detection if full application is not appended
            type = NordicSoftDeviceType.S132;
            appOffset = S132_V7_APP_OFFSET;
            version = "v7.x";
        }

        long sdSize = appOffset - SOFTDEVICE_BASE;

        return Optional.of(new NordicSoftDeviceInfo(
            type,
            version,
            fwid,
            SOFTDEVICE_BASE,
            sdSize,
            appOffset,
            mbrPresent,
            mbrPresent ? MBR_SIZE : 0L,
            sdSvc & 0xFFFFFFFFL
        ));
    }

    public static boolean hasValidApplicationVector(byte[] flashBytes, long baseAddress, long targetOffset) {
        int index = (int) (targetOffset - baseAddress);
        if (index < 0 || index + 8 > flashBytes.length) {
            return false;
        }

        ByteBuffer buf = ByteBuffer.wrap(flashBytes).order(ByteOrder.LITTLE_ENDIAN);
        int initialSp = buf.getInt(index);
        int resetVector = buf.getInt(index + 4);

        boolean validSp = (initialSp & 0xFFF00000) == 0x20000000;
        boolean validReset = (resetVector & ~1) >= targetOffset;
        boolean thumbBit = (resetVector & 1) != 0;

        return validSp && validReset && thumbBit;
    }

    public static long relocateApplicationVector(byte[] flashBytes, long baseAddress, long appOffset)
            throws DiagnosticException {
        if (!hasValidApplicationVector(flashBytes, baseAddress, appOffset)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_VECTOR_TABLE_INVALID,
                "No valid relocated Cortex-M application vector table at offset 0x" + Long.toHexString(appOffset),
                null));
        }

        int index = (int) (appOffset - baseAddress);
        ByteBuffer buf = ByteBuffer.wrap(flashBytes).order(ByteOrder.LITTLE_ENDIAN);
        int resetVector = buf.getInt(index + 4);
        return resetVector & ~1L; // Aligned entry point
    }

    public static Optional<Long> discoverBootloaderAddress(byte[] uicrBytes) {
        if (uicrBytes == null || uicrBytes.length < 0x18) {
            return Optional.empty();
        }
        // UICR BOOTLOADERADDR is at offset 0x14 (0x10001014)
        ByteBuffer buf = ByteBuffer.wrap(uicrBytes).order(ByteOrder.LITTLE_ENDIAN);
        long addr = buf.getInt(0x14) & 0xFFFFFFFFL;
        if (addr == 0xFFFFFFFFL || addr == 0L) {
            return Optional.empty();
        }
        return Optional.of(addr);
    }
}
