package io.github.rezabakhshi.embedra.core.stm32.input;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;

class Stm32DfuParserTest {
    private static final int FIRST_TARGET = 11;

    private static final int FIRST_ELEMENT = FIRST_TARGET + 274;

    @Test
    void preservesTwoTargetsThreeAddressedElementsAndSuffix() throws Exception {
        byte[] firmware = f103Bin();
        byte[] input = dfu(List.of(
            new TargetData(0, "Internal Flash", List.of(
                new ElementData(0x08000000L, Arrays.copyOfRange(firmware, 0, 16)),
                new ElementData(0x08001000L, new byte[] {1, 2, 3, 4}))),
            new TargetData(1, "Option Bytes", List.of(
                new ElementData(0x1fff7800L, new byte[] {5, 6, 7, 8})))));

        Stm32DfuImage image = parse(input);

        assertEquals(2, image.targets().size());
        assertEquals("Internal Flash", image.targets().getFirst().name());
        assertEquals(0, image.targets().getFirst().alternateSetting());
        assertEquals(1, image.targets().get(1).alternateSetting());
        assertEquals(0x08000000L, image.targets().getFirst().elements().getFirst().encodedAddress());
        assertEquals(0x08001000L, image.targets().getFirst().elements().get(1).encodedAddress());
        assertEquals(0x1fff7800L, image.targets().get(1).elements().getFirst().encodedAddress());
        Stm32DfuImage.Element first = image.targets().getFirst().elements().getFirst();
        assertArrayEquals(Arrays.copyOfRange(firmware, 0, 16), Arrays.copyOfRange(input,
            (int) first.dataRange().offset(), (int) first.dataRange().endExclusive()));
        assertEquals(0x0483, image.suffix().vendorId());
        assertEquals(0xdf11, image.suffix().productId());
        assertEquals(0x011a, image.suffix().dfuVersion());
        assertFalse(image.targets().getFirst().bodyRange().contains(
            image.targets().get(1).bodyRange()));
        assertThrows(UnsupportedOperationException.class, () -> image.targets().clear());
        assertThrows(UnsupportedOperationException.class,
            () -> image.targets().getFirst().elements().clear());
    }

    @Test
    void rejectsInvalidPrefixAndSuffix() throws Exception {
        byte[] good = sample();
        assertEquals(0x35a8bbd4L, parse(good).suffix().storedCrc());
        reject(good, 0, 'X', DiagnosticCode.STM_DFU_INVALID);
        reject(good, 5, 2, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, 6, good.length - 16, DiagnosticCode.STM_DFU_INVALID);
        reject(good, 10, 0, DiagnosticCode.STM_DFU_INVALID);
        reject(good, 10, 2, DiagnosticCode.STM_DFU_INVALID);
        reject(good, good.length - 8, 0, DiagnosticCode.STM_DFU_INVALID);
        reject(good, good.length - 7, 'X', DiagnosticCode.STM_DFU_INVALID);
        reject(good, good.length - 10, 0, DiagnosticCode.STM_DFU_INVALID);
        reject(good, good.length - 5, 15, DiagnosticCode.STM_DFU_INVALID);
        byte[] badCrc = good.clone();
        badCrc[293] ^= 1;
        assertEquals(DiagnosticCode.STM_DFU_CRC_MISMATCH,
            assertThrows(DiagnosticException.class, () -> parse(badCrc)).diagnostic().code());
        assertEquals(DiagnosticCode.STM_DFU_INVALID,
            assertThrows(DiagnosticException.class,
                () -> parse(Arrays.copyOf(good, 20))).diagnostic().code());

        byte[] twoTargets = good.clone();
        twoTargets[10] = 2;
        refreshCrc(twoTargets);
        ParserLimits oneObj = new ParserLimits(100_000, 100_000, 100_000, 1, 10, Duration.ofSeconds(5));
        assertEquals(DiagnosticCode.STM_DFU_INVALID, assertThrows(DiagnosticException.class, () ->
            Stm32DfuParser.parse(twoTargets, oneObj, CancellationToken.none())).diagnostic().code());

        ParserLimits fastTimeout = new ParserLimits(100_000, 100_000, 100_000, 100, 10, Duration.ofNanos(1));
        try {
            Thread.sleep(2);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, assertThrows(DiagnosticException.class, () ->
            Stm32DfuParser.parse(good, fastTimeout, CancellationToken.none())).diagnostic().code());
    }

    @Test
    void rejectsTargetAndElementStructuralErrors() throws Exception {
        byte[] good = sample();
        reject(good, FIRST_TARGET, 'X', DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_TARGET + 7, 2, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_TARGET + 266, 0, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_TARGET + 266, 1000, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_TARGET + 270, 0, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_TARGET + 270, 2, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_ELEMENT, 0xfffffffEL, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_ELEMENT + 4, 0, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_ELEMENT + 4, 0xfffffffFL, DiagnosticCode.STM_DFU_INVALID);
        rejectU32(good, FIRST_ELEMENT + 4, 1000, DiagnosticCode.STM_DFU_INVALID);
        byte[] overlap = dfu(List.of(new TargetData(0, "flash", List.of(
            new ElementData(0x08000000L, new byte[] {1, 2, 3, 4}),
            new ElementData(0x08000002L, new byte[] {5, 6, 7, 8})))));
        assertEquals(DiagnosticCode.STM_DFU_INVALID,
            assertThrows(DiagnosticException.class, () -> parse(overlap)).diagnostic().code());
        byte[] duplicateAlt = dfu(List.of(
            new TargetData(0, "one", List.of(new ElementData(0x08000000L, new byte[] {1}))),
            new TargetData(0, "two", List.of(new ElementData(0x08001000L, new byte[] {2})))));
        assertEquals(DiagnosticCode.STM_DFU_INVALID,
            assertThrows(DiagnosticException.class, () -> parse(duplicateAlt))
                .diagnostic().code());
        byte[] extraBodyByte = withBodyPadding(good);
        assertEquals(DiagnosticCode.STM_DFU_INVALID,
            assertThrows(DiagnosticException.class, () -> parse(extraBodyByte))
                .diagnostic().code());
        writeU32(extraBodyByte, FIRST_TARGET + 266, 13);
        refreshCrc(extraBodyByte);
        assertEquals(DiagnosticCode.STM_DFU_INVALID,
            assertThrows(DiagnosticException.class, () -> parse(extraBodyByte))
                .diagnostic().code());
    }

    @Test
    void acceptsUnnamedAndMaximumLengthTargetNames() throws Exception {
        byte[] unnamed = sample();
        writeU32(unnamed, FIRST_TARGET + 7, 0);
        refreshCrc(unnamed);
        assertEquals("", parse(unnamed).targets().getFirst().name());

        String fullName = "A".repeat(255);
        byte[] full = dfu(List.of(new TargetData(0, fullName,
            List.of(new ElementData(0x08000000L, new byte[] {1})))));
        assertEquals(fullName, parse(full).targets().getFirst().name());
    }

    @Test
    void verifiesCrcAcrossMultipleChunksWithoutCopyingPayload() throws Exception {
        byte[] payload = new byte[8192];
        for (int index = 0; index < payload.length; index++) {
            payload[index] = (byte) index;
        }
        byte[] input = dfu(List.of(new TargetData(0, "large",
            List.of(new ElementData(0x08000000L, payload)))));
        Stm32DfuImage.Element element = parse(input).targets().getFirst().elements().getFirst();
        assertEquals(payload.length, element.dataRange().length());
        input[(int) element.dataRange().offset() + 4096] ^= 1;
        assertEquals(DiagnosticCode.STM_DFU_CRC_MISMATCH,
            assertThrows(DiagnosticException.class, () -> parse(input)).diagnostic().code());
    }

    @Test
    void enforcesInputObjectPayloadAndCancellationLimits() throws Exception {
        byte[] good = sample();
        ParserLimits inputLimit = limits(good.length - 1, 10, 10);
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED,
            assertThrows(DiagnosticException.class,
                () -> Stm32DfuParser.parse(good, inputLimit, CancellationToken.none()))
                    .diagnostic().code());
        ParserLimits objectLimit = limits(good.length, 1, 10);
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED,
            assertThrows(DiagnosticException.class,
                () -> Stm32DfuParser.parse(good, objectLimit, CancellationToken.none()))
                    .diagnostic().code());
        ParserLimits payloadLimit = limits(good.length, 10, 1);
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED,
            assertThrows(DiagnosticException.class,
                () -> Stm32DfuParser.parse(good, payloadLimit, CancellationToken.none()))
                    .diagnostic().code());
        assertEquals(DiagnosticCode.CANCELLED,
            assertThrows(DiagnosticException.class,
                () -> Stm32DfuParser.parse(good, ParserLimits.defaults(), () -> true))
                    .diagnostic().code());
    }

    private static byte[] sample() {
        return dfu(List.of(new TargetData(0, "flash",
            List.of(new ElementData(0x08000000L, new byte[] {1, 2, 3, 4})))));
    }

    private static Stm32DfuImage parse(byte[] bytes) throws DiagnosticException {
        return Stm32DfuParser.parse(bytes, ParserLimits.defaults(), CancellationToken.none());
    }

    private static ParserLimits limits(long input, long objects, long payload) {
        return new ParserLimits(input, 16, payload, objects, 4, Duration.ofSeconds(30));
    }

    private static void reject(byte[] good, int offset, int value, DiagnosticCode code) {
        byte[] changed = good.clone();
        changed[offset] = (byte) value;
        refreshCrc(changed);
        assertEquals(code, assertThrows(DiagnosticException.class,
            () -> parse(changed)).diagnostic().code());
    }

    private static void rejectU32(byte[] good, int offset, long value, DiagnosticCode code) {
        byte[] changed = good.clone();
        writeU32(changed, offset, value);
        refreshCrc(changed);
        assertEquals(code, assertThrows(DiagnosticException.class,
            () -> parse(changed)).diagnostic().code());
    }

    private static byte[] dfu(List<TargetData> targets) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (TargetData target : targets) {
            ByteArrayOutputStream elements = new ByteArrayOutputStream();
            for (ElementData element : target.elements()) {
                writeU32(elements, element.address());
                writeU32(elements, element.data().length);
                elements.writeBytes(element.data());
            }
            body.writeBytes("Target".getBytes(StandardCharsets.US_ASCII));
            body.write(target.alternateSetting());
            writeU32(body, 1);
            byte[] name = new byte[255];
            byte[] nameBytes = target.name().getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(nameBytes, 0, name, 0, nameBytes.length);
            body.writeBytes(name);
            writeU32(body, elements.size());
            writeU32(body, target.elements().size());
            body.writeBytes(elements.toByteArray());
        }
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        file.writeBytes("DfuSe".getBytes(StandardCharsets.US_ASCII));
        file.write(1);
        writeU32(file, 11 + body.size() + 16);
        file.write(targets.size());
        file.writeBytes(body.toByteArray());
        writeU16(file, 0xffff);
        writeU16(file, 0xdf11);
        writeU16(file, 0x0483);
        writeU16(file, 0x011a);
        file.writeBytes("UFD".getBytes(StandardCharsets.US_ASCII));
        file.write(16);
        writeU32(file, 0);
        byte[] result = file.toByteArray();
        refreshCrc(result);
        return result;
    }

    private static void refreshCrc(byte[] bytes) {
        CRC32 crc = new CRC32();
        crc.update(bytes, 0, bytes.length - 4);
        writeU32(bytes, bytes.length - 4, ~crc.getValue() & 0xffff_ffffL);
    }

    private static byte[] withBodyPadding(byte[] good) {
        byte[] padded = new byte[good.length + 1];
        int bodyEnd = good.length - 16;
        System.arraycopy(good, 0, padded, 0, bodyEnd);
        System.arraycopy(good, bodyEnd, padded, bodyEnd + 1, 16);
        writeU32(padded, 6, padded.length);
        refreshCrc(padded);
        return padded;
    }

    private static void writeU32(ByteArrayOutputStream output, long value) {
        for (int shift = 0; shift < 32; shift += 8) {
            output.write((int) (value >>> shift) & 0xff);
        }
    }

    private static void writeU16(ByteArrayOutputStream output, int value) {
        output.write(value & 0xff);
        output.write((value >>> 8) & 0xff);
    }

    private static void writeU32(byte[] bytes, int offset, long value) {
        for (int shift = 0; shift < 32; shift += 8) {
            bytes[offset + shift / 8] = (byte) (value >>> shift);
        }
    }

    private static byte[] f103Bin() throws IOException {
        try (InputStream input = Stm32DfuParserTest.class.getResourceAsStream(
                "/fixtures/stm32f103/STM32F103C8T6.bin")) {
            return java.util.Objects.requireNonNull(input).readAllBytes();
        }
    }

    private record TargetData(int alternateSetting, String name, List<ElementData> elements) {
    }

    private record ElementData(long address, byte[] data) {
    }
}
