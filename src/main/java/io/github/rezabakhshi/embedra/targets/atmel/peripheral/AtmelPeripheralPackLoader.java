package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Bounded JSON parser and integrity verifier for Atmel/Microchip peripheral definition packs.
 */
public final class AtmelPeripheralPackLoader {

    public static final String EXPECTED_SCHEMA = "urn:embedra:schema:atmel-peripheral-pack:1";

    private AtmelPeripheralPackLoader() {
    }

    public static AtmelPeripheralPack load(
            Path packPath, Path checksumPath, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(packPath, "packPath must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (!Files.isRegularFile(packPath)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_PACK_INVALID,
                "Atmel peripheral pack file not found: " + packPath,
                null));
        }

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(packPath);
        } catch (IOException e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_PACK_INVALID,
                "Failed to read Atmel peripheral pack: " + e.getMessage(),
                null));
        }

        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Atmel peripheral pack exceeds configured input limits: " + bytes.length,
                null));
        }

        if (checksumPath != null && Files.isRegularFile(checksumPath)) {
            try {
                String checksumLine = Files.readString(checksumPath, StandardCharsets.UTF_8).trim();
                String expectedSha = checksumLine.split("\\s+")[0].toLowerCase(Locale.ROOT);
                String actualSha = sha256Hex(bytes);
                if (!expectedSha.equalsIgnoreCase(actualSha)) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.ATMEL_PACK_INTEGRITY_MISMATCH,
                        "Atmel peripheral pack checksum mismatch: expected " + expectedSha + " but got " + actualSha,
                        null));
                }
            } catch (IOException e) {
                throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.ATMEL_PACK_INVALID,
                    "Failed to read checksum file: " + e.getMessage(),
                    null));
            }
        }

        return parseBytes(bytes, limits, token);
    }

    @SuppressWarnings("unchecked")
    public static AtmelPeripheralPack parseBytes(byte[] bytes, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        token.throwIfCancellationRequested();
        Object parsed;
        try {
            parsed = StrictJsonParser.parse(bytes, limits, token);
        } catch (DiagnosticException e) {
            if (e.diagnostic().code() == DiagnosticCode.CANCELLED
                    || e.diagnostic().code() == DiagnosticCode.LIMIT_EXCEEDED) {
                throw e;
            }
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_PACK_INVALID,
                "Malformed Atmel peripheral pack JSON: " + e.getMessage(),
                null));
        }
        if (!(parsed instanceof Map<?, ?> rootMap)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_PACK_INVALID,
                "Atmel peripheral pack root must be a JSON object",
                null));
        }

        String schemaId = (String) rootMap.get("schemaId");
        if (schemaId == null || !schemaId.equals(EXPECTED_SCHEMA)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_PACK_INVALID,
                "Unsupported peripheral pack schema: " + schemaId,
                null));
        }

        String packId = (String) rootMap.get("packId");
        String device = (String) rootMap.get("device");
        String catalogPart = (String) rootMap.get("catalogPart");
        String series = (String) rootMap.get("series");
        String core = (String) rootMap.get("core");
        String addressSpace = (String) rootMap.get("addressSpace");
        String sourceReference = rootMap.get("sourceReference") instanceof String s
                ? s : "Authoritative Microchip DFP / ASF documentation";

        List<AtmelIoPort> ioPorts = parseIoPorts(rootMap.get("ioPorts"));
        AtmelFuseMap fuseMap = parseFuseMap(rootMap.get("fuseMap"));
        List<AtmelInterrupt> interrupts = parseInterrupts(rootMap.get("interrupts"));
        List<AtmelPeripheral> peripherals = parsePeripherals(rootMap.get("peripherals"), addressSpace);

        return new AtmelPeripheralPack(
            packId, device, catalogPart, series, core, addressSpace, schemaId,
            sourceReference, ioPorts, fuseMap, interrupts, peripherals
        );
    }

    private static List<AtmelIoPort> parseIoPorts(Object rawObj) {
        if (!(rawObj instanceof List<?> rawList)) {
            return List.of();
        }
        List<AtmelIoPort> ports = new ArrayList<>(rawList.size());
        for (Object item : rawList) {
            if (!(item instanceof Map<?, ?> map)) {
                continue;
            }
            String name = (String) map.get("name");
            int pinCount = parseInt(map.get("pinCount"));
            String dataReg = map.get("dataRegister") instanceof String s ? s : "";
            String dirReg = map.get("directionRegister") instanceof String s ? s : "";
            String inReg = map.get("inputRegister") instanceof String s ? s : "";
            ports.add(new AtmelIoPort(name, pinCount, dataReg, dirReg, inReg));
        }
        return List.copyOf(ports);
    }

    private static AtmelFuseMap parseFuseMap(Object rawObj) {
        if (!(rawObj instanceof Map<?, ?> map)) {
            return new AtmelFuseMap("UNAVAILABLE", "No fuse map provided", List.of());
        }
        String state = map.get("state") instanceof String s ? s : "UNAVAILABLE";
        String reason = map.get("reason") instanceof String s ? s : "";
        List<AtmelFuseByte> bytes = new ArrayList<>();
        if (map.get("bytes") instanceof List<?> rawBytes) {
            for (Object bItem : rawBytes) {
                if (!(bItem instanceof Map<?, ?> bMap)) {
                    continue;
                }
                String bName = (String) bMap.get("name");
                long bAddr = parseLong(bMap.get("address"));
                int sizeBits = bMap.get("sizeBits") instanceof Number n ? n.intValue() : 8;
                long defVal = bMap.get("defaultValue") != null ? parseLong(bMap.get("defaultValue")) : 0xFFL;
                String bDesc = bMap.get("description") instanceof String s ? s : "";

                List<AtmelFuseBit> bits = new ArrayList<>();
                if (bMap.get("bits") instanceof List<?> rawBits) {
                    for (Object bitItem : rawBits) {
                        if (!(bitItem instanceof Map<?, ?> bitMap)) {
                            continue;
                        }
                        String bitName = (String) bitMap.get("name");
                        int bitOffset = parseInt(bitMap.get("bitOffset"));
                        int bitWidth = parseInt(bitMap.get("bitWidth"));
                        long mask = parseLong(bitMap.get("mask"));
                        String polStr = bitMap.get("polarity") instanceof String s ? s : "PROGRAMMED_LOW";
                        AtmelFusePolarity pol = "PROGRAMMED_HIGH".equalsIgnoreCase(polStr)
                            ? AtmelFusePolarity.PROGRAMMED_HIGH : AtmelFusePolarity.PROGRAMMED_LOW;
                        String bitDesc = bitMap.get("description") instanceof String s ? s : "";

                        bits.add(new AtmelFuseBit(bitName, bitOffset, bitWidth, mask, pol, bitDesc));
                    }
                }
                bytes.add(new AtmelFuseByte(bName, bAddr, sizeBits, defVal, bDesc, bits));
            }
        }
        return new AtmelFuseMap(state, reason, bytes);
    }

    private static List<AtmelInterrupt> parseInterrupts(Object rawObj) {
        if (!(rawObj instanceof List<?> rawList)) {
            return List.of();
        }
        List<AtmelInterrupt> interrupts = new ArrayList<>(rawList.size());
        for (Object item : rawList) {
            if (!(item instanceof Map<?, ?> map)) {
                continue;
            }
            int index = parseInt(map.get("index"));
            String name = (String) map.get("name");
            String desc = map.get("description") instanceof String s ? s : "";
            interrupts.add(new AtmelInterrupt(index, name, desc));
        }
        return List.copyOf(interrupts);
    }

    private static List<AtmelPeripheral> parsePeripherals(Object rawObj, String defaultAddressSpace) {
        if (!(rawObj instanceof List<?> rawList)) {
            return List.of();
        }
        List<AtmelPeripheral> peripherals = new ArrayList<>(rawList.size());
        for (Object item : rawList) {
            if (!(item instanceof Map<?, ?> pMap)) {
                continue;
            }
            String pName = (String) pMap.get("name");
            long baseAddr = parseLong(pMap.get("baseAddress"));
            long endExcl = parseLong(pMap.get("endExclusive"));
            String addrSpace = pMap.get("addressSpace") instanceof String s ? s : defaultAddressSpace;
            String pDesc = pMap.get("description") instanceof String s ? s : "";

            List<AtmelRegister> registers = new ArrayList<>();
            if (pMap.get("registers") instanceof List<?> rawRegs) {
                for (Object rItem : rawRegs) {
                    if (!(rItem instanceof Map<?, ?> rMap)) {
                        continue;
                    }
                    String rName = (String) rMap.get("name");
                    long rAddr = parseLong(rMap.get("address"));
                    long rOffset = parseLong(rMap.get("offset"));
                    int widthBits = rMap.get("widthBits") instanceof Number n ? n.intValue() : 8;
                    String rAccess = rMap.get("access") instanceof String s ? s : "R/W";
                    String rDesc = rMap.get("description") instanceof String s ? s : "";

                    List<AtmelBitField> bitfields = new ArrayList<>();
                    if (rMap.get("bitfields") instanceof List<?> rawBfs) {
                        for (Object bfItem : rawBfs) {
                            if (!(bfItem instanceof Map<?, ?> bfMap)) {
                                continue;
                            }
                            String bfName = (String) bfMap.get("name");
                            int bfOffset = parseInt(bfMap.get("bitOffset"));
                            int bfWidth = parseInt(bfMap.get("bitWidth"));
                            long bfMask = parseLong(bfMap.get("mask"));
                            String bfAccess = bfMap.get("access") instanceof String s ? s : "R/W";
                            String bfDesc = bfMap.get("description") instanceof String s ? s : "";

                            bitfields.add(new AtmelBitField(bfName, bfOffset, bfWidth, bfMask, bfAccess, bfDesc));
                        }
                    }
                    registers.add(new AtmelRegister(
                        rName, rAddr, rOffset, widthBits, rAccess, rDesc, bitfields));
                }
            }
            peripherals.add(new AtmelPeripheral(pName, baseAddr, endExcl, addrSpace, pDesc, registers));
        }
        return List.copyOf(peripherals);
    }

    private static long parseLong(Object val) {
        if (val instanceof Number n) {
            return n.longValue();
        }
        if (val instanceof String s) {
            String trimmed = s.trim();
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                return Long.parseUnsignedLong(trimmed.substring(2), 16);
            }
            return Long.parseLong(trimmed);
        }
        throw new IllegalArgumentException("Expected numeric or hex string value: " + val);
    }

    private static int parseInt(Object val) {
        if (val instanceof Number n) {
            return n.intValue();
        }
        if (val instanceof String s) {
            String trimmed = s.trim();
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                return Integer.parseUnsignedInt(trimmed.substring(2), 16);
            }
            return Integer.parseInt(trimmed);
        }
        throw new IllegalArgumentException("Expected numeric or hex string value: " + val);
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm missing", e);
        }
    }
}
