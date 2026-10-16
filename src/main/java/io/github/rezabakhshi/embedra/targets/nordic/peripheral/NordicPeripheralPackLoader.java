package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

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
 * Bounded JSON parser and integrity verifier for Nordic peripheral definition packs.
 */
public final class NordicPeripheralPackLoader {

    public static final String EXPECTED_SCHEMA = "urn:embedra:schema:nordic-peripheral-pack:1";

    private NordicPeripheralPackLoader() {
    }

    public static NordicPeripheralPack load(
            Path packPath, Path checksumPath, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(packPath, "packPath must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (!Files.isRegularFile(packPath)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_PACK_INVALID,
                "Nordic peripheral pack file not found: " + packPath,
                null));
        }

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(packPath);
        } catch (IOException e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_PACK_INVALID,
                "Failed to read Nordic peripheral pack: " + e.getMessage(),
                null));
        }

        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Nordic peripheral pack exceeds configured input limits: " + bytes.length,
                null));
        }

        if (checksumPath != null && Files.isRegularFile(checksumPath)) {
            try {
                String checksumLine = Files.readString(checksumPath, StandardCharsets.UTF_8).trim();
                String expectedSha = checksumLine.split("\\s+")[0].toLowerCase(Locale.ROOT);
                String actualSha = sha256Hex(bytes);
                if (!expectedSha.equalsIgnoreCase(actualSha)) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.NORDIC_PACK_INTEGRITY_MISMATCH,
                        "Nordic peripheral pack checksum mismatch: expected " + expectedSha + " but got " + actualSha,
                        null));
                }
            } catch (IOException e) {
                throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.NORDIC_PACK_INVALID,
                    "Failed to read checksum file: " + e.getMessage(),
                    null));
            }
        }

        return parseBytes(bytes, limits, token);
    }

    @SuppressWarnings("unchecked")
    public static NordicPeripheralPack parseBytes(byte[] bytes, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        token.throwIfCancellationRequested();
        Object parsed = StrictJsonParser.parse(bytes, limits, token);
        if (!(parsed instanceof Map<?, ?> rootMap)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_PACK_INVALID,
                "Nordic peripheral pack root must be a JSON object",
                null));
        }

        String schemaId = (String) rootMap.get("schemaId");
        if (schemaId == null || !schemaId.equals(EXPECTED_SCHEMA)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_PACK_INVALID,
                "Unsupported peripheral pack schema: " + schemaId,
                null));
        }

        String packId = (String) rootMap.get("packId");
        String series = (String) rootMap.get("series");
        String sourceReference = rootMap.get("sourceReference") instanceof String s
                ? s : "Authoritative Nordic Semiconductor documentation";

        Object periphsObj = rootMap.get("peripherals");
        if (!(periphsObj instanceof List<?> rawPeriphs)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_PACK_INVALID,
                "Missing 'peripherals' list in pack",
                null));
        }

        List<NordicPeripheral> peripherals = new ArrayList<>(rawPeriphs.size());
        for (Object pItem : rawPeriphs) {
            if (!(pItem instanceof Map<?, ?> pMap)) {
                continue;
            }
            String pName = (String) pMap.get("name");
            long baseAddr = parseLong(pMap.get("baseAddress"));
            long endExcl = parseLong(pMap.get("endExclusive"));
            String pDesc = pMap.get("description") instanceof String s ? s : "";

            List<NordicRegister> registers = new ArrayList<>();
            Object regsObj = pMap.get("registers");
            if (regsObj instanceof List<?> rawRegs) {
                for (Object rItem : rawRegs) {
                    if (!(rItem instanceof Map<?, ?> rMap)) {
                        continue;
                    }
                    String rName = (String) rMap.get("name");
                    long rAddr = parseLong(rMap.get("address"));
                    long rOffset = parseLong(rMap.get("offset"));
                    int widthBits = rMap.get("widthBits") instanceof Number n ? n.intValue() : 32;
                    String rDesc = rMap.get("description") instanceof String s ? s : "";
                    boolean isEasyDma = Boolean.TRUE.equals(rMap.get("isEasyDma"));
                    NordicEasyDmaType dmaType = null;
                    if (rMap.get("easyDmaType") instanceof String dt) {
                        try {
                            dmaType = NordicEasyDmaType.valueOf(dt.trim().toUpperCase(Locale.ROOT));
                        } catch (IllegalArgumentException ignored) {
                        }
                    }

                    List<NordicBitField> bitfields = new ArrayList<>();
                    Object bfsObj = rMap.get("bitfields");
                    if (bfsObj instanceof List<?> rawBfs) {
                        for (Object bfItem : rawBfs) {
                            if (!(bfItem instanceof Map<?, ?> bfMap)) {
                                continue;
                            }
                            String bfName = (String) bfMap.get("name");
                            int bfOffset = ((Number) bfMap.get("bitOffset")).intValue();
                            int bfWidth = ((Number) bfMap.get("bitWidth")).intValue();
                            long bfMask = parseLong(bfMap.get("mask"));
                            String bfAccess = bfMap.get("access") instanceof String s ? s : "R/W";
                            String bfDesc = bfMap.get("description") instanceof String s ? s : "";

                            bitfields.add(new NordicBitField(
                                bfName, bfOffset, bfWidth, bfMask, bfAccess, bfDesc));
                        }
                    }

                    registers.add(new NordicRegister(
                        rName, rAddr, rOffset, widthBits, rDesc, bitfields, isEasyDma, dmaType));
                }
            }

            peripherals.add(new NordicPeripheral(
                pName, baseAddr, endExcl, pDesc, registers));
        }

        return new NordicPeripheralPack(packId, series, schemaId, sourceReference, peripherals);
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
