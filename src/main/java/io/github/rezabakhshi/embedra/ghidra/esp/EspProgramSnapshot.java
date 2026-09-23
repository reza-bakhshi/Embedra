package io.github.rezabakhshi.embedra.ghidra.esp;

import io.github.rezabakhshi.embedra.core.report.CanonicalJson;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageSegment;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Canonical snapshot of the exact committed ESP mapping contract. */
public final class EspProgramSnapshot {
    public static final String SCHEMA_ID = "urn:embedra:snapshot:esp-program:1";

    private final Map<String, Object> canonicalValue;

    private EspProgramSnapshot(Map<String, Object> canonicalValue) {
        this.canonicalValue = Map.copyOf(canonicalValue);
    }

    public static EspProgramSnapshot from(EspImage image, EspImportReport report) {
        Objects.requireNonNull(image, "image");
        Objects.requireNonNull(report, "report");
        List<Map<String, Object>> blocks = new ArrayList<>(report.segments().size());
        for (EspMappedSegmentReport mapped : report.segments()) {
            EspImageSegment segment = image.segments().stream()
                .filter(candidate -> candidate.index() == mapped.index())
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                    "Mapped segment has no parsed source segment"));
            LinkedHashMap<String, Object> block = new LinkedHashMap<>();
            block.put("name", mapped.blockName());
            block.put("start", mapped.loadAddress());
            block.put("length", mapped.length());
            block.put("readable", mapped.readable());
            block.put("writable", mapped.writable());
            block.put("executable", mapped.executable());
            block.put("sha256", sha256(segment.data()));
            block.put("sourceOffset", mapped.sourceRange().offset());
            block.put("sourceLength", mapped.sourceRange().length());
            blocks.add(Map.copyOf(block));
        }
        LinkedHashMap<String, Object> value = new LinkedHashMap<>();
        value.put("schemaId", SCHEMA_ID);
        value.put("deviceId", report.deviceId());
        value.put("languageId", report.languageId());
        value.put("compilerSpecId", report.compilerSpecId());
        value.put("blocks", List.copyOf(blocks));
        value.put("entryPoint", report.entryPoint().orElseThrow());
        value.put("entrySymbol", "entry");
        return new EspProgramSnapshot(value);
    }

    public String toCanonicalJson() {
        return CanonicalJson.write(canonicalValue);
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Required SHA-256 implementation unavailable",
                exception);
        }
    }
}
