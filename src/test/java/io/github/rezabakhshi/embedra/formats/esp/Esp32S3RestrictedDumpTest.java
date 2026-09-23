package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class Esp32S3RestrictedDumpTest {
    private static final String EXPECTED_SHA256 =
        "837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de";

    @Test
    void plansUserSuppliedDumpWithoutTreatingErasedOtaSlotAsCode()
            throws Exception {
        Path dump = Path.of(System.getProperty("embedra.projectDir"),
            "esp32s3_ctf_dump_4MB.bin");
        assumeTrue(Files.isRegularFile(dump),
            "restricted local fixture is intentionally absent from public CI");
        byte[] bytes = Files.readAllBytes(dump);
        assertEquals(EXPECTED_SHA256, HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(bytes)));

        EspFullFlashWorkspace workspace = EspFullFlashWorkspacePlanner.plan(bytes,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals(List.of("nvs", "otadata", "app0", "app1", "spiffs",
            "coredump"), workspace.partitionTable().entries().stream()
                .map(EspPartitionEntry::label).toList());
        assertEquals(List.of("bootloader", "app0"), workspace.executables().stream()
            .map(EspExtractedExecutable::name).toList());
        EspExtractedPartition app1 = workspace.dataPartitions().stream()
            .filter(partition -> partition.entry().label().equals("app1"))
            .findFirst().orElseThrow();
        assertEquals(EspPartitionPayloadKind.ERASED_APPLICATION_SLOT, app1.kind());
        assertEquals("app0", workspace.partitionAnalysis().otaSelection()
            .orElseThrow().activePartitionLabel().orElseThrow());
        assertEquals(EspPartitionDisposition.VALIDATED_METADATA,
            inspection(workspace, "nvs").disposition());
        assertEquals(EspPartitionDisposition.ERASED,
            inspection(workspace, "spiffs").disposition());
        assertEquals("9", inspection(workspace, "coredump")
            .metadata().get("chipId"));
        assertTrue(inspection(workspace, "coredump").metadata()
            .containsKey("dataLength"));
    }

    private static EspPartitionInspection inspection(EspFullFlashWorkspace workspace,
            String label) {
        return workspace.partitionAnalysis().inspections().stream()
            .filter(candidate -> candidate.entry().label().equals(label))
            .findFirst().orElseThrow();
    }
}
