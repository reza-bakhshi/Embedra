package io.github.rezabakhshi.embedra.ghidra.esp;

import io.github.rezabakhshi.embedra.formats.esp.EspExtractedExecutable;
import io.github.rezabakhshi.embedra.formats.esp.EspFullFlashWorkspace;
import java.util.Objects;

/** Physical full-flash provenance persisted alongside one extracted Ghidra program. */
public record EspFlashProgramProvenance(
        String sourceSha256,
        long partitionTableOffset,
        long flashOffset,
        long flashLength,
        String role,
        String partitionLabel) {
    public EspFlashProgramProvenance {
        Objects.requireNonNull(sourceSha256, "sourceSha256");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(partitionLabel, "partitionLabel");
        if (!sourceSha256.matches("[0-9a-f]{64}") || partitionTableOffset < 0
            || flashOffset < 0 || flashLength <= 0 || role.isBlank()) {
            throw new IllegalArgumentException("Invalid ESP flash program provenance");
        }
    }

    public static EspFlashProgramProvenance from(EspFullFlashWorkspace workspace,
            EspExtractedExecutable executable) {
        return new EspFlashProgramProvenance(workspace.sourceSha256(),
            workspace.partitionTable().tableFlashRange().offset(),
            executable.flashRange().offset(), executable.flashRange().length(),
            executable.role().name(), executable.partitionLabel().orElse(""));
    }
}
