package io.github.rezabakhshi.embedra.ghidra.esp;

import io.github.rezabakhshi.embedra.core.report.CanonicalReport;
import io.github.rezabakhshi.embedra.formats.esp.EspAppDescriptionResult;
import java.util.Objects;

/** Deterministic result shared by interactive and headless ESP imports. */
public record EspImportWorkflowResult(
        EspImportReport importReport,
        EspAppDescriptionResult appDescription,
        CanonicalReport canonicalReport,
        EspProgramSnapshot programSnapshot) {
    public EspImportWorkflowResult {
        Objects.requireNonNull(importReport, "importReport");
        Objects.requireNonNull(appDescription, "appDescription");
        Objects.requireNonNull(canonicalReport, "canonicalReport");
        Objects.requireNonNull(programSnapshot, "programSnapshot");
    }

    public String canonicalReportJson() {
        return canonicalReport.toCanonicalJson();
    }

    public String programSnapshotJson() {
        return programSnapshot.toCanonicalJson();
    }
}
