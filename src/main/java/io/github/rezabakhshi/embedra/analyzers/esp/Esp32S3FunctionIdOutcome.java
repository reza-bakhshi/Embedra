package io.github.rezabakhshi.embedra.analyzers.esp;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Immutable, deterministic ESP32-S3 Function ID run outcome. */
public record Esp32S3FunctionIdOutcome(
        Esp32S3FunctionIdStatus status,
        Optional<Esp32S3FunctionIdEvidence> evidence,
        int functionsExamined,
        int candidateFunctions,
        int functionsRenamed,
        int functionsAmbiguous) {
    private static final Set<Esp32S3FunctionIdStatus> REFUSAL_STATUSES = Set.of(
        Esp32S3FunctionIdStatus.DATABASE_ABSENT,
        Esp32S3FunctionIdStatus.TARGET_INCOMPATIBLE,
        Esp32S3FunctionIdStatus.VERSION_INCOMPATIBLE,
        Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH,
        Esp32S3FunctionIdStatus.DATABASE_CONFLICT,
        Esp32S3FunctionIdStatus.PROVENANCE_INVALID,
        Esp32S3FunctionIdStatus.CANCELLED,
        Esp32S3FunctionIdStatus.RUN_FAILED);

    public Esp32S3FunctionIdOutcome {
        Objects.requireNonNull(status, "status");
        evidence = Objects.requireNonNull(evidence, "evidence");
        if (functionsExamined < 0 || candidateFunctions < 0 || functionsRenamed < 0
            || functionsAmbiguous < 0) {
            throw new IllegalArgumentException("Function ID outcome counts must be non-negative");
        }
        if (candidateFunctions > functionsExamined || functionsRenamed > candidateFunctions
            || functionsAmbiguous > candidateFunctions) {
            throw new IllegalArgumentException(
                "Function ID outcome counts must be consistent");
        }
    }

    public static Esp32S3FunctionIdOutcome classify(Esp32S3FunctionIdEvidence evidence,
            int functionsExamined, int candidateFunctions, int functionsRenamed,
            int functionsAmbiguous) {
        Objects.requireNonNull(evidence, "evidence");
        Esp32S3FunctionIdStatus status;
        if (functionsAmbiguous > 0) {
            status = Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES;
        }
        else if (functionsRenamed > 0) {
            status = Esp32S3FunctionIdStatus.MATCHES_APPLIED;
        }
        else if (candidateFunctions > 0) {
            status = Esp32S3FunctionIdStatus.ALREADY_APPLIED;
        }
        else {
            status = Esp32S3FunctionIdStatus.NO_MATCHES;
        }
        return new Esp32S3FunctionIdOutcome(status, Optional.of(evidence), functionsExamined,
            candidateFunctions, functionsRenamed, functionsAmbiguous);
    }

    public static Esp32S3FunctionIdOutcome refused(Esp32S3FunctionIdStatus status) {
        Objects.requireNonNull(status, "status");
        if (!REFUSAL_STATUSES.contains(status)) {
            throw new IllegalArgumentException(
                "Refused outcomes require a refusal status: " + status);
        }
        return new Esp32S3FunctionIdOutcome(status, Optional.empty(), 0, 0, 0, 0);
    }
}
