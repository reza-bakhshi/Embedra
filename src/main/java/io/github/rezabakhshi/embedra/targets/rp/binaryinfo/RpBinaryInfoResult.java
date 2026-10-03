package io.github.rezabakhshi.embedra.targets.rp.binaryinfo;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Validated in-memory result of parsing a Pico SDK binary info block.
 */
public record RpBinaryInfoResult(
        boolean present,
        long headerAddress,
        Optional<String> programName,
        Optional<String> programVersion,
        Optional<String> programBuildDate,
        Optional<String> programUrl,
        Optional<String> programDescription,
        Optional<String> sdkVersion,
        Optional<String> picoBoard,
        Optional<String> boot2Name,
        Optional<Long> binaryEnd,
        List<String> programFeatures,
        List<String> buildAttributes,
        List<RpBinaryInfoPin> pins,
        List<RpBinaryInfoBlockDevice> blockDevices,
        List<String> diagnostics) {

    public RpBinaryInfoResult {
        Objects.requireNonNull(programName, "programName must not be null");
        Objects.requireNonNull(programVersion, "programVersion must not be null");
        Objects.requireNonNull(programBuildDate, "programBuildDate must not be null");
        Objects.requireNonNull(programUrl, "programUrl must not be null");
        Objects.requireNonNull(programDescription, "programDescription must not be null");
        Objects.requireNonNull(sdkVersion, "sdkVersion must not be null");
        Objects.requireNonNull(picoBoard, "picoBoard must not be null");
        Objects.requireNonNull(boot2Name, "boot2Name must not be null");
        Objects.requireNonNull(binaryEnd, "binaryEnd must not be null");
        Objects.requireNonNull(programFeatures, "programFeatures must not be null");
        Objects.requireNonNull(buildAttributes, "buildAttributes must not be null");
        Objects.requireNonNull(pins, "pins must not be null");
        Objects.requireNonNull(blockDevices, "blockDevices must not be null");
        Objects.requireNonNull(diagnostics, "diagnostics must not be null");

        programFeatures = List.copyOf(programFeatures);
        buildAttributes = List.copyOf(buildAttributes);
        pins = List.copyOf(pins);
        blockDevices = List.copyOf(blockDevices);
        diagnostics = List.copyOf(diagnostics);
    }

    public static RpBinaryInfoResult notPresent() {
        return new RpBinaryInfoResult(
                false, 0L,
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(),
                List.of(), List.of(), List.of(), List.of(), List.of());
    }
}
