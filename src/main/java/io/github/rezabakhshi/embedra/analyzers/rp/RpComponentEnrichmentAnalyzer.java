package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure analyzer running TinyUSB, lwIP, and CYW43 component detectors.
 */
public final class RpComponentEnrichmentAnalyzer {

    private final RpTinyUsbDetector tinyUsbDetector;

    private final RpLwIpDetector lwIpDetector;

    private final RpCyw43Detector cyw43Detector;

    public RpComponentEnrichmentAnalyzer() {
        this(new RpTinyUsbDetector(), new RpLwIpDetector(), new RpCyw43Detector());
    }

    public RpComponentEnrichmentAnalyzer(
            RpTinyUsbDetector tinyUsbDetector,
            RpLwIpDetector lwIpDetector,
            RpCyw43Detector cyw43Detector) {
        this.tinyUsbDetector = Objects.requireNonNull(tinyUsbDetector, "tinyUsbDetector must not be null");
        this.lwIpDetector = Objects.requireNonNull(lwIpDetector, "lwIpDetector must not be null");
        this.cyw43Detector = Objects.requireNonNull(cyw43Detector, "cyw43Detector must not be null");
    }

    public RpComponentEnrichmentReport analyze(
            RpAnalysisContext context,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        RpTinyUsbMatch tinyUsb = tinyUsbDetector.detect(context, limits, token);
        token.throwIfCancellationRequested();

        RpLwIpMatch lwIp = lwIpDetector.detect(context, limits, token);
        token.throwIfCancellationRequested();

        RpCyw43Match cyw43 = cyw43Detector.detect(context, limits, token);
        token.throwIfCancellationRequested();

        List<Evidence> overall = new ArrayList<>();
        if (tinyUsb.detected()) {
            overall.add(new Evidence(
                    EvidenceKind.EXACT_SIGNATURE_MATCH,
                    "TinyUSB Recognition",
                    "Detected TinyUSB USB device stack"));
        }
        if (lwIp.detected()) {
            overall.add(new Evidence(
                    EvidenceKind.EXACT_SIGNATURE_MATCH,
                    "lwIP Recognition",
                    "Detected lwIP embedded TCP/IP stack"));
        }
        if (cyw43.detected()) {
            overall.add(new Evidence(
                    EvidenceKind.EXACT_SIGNATURE_MATCH,
                    "CYW43 Recognition",
                    "Detected Infineon CYW43439 wireless driver"));
        }

        return new RpComponentEnrichmentReport(tinyUsb, lwIp, cyw43, overall);
    }
}
