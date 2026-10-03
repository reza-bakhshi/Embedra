package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Pure detector identifying TinyUSB descriptors, tables, and API call patterns.
 */
public final class RpTinyUsbDetector {

    private static final Set<String> KNOWN_APIS = Set.of(
            "tud_init", "tud_task", "tud_cdc_connected", "tud_cdc_write", "tud_cdc_read",
            "tud_mounted", "tud_suspended", "tuh_init", "tuh_task", "dcd_init",
            "dcd_int_handler", "tusb_init", "tud_msc_read10_cb");

    public RpTinyUsbMatch detect(
            RpAnalysisContext context,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        List<UsbDescriptorInfo> descriptors = scanDescriptors(context.segments(), token);
        List<String> matchedApis = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();

        for (String sym : context.symbols()) {
            token.throwIfCancellationRequested();
            if (KNOWN_APIS.contains(sym)) {
                matchedApis.add(sym);
            }
        }

        for (String str : context.strings()) {
            token.throwIfCancellationRequested();
            if (KNOWN_APIS.contains(str) && !matchedApis.contains(str)) {
                matchedApis.add(str);
            }
            if ("TinyUSB".equalsIgnoreCase(str) || str.contains("TinyUSB")) {
                evidence.add(new Evidence(
                        EvidenceKind.DOCUMENTED_FIELD,
                        "TinyUSB string literal",
                        "Found string: " + str));
            }
        }

        if (!descriptors.isEmpty()) {
            evidence.add(new Evidence(
                    EvidenceKind.EXACT_SIGNATURE_MATCH,
                    "USB Standard Descriptors",
                    "Found " + descriptors.size() + " validated USB descriptor structures"));
        }

        if (!matchedApis.isEmpty()) {
            evidence.add(new Evidence(
                    EvidenceKind.EXACT_SIGNATURE_MATCH,
                    "TinyUSB API Symbols",
                    "Identified TinyUSB driver APIs: " + String.join(", ", matchedApis)));
        }

        boolean detected = !descriptors.isEmpty() || !matchedApis.isEmpty() || !evidence.isEmpty();
        if (!detected) {
            return RpTinyUsbMatch.notDetected();
        }

        Confidence confidence;
        if (!descriptors.isEmpty() && !matchedApis.isEmpty()) {
            confidence = Confidence.VERIFIED;
        } else if (!descriptors.isEmpty() || !matchedApis.isEmpty()) {
            confidence = Confidence.DERIVED;
        } else {
            confidence = Confidence.HEURISTIC;
        }

        return new RpTinyUsbMatch(true, descriptors, matchedApis, confidence, evidence);
    }

    private List<UsbDescriptorInfo> scanDescriptors(List<RpUf2Segment> segments, CancellationToken token)
            throws DiagnosticException {
        List<UsbDescriptorInfo> result = new ArrayList<>();
        for (RpUf2Segment seg : segments) {
            byte[] data = seg.data();
            long base = seg.targetAddress();
            int len = data.length;

            for (int i = 0; i + 18 <= len; i++) {
                if ((i & 0xFFF) == 0) {
                    token.throwIfCancellationRequested();
                }

                // Check Device Descriptor: length 18 (0x12), type 1 (0x01)
                if (data[i] == 0x12 && data[i + 1] == 0x01) {
                    int bcdUsb = (data[i + 2] & 0xFF) | ((data[i + 3] & 0xFF) << 8);
                    int maxPacket = data[i + 7] & 0xFF;
                    int numConfigs = data[i + 17] & 0xFF;
                    if ((bcdUsb == 0x0110 || bcdUsb == 0x0200 || bcdUsb == 0x0210)
                            && (maxPacket == 8 || maxPacket == 16 || maxPacket == 32 || maxPacket == 64)
                            && numConfigs >= 1 && numConfigs <= 4) {
                        int vid = (data[i + 8] & 0xFF) | ((data[i + 9] & 0xFF) << 8);
                        int pid = (data[i + 10] & 0xFF) | ((data[i + 11] & 0xFF) << 8);
                        result.add(new UsbDescriptorInfo(
                                base + i,
                                "DEVICE",
                                18,
                                String.format("USB Device Descriptor (VID=0x%04X, PID=0x%04X, USB=%X.%02X)",
                                        vid, pid, (bcdUsb >> 8) & 0xFF, bcdUsb & 0xFF)));
                    }
                }

                // Check Configuration Descriptor: length 9 (0x09), type 2 (0x02)
                if (i + 9 <= len && data[i] == 0x09 && data[i + 1] == 0x02) {
                    int wTotal = (data[i + 2] & 0xFF) | ((data[i + 3] & 0xFF) << 8);
                    int numInterfaces = data[i + 4] & 0xFF;
                    int cfgVal = data[i + 5] & 0xFF;
                    if (wTotal >= 9 && wTotal <= 1024 && numInterfaces >= 1 && numInterfaces <= 16 && cfgVal >= 1) {
                        result.add(new UsbDescriptorInfo(
                                base + i,
                                "CONFIGURATION",
                                9,
                                String.format("USB Config Descriptor (TotalLength=%d, Interfaces=%d)",
                                        wTotal, numInterfaces)));
                    }
                }

                // Check Interface Descriptor: length 9 (0x09), type 4 (0x04)
                if (i + 9 <= len && data[i] == 0x09 && data[i + 1] == 0x04) {
                    int ifaceNum = data[i + 2] & 0xFF;
                    int altSetting = data[i + 3] & 0xFF;
                    int numEp = data[i + 4] & 0xFF;
                    int ifaceClass = data[i + 5] & 0xFF;
                    if (altSetting == 0 && numEp <= 16) {
                        result.add(new UsbDescriptorInfo(
                                base + i,
                                "INTERFACE",
                                9,
                                String.format("USB Interface Descriptor (Index=%d, Class=0x%02X, Endpoints=%d)",
                                        ifaceNum, ifaceClass, numEp)));
                    }
                }

                // Check Endpoint Descriptor: length 7 (0x07), type 5 (0x05)
                if (i + 7 <= len && data[i] == 0x07 && data[i + 1] == 0x05) {
                    int epAddr = data[i + 2] & 0xFF;
                    int epAttr = data[i + 3] & 0xFF;
                    int maxPack = (data[i + 4] & 0xFF) | ((data[i + 5] & 0xFF) << 8);
                    if (maxPack >= 8 && maxPack <= 1024 && epAttr <= 3) {
                        result.add(new UsbDescriptorInfo(
                                base + i,
                                "ENDPOINT",
                                7,
                                String.format("USB Endpoint Descriptor (Addr=0x%02X, Attr=0x%02X, MaxPacket=%d)",
                                        epAddr, epAttr, maxPack)));
                    }
                }
            }
        }
        return result;
    }
}
