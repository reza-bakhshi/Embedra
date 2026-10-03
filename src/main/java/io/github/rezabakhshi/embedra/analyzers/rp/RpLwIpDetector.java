package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure detector identifying lwIP protocol stack components, network interfaces, and state models.
 */
public final class RpLwIpDetector {

    private static final Set<String> KNOWN_APIS = Set.of(
            "lwip_init", "netif_add", "netif_set_up", "netif_set_default", "netif_set_link_up",
            "tcp_new", "tcp_bind", "tcp_listen", "tcp_connect", "tcp_write", "tcp_output",
            "udp_new", "udp_bind", "udp_send", "dhcp_start", "dhcp_stop",
            "pbuf_alloc", "pbuf_free", "netconn_new", "netconn_connect");

    private static final Pattern LWIP_VERSION_PATTERN = Pattern.compile(
            "lwIP\\s+v?([0-9]+\\.[0-9]+(\\.[0-9]+)?(-\\w+)?)", Pattern.CASE_INSENSITIVE);

    public RpLwIpMatch detect(
            RpAnalysisContext context,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        String foundVersion = null;
        Set<String> protocols = new LinkedHashSet<>();
        List<String> matchedApis = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();

        for (String sym : context.symbols()) {
            token.throwIfCancellationRequested();
            if (KNOWN_APIS.contains(sym)) {
                matchedApis.add(sym);
                classifyProtocol(sym, protocols);
            }
        }

        for (String str : context.strings()) {
            token.throwIfCancellationRequested();
            if (KNOWN_APIS.contains(str) && !matchedApis.contains(str)) {
                matchedApis.add(str);
                classifyProtocol(str, protocols);
            }

            Matcher m = LWIP_VERSION_PATTERN.matcher(str);
            if (m.find()) {
                foundVersion = m.group(1);
                evidence.add(new Evidence(
                        EvidenceKind.DOCUMENTED_FIELD,
                        "lwIP Version String",
                        "Identified version string: " + str));
            } else if (str.contains("lwIP") || str.contains("lwip")) {
                evidence.add(new Evidence(
                        EvidenceKind.HEURISTIC,
                        "lwIP string literal",
                        "Found string: " + str));
            }

            if (str.contains("netif") || str.contains("NETIF")) {
                protocols.add("NETIF");
            }
            if (str.contains("DHCP") || str.contains("dhcp")) {
                protocols.add("DHCP");
            }
        }

        if (!matchedApis.isEmpty()) {
            evidence.add(new Evidence(
                    EvidenceKind.EXACT_SIGNATURE_MATCH,
                    "lwIP API Symbols",
                    "Identified lwIP stack APIs: " + String.join(", ", matchedApis)));
        }

        boolean detected = foundVersion != null || !matchedApis.isEmpty() || !evidence.isEmpty();
        if (!detected) {
            return RpLwIpMatch.notDetected();
        }

        Confidence confidence;
        if (foundVersion != null && !matchedApis.isEmpty()) {
            confidence = Confidence.VERIFIED;
        } else if (foundVersion != null || matchedApis.size() >= 2) {
            confidence = Confidence.DERIVED;
        } else {
            confidence = Confidence.HEURISTIC;
        }

        return new RpLwIpMatch(
                true,
                Optional.ofNullable(foundVersion),
                List.copyOf(protocols),
                matchedApis,
                confidence,
                evidence);
    }

    private static void classifyProtocol(String api, Set<String> protocols) {
        if (api.startsWith("tcp_")) {
            protocols.add("TCP");
        } else if (api.startsWith("udp_")) {
            protocols.add("UDP");
        } else if (api.startsWith("dhcp_")) {
            protocols.add("DHCP");
        } else if (api.startsWith("netif_")) {
            protocols.add("NETIF");
        } else if (api.startsWith("lwip_")) {
            protocols.add("IP");
        }
    }
}
