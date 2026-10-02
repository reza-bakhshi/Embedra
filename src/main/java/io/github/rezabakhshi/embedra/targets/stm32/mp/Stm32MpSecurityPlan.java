package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * TrustZone, firewall controller, and OTP security model for STM32MP parts.
 *
 * <p>Captures hardware security controllers (ETZPC on STM32MP1, RIF on STM32MP2),
 * secure world vs non-secure world boundaries, and OTP configuration registers (BSEC).</p>
 */
public record Stm32MpSecurityPlan(
        String exactPart,
        SecurityArchitecture architecture,
        List<SecurityDomain> domains,
        List<SecurityFirewallWindow> firewallWindows,
        List<OtpSecurityRegion> otpRegions,
        Confidence confidence,
        List<Evidence> evidence) {

    public Stm32MpSecurityPlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(architecture, "architecture");
        Objects.requireNonNull(confidence, "confidence");
        domains = List.copyOf(domains);
        firewallWindows = List.copyOf(firewallWindows);
        otpRegions = List.copyOf(otpRegions);
        evidence = List.copyOf(evidence);

        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Exact part must not be blank");
        }
        Set<String> domainIds = new HashSet<>();
        for (SecurityDomain d : domains) {
            if (!domainIds.add(d.id())) {
                throw new IllegalArgumentException("Duplicate security domain ID: " + d.id());
            }
        }
        Set<String> windowIds = new HashSet<>();
        for (SecurityFirewallWindow w : firewallWindows) {
            if (!windowIds.add(w.id())) {
                throw new IllegalArgumentException("Duplicate firewall window ID: " + w.id());
            }
        }
        Set<String> otpIds = new HashSet<>();
        for (OtpSecurityRegion o : otpRegions) {
            if (!otpIds.add(o.id())) {
                throw new IllegalArgumentException("Duplicate OTP region ID: " + o.id());
            }
        }
    }

    /** Security hardware architecture kind. */
    public enum SecurityArchitecture {
        ETZPC_TRUSTZONE,
        RIF_TRUSTZONE
    }

    /** Hardware firewall aperture governing peripheral and bus access. */
    public record SecurityFirewallWindow(
            String id,
            String controllerName,
            AddressRange range,
            SecurityDomain securityDomain,
            boolean programmable,
            Confidence confidence,
            List<Evidence> evidence) {

        public SecurityFirewallWindow {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(controllerName, "controllerName");
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(securityDomain, "securityDomain");
            Objects.requireNonNull(confidence, "confidence");
            evidence = List.copyOf(evidence);
            if (id.isBlank() || controllerName.isBlank()) {
                throw new IllegalArgumentException("Firewall window fields must not be blank");
            }
        }
    }

    /** OTP fuse or security configuration register range (BSEC). */
    public record OtpSecurityRegion(
            String id,
            String controllerName,
            AddressRange range,
            boolean fuseLocked,
            Confidence confidence,
            List<Evidence> evidence) {

        public OtpSecurityRegion {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(controllerName, "controllerName");
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(confidence, "confidence");
            evidence = List.copyOf(evidence);
            if (id.isBlank() || controllerName.isBlank()) {
                throw new IllegalArgumentException("OTP region fields must not be blank");
            }
        }
    }
}
