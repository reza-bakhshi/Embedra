package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.List;

/**
 * Pure contract for STM32MP heterogeneous target providers.
 *
 * <p>STM32MP devices represent heterogeneous application processors combining
 * 32-bit or 64-bit Cortex-A application cores with Cortex-M real-time
 * coprocessors and dedicated security domains. They operate under separate
 * OS-aware workflows and are not loaded as ordinary Cortex-M-only MCU firmware
 * (STM-015, STM-021).</p>
 */
public interface Stm32MpTargetProvider {
    /** Unique stable provider identifier. */
    String providerId();

    /** Provider implementation version. */
    String providerVersion();

    /** Canonical exact commercial part number (CPN) or primary orderable target. */
    String exactPart();

    /** Product line prefix, e.g. "STM32MP157", "STM32MP257", "STM32MP135". */
    String line();

    /** Architecture family identifier, e.g. "STM32MP1" or "STM32MP2". */
    String family();

    /** Validated execution topology across all physical and logical execution units. */
    ExecutionTopology topology();

    /** Default boot chain plan from SoC ROM to application runtime. */
    Stm32MpBootChainPlan bootChainPlan();

    /** Boot chain plan for an explicitly selected boot architecture flavor. */
    Stm32MpBootChainPlan bootChainPlan(Stm32MpBootChainPlan.BootArchitecture architecture);

    /** Device tree binding and resource allocation plan. */
    Stm32MpDeviceTreePlan deviceTreePlan();

    /** TrustZone, firewall, and OTP security allocation plan. */
    Stm32MpSecurityPlan securityPlan();

    /** Shared memory, mailbox, and hardware semaphore plan. */
    Stm32MpSharedResourcesPlan sharedResourcesPlan();

    /** Multi-program workspace allocation plan per TOPO-004. */
    Stm32MpWorkspacePlan workspacePlan();

    /** Evaluate support for a candidate part or line identifier. */
    SupportDecision supports(String exactPartOrLine);

    /** True when this provider matches the given exact part number or line name. */
    boolean matches(String exactPartOrLine);

    /** Confidence level of the provider facts. */
    Confidence confidence();

    /** Pinned factual evidence justifying the provider configuration. */
    List<Evidence> evidence();

    /**
     * Shipped support state per STM-019.
     * All STM32MP devices remain {@code PLANNED} until all execution topologies pass fixtures.
     */
    default String supportState() {
        return "PLANNED";
    }
}
