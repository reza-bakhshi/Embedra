package io.github.rezabakhshi.embedra.targets.stm32.wireless;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32SvdApplicability;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlan;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable wireless/network-core classification for one exact curated part.
 *
 * <p>The record carries no invented fact: the pinned curatorial family labels
 * the series, the pinned T039 topology decides whether a separately
 * programmable network core exists, the pinned T040 applicability entry
 * decides every register-model state, and pinned T044 record decides the
 * TrustZone view. Unavailable facts carry a reason and no data.</p>
 */
public record Stm32WirelessRecord(
        String exactPart,
        Series series,
        Status status,
        CoreRole applicationCore,
        RadioSubsystem radioSubsystem,
        SharedResources sharedResources,
        NetworkCore networkCore,
        Stm32SecurityRecord securityRecord,
        List<Evidence> evidence) {

    /** The pinned wireless series of the exact part, from its curated family. */
    public enum Series {
        WB, WB0, WBA, WL3
    }

    /** Network-core evidence state; missing cores stay explicit, never inferred. */
    public enum Status {
        NETWORK_CORE_PINNED, SINGLE_APPLICATION_CORE
    }

    /** Register-model availability; only pinned states and reasons are allowed. */
    public enum RegisterModel {
        SHIPPED, DEFERRED, UNAVAILABLE
    }

    /** Who manages the radio subsystem per the pinned topology. */
    public enum Management {
        NETWORK_CORE_MANAGED, APPLICATION_CORE_MANAGED
    }

    /**
     * One pinned CPU role with its register-model state.
     *
     * @param svdFile the reviewed per-core SVD source, or null when unavailable
     */
    public record CoreRole(String nodeId, String role, FirmwareSource firmwareSource,
            String instructionSet, String ghidraLanguageId, String compilerSpecId,
            SecurityDomain securityDomain, RegisterModel registerModel,
            String registerModelReason, Stm32SvdApplicability.SvdFile svdFile) {
        public CoreRole {
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(role, "role");
            Objects.requireNonNull(firmwareSource, "firmwareSource");
            Objects.requireNonNull(instructionSet, "instructionSet");
            Objects.requireNonNull(ghidraLanguageId, "ghidraLanguageId");
            Objects.requireNonNull(compilerSpecId, "compilerSpecId");
            Objects.requireNonNull(securityDomain, "securityDomain");
            Objects.requireNonNull(registerModel, "registerModel");
            if (nodeId.isBlank() || role.isBlank() || instructionSet.isBlank()
                    || ghidraLanguageId.isBlank() || compilerSpecId.isBlank()) {
                throw new IllegalArgumentException("Wireless core identity is incomplete");
            }
            if (registerModel == RegisterModel.SHIPPED) {
                if (svdFile == null || registerModelReason != null) {
                    throw new IllegalArgumentException(
                        "A shipped register model requires its pinned file and no reason");
                }
            }
            else if (registerModel == RegisterModel.DEFERRED) {
                if (svdFile == null || registerModelReason == null
                        || registerModelReason.isBlank()) {
                    throw new IllegalArgumentException(
                        "A deferred register model requires its pinned file and a reason");
                }
            }
            else {
                if (svdFile != null || registerModelReason == null
                        || registerModelReason.isBlank()) {
                    throw new IllegalArgumentException(
                        "An unavailable register model requires a reason and no file");
                }
            }
        }
    }

    /**
     * The radio subsystem of the die. Only the management classification and
     * the register-model availability are pinned; no radio register window,
     * protocol state, or firmware content is invented.
     */
    public record RadioSubsystem(Management management, RegisterModel registerModel,
            String registerModelReason) {
        public RadioSubsystem {
            Objects.requireNonNull(management, "management");
            Objects.requireNonNull(registerModel, "registerModel");
            if (registerModel == RegisterModel.SHIPPED) {
                if (registerModelReason != null) {
                    throw new IllegalArgumentException(
                        "A shipped radio register model carries no reason");
                }
            }
            else if (registerModelReason == null || registerModelReason.isBlank()) {
                throw new IllegalArgumentException(
                    "A deferred or unavailable radio register model requires a reason");
            }
        }
    }

    /**
     * Radio-to-CPU shared-resource attribution.
     *
     * <p>{@code SHARED_RESOURCES_IN_PINNED_WORKSPACE_PLAN} points at the T045
     * workspace that owns the pinned CPU1/CPU2 shared banks and the mailbox,
     * semaphore, and boot-order references. {@code UNAVAILABLE_NO_PINNED_
     * RADIO_MEMORY_ATTRIBUTION} records that no per-region radio sharing
     * exists in the pinned sources.</p>
     */
    public record SharedResources(State state, Stm32WorkspacePlan workspace) {
        /** Pinned shared-resource state; unattributed sharing stays explicit. */
        public enum State {
            SHARED_RESOURCES_IN_PINNED_WORKSPACE_PLAN,
            UNAVAILABLE_NO_PINNED_RADIO_MEMORY_ATTRIBUTION
        }

        public SharedResources {
            Objects.requireNonNull(state, "state");
            if (state == State.SHARED_RESOURCES_IN_PINNED_WORKSPACE_PLAN) {
                if (workspace == null || !workspace.pinned()) {
                    throw new IllegalArgumentException(
                        "Shared resources require a pinned workspace plan");
                }
            }
            else if (workspace != null) {
                throw new IllegalArgumentException(
                    "Unavailable shared resources carry no workspace plan");
            }
        }
    }

    /**
     * The network processor that hosts the radio stack and is fed by
     * separately supplied firmware.
     *
     * @param communicationRanges the pinned mailbox and semaphore windows
     */
    public record NetworkCore(CoreRole core, CoprocessorFirmware firmware,
            List<AddressRange> communicationRanges) {
        public NetworkCore {
            Objects.requireNonNull(core, "core");
            Objects.requireNonNull(firmware, "firmware");
            communicationRanges = List.copyOf(communicationRanges);
            if (core.firmwareSource() != FirmwareSource.INDEPENDENT_IMAGE) {
                throw new IllegalArgumentException(
                    "A network core requires the pinned independent-image relationship");
            }
            if (communicationRanges.isEmpty()) {
                throw new IllegalArgumentException(
                    "A network core requires pinned communication windows");
            }
            if (communicationRanges.stream().anyMatch(range -> range == null
                    || range.length() <= 0 || range.endExclusive() > 0x1_0000_0000L)) {
                throw new IllegalArgumentException(
                    "Communication windows must fit the 32-bit address space");
            }
            Set<AddressRange> unique = new HashSet<>(communicationRanges);
            if (unique.size() != communicationRanges.size()) {
                throw new IllegalArgumentException("Duplicate communication window");
            }
        }
    }

    /**
     * The independently supplied coprocessor firmware contract. The bytes are
     * never pinned, owned, or placed: the release and reset-vector fetch
     * basis stays the pinned configuration-dependent citation, and no image
     * range, size, or content is ever invented for the coprocessor domain.
     */
    public record CoprocessorFirmware(State state, Binding binding, String bindingMechanism,
            UnresolvedFetchView fetchView) {
        /** The firmware relationship of the separately supplied image domain. */
        public enum State {
            INDEPENDENTLY_SUPPLIED
        }

        /** The pinned binding state; configuration dependence is explicit. */
        public enum Binding {
            UNRESOLVED_CONFIGURATION_DEPENDENT
        }

        public CoprocessorFirmware {
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(binding, "binding");
            Objects.requireNonNull(bindingMechanism, "bindingMechanism");
            Objects.requireNonNull(fetchView, "fetchView");
            if (bindingMechanism.isBlank()) {
                throw new IllegalArgumentException("Binding mechanism is incomplete");
            }
        }
    }

    /**
     * The pinned configuration-dependent memory view: the C2OPT/SBRV-selected
     * CPU2 reset-vector fetch basis that T039 fixes as unresolved.
     */
    public record UnresolvedFetchView(String id, String reason) {
        public UnresolvedFetchView {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(reason, "reason");
            if (id.isBlank() || reason.isBlank()) {
                throw new IllegalArgumentException("Unresolved fetch-view identity is incomplete");
            }
        }
    }

    public Stm32WirelessRecord {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(series, "series");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(applicationCore, "applicationCore");
        Objects.requireNonNull(radioSubsystem, "radioSubsystem");
        Objects.requireNonNull(sharedResources, "sharedResources");
        Objects.requireNonNull(securityRecord, "securityRecord");
        evidence = List.copyOf(evidence);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Wireless record requires an exact part");
        }
        if (!securityRecord.exactPart().equals(exactPart)) {
            throw new IllegalArgumentException("Wireless record and security record parts "
                + "disagree: " + exactPart + ", " + securityRecord.exactPart());
        }
        if (applicationCore.firmwareSource() != FirmwareSource.SHARED_IMAGE) {
            throw new IllegalArgumentException(
                "The application core requires the pinned shared-image relationship");
        }
        if (evidence.isEmpty()) {
            throw new IllegalArgumentException("Wireless records require evidence");
        }
        if (status == Status.NETWORK_CORE_PINNED) {
            if (networkCore == null) {
                throw new IllegalArgumentException(
                    "A pinned network core is required for NETWORK_CORE_PINNED");
            }
            if (sharedResources.state() != SharedResources.State
                    .SHARED_RESOURCES_IN_PINNED_WORKSPACE_PLAN) {
                throw new IllegalArgumentException(
                    "Pinned network cores point at the pinned workspace shared resources");
            }
            if (radioSubsystem.management() != Management.NETWORK_CORE_MANAGED) {
                throw new IllegalArgumentException(
                    "A pinned network core manages the radio subsystem");
            }
        }
        else {
            if (networkCore != null) {
                throw new IllegalArgumentException(
                    "SINGLE_APPLICATION_CORE must not carry a network core");
            }
            if (sharedResources.state() != SharedResources.State
                    .UNAVAILABLE_NO_PINNED_RADIO_MEMORY_ATTRIBUTION) {
                throw new IllegalArgumentException(
                    "Single-application-core parts carry no pinned radio-to-CPU sharing");
            }
            if (radioSubsystem.management() != Management.APPLICATION_CORE_MANAGED) {
                throw new IllegalArgumentException(
                    "A single application core manages the radio subsystem");
            }
        }
    }

    /** True when this exact part has a pinned separately-programmable network core. */
    public boolean pinnedNetworkCore() {
        return status == Status.NETWORK_CORE_PINNED;
    }

    /** Every exact STM32 part remains PLANNED; wireless planning never promotes. */
    public String supportState() {
        return "PLANNED";
    }
}
