package io.github.rezabakhshi.embedra.targets.stm32.security;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable TrustZone record for one exact curated part.
 *
 * <p>A pinned record carries at least one secure alias aperture and its pinned
 * header provenance. A part with no pinned alias evidence stays explicitly
 * {@code UNAVAILABLE} with a reason and no windows: the model never promotes
 * architectural capability from a core, family, or sibling part.</p>
 */
public record Stm32SecurityRecord(
        String exactPart,
        Status status,
        String reason,
        List<Stm32SecurityHeaderSource> sourceHeaders,
        List<Stm32SecurityWindow> windows,
        List<UnresolvedAlias> unresolvedAliasSymbols,
        NscBoundary nonSecureCallable,
        VeneerEvidence veneerEvidence) {

    /** Exact-part evidence state; unavailable facts stay explicit. */
    public enum Status {
        ALIAS_VIEWS_PINNED, UNAVAILABLE
    }

    /** Whether a reviewed fact is pinned or unavailable with a reason. */
    public enum EvidenceState {
        UNAVAILABLE, PINNED
    }

    /** A pinned secure-alias symbol that has no reviewed T039 pair yet. */
    public record UnresolvedAlias(String symbol, String reason) {
        public UnresolvedAlias {
            Objects.requireNonNull(symbol, "symbol");
            Objects.requireNonNull(reason, "reason");
            if (symbol.isBlank() || reason.isBlank()) {
                throw new IllegalArgumentException("Unresolved alias identity is incomplete");
            }
        }
    }

    /** Non-secure-callable boundary state; configuration dependence is explicit. */
    public record NscBoundary(EvidenceState status, String reason,
            List<String> configurationEvidence) {
        public NscBoundary {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(reason, "reason");
            configurationEvidence = List.copyOf(configurationEvidence);
            if (reason.isBlank()) {
                throw new IllegalArgumentException("NSC boundary reason is blank");
            }
            if (configurationEvidence.stream()
                    .anyMatch(entry -> entry == null || entry.isBlank())) {
                throw new IllegalArgumentException("NSC configuration evidence is blank");
            }
        }
    }

    /** Veneer evidence; transitions require an explicit non-empty state. */
    public record VeneerEvidence(EvidenceState status, String reason,
            SecureFaultException secureFaultException,
            List<Stm32VeneerTransition> transitions) {
        public VeneerEvidence {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(reason, "reason");
            transitions = List.copyOf(transitions);
            if (reason.isBlank()) {
                throw new IllegalArgumentException("Veneer evidence reason is blank");
            }
            if (status == EvidenceState.UNAVAILABLE && !transitions.isEmpty()) {
                throw new IllegalArgumentException(
                    "Unavailable veneer evidence must not carry transitions");
            }
        }
    }

    /** The pinned Armv8-M SecureFault exception, or null when not evidence-backed. */
    public record SecureFaultException(String name, int number) {
        public SecureFaultException {
            Objects.requireNonNull(name, "name");
            if (name.isBlank() || number >= 0) {
                throw new IllegalArgumentException("SecureFault exception is invalid");
            }
        }
    }

    public Stm32SecurityRecord {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(nonSecureCallable, "nonSecureCallable");
        Objects.requireNonNull(veneerEvidence, "veneerEvidence");
        sourceHeaders = List.copyOf(sourceHeaders);
        windows = List.copyOf(windows);
        unresolvedAliasSymbols = List.copyOf(unresolvedAliasSymbols);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Security record requires an exact part");
        }
        if (sourceHeaders.isEmpty()) {
            throw new IllegalArgumentException("Security record requires pinned sources");
        }
        Set<String> headerPaths = new HashSet<>();
        for (Stm32SecurityHeaderSource header : sourceHeaders) {
            if (!headerPaths.add(header.path())) {
                throw new IllegalArgumentException("Duplicate security header source");
            }
        }
        Set<String> windowIds = new HashSet<>();
        boolean secureWindow = false;
        for (Stm32SecurityWindow window : windows) {
            if (!windowIds.add(window.id())) {
                throw new IllegalArgumentException("Duplicate security window id");
            }
            if (!headerPaths.contains(window.headerPath())) {
                throw new IllegalArgumentException(
                    "Security window does not cite a pinned header source");
            }
            secureWindow |= window.attribute() == Stm32SecurityAttribute.SECURE;
        }
        for (int left = 0; left < windows.size(); left++) {
            for (int right = left + 1; right < windows.size(); right++) {
                Stm32SecurityWindow first = windows.get(left);
                Stm32SecurityWindow second = windows.get(right);
                if (first.boundaryKind() == Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE
                        && second.boundaryKind()
                            == Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE
                        && first.range().overlaps(second.range())) {
                    throw new IllegalArgumentException("Overlapping security alias apertures");
                }
            }
        }
        Set<String> unresolved = new HashSet<>();
        for (UnresolvedAlias alias : unresolvedAliasSymbols) {
            if (!unresolved.add(alias.symbol())) {
                throw new IllegalArgumentException("Duplicate unresolved alias symbol");
            }
        }
        if (status == Status.ALIAS_VIEWS_PINNED) {
            if (reason != null) {
                throw new IllegalArgumentException("A pinned record must not carry a reason");
            }
            if (!secureWindow) {
                throw new IllegalArgumentException(
                    "A pinned record requires at least one secure alias aperture");
            }
        }
        else {
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("An unavailable record requires a reason");
            }
            if (!windows.isEmpty() || !unresolvedAliasSymbols.isEmpty()
                    || !veneerEvidence.transitions().isEmpty()) {
                throw new IllegalArgumentException(
                    "An unavailable record must not carry windows or veneers");
            }
            if (nonSecureCallable.status() != EvidenceState.UNAVAILABLE) {
                throw new IllegalArgumentException(
                    "An unavailable record cannot pin an NSC boundary");
            }
        }
        for (Stm32VeneerTransition transition : veneerEvidence.transitions()) {
            boolean covered = windows.stream()
                .anyMatch(window -> window.attribute()
                        == Stm32SecurityAttribute.NON_SECURE_CALLABLE
                    && window.covers(transition.nscRange()));
            if (!covered) {
                throw new IllegalArgumentException(
                    "Veneer transition is not inside a non-secure-callable window");
            }
        }
    }

    /** True when this exact part has pinned alias-view evidence. */
    public boolean pinned() {
        return status == Status.ALIAS_VIEWS_PINNED;
    }
}
