package io.github.rezabakhshi.embedra.core.model;

import java.util.Objects;

/** Named security domain attached to processors and address-space ownership. */
public record SecurityDomain(String id, SecurityDomainKind kind) {
    public SecurityDomain {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        if (id.isBlank()) {
            throw new IllegalArgumentException("Security-domain ID must not be blank");
        }
    }

    public static SecurityDomain secure() {
        return new SecurityDomain("secure", SecurityDomainKind.SECURE);
    }

    public static SecurityDomain nonSecure() {
        return new SecurityDomain("non-secure", SecurityDomainKind.NON_SECURE);
    }

    public static SecurityDomain unknown() {
        return new SecurityDomain("unknown", SecurityDomainKind.UNKNOWN);
    }
}
