package io.github.rezabakhshi.embedra.targets.stm32.security;

/**
 * Explicit Armv8-M security attribution of one alias view or boundary.
 *
 * <p>The attribute never describes a runtime partition: a {@code SECURE} alias
 * aperture is the architecturally fixed secure address view of a bank whose
 * secure/non-secure partition remains configuration-dependent until an
 * explicit configuration input resolves it.</p>
 */
public enum Stm32SecurityAttribute {
    SECURE,
    NON_SECURE,
    NON_SECURE_CALLABLE
}
