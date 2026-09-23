package io.github.rezabakhshi.embedra.targets.esp.catalog;

/** Catalog ISA classification; PROFILE is never an executable processor ISA. */
public enum EspCpuIsa {
    XTENSA,
    RISCV,
    PROFILE
}
