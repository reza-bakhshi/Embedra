package io.github.rezabakhshi.embedra.pack;

import java.util.List;

/** One memory-mapped register address with all authoritative aliases. */
public record EspPeripheralRegister(
        long address,
        int widthBits,
        List<String> names,
        List<String> sourceFiles) {
    public EspPeripheralRegister {
        if (address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("Register address is not unsigned 32-bit");
        }
        if (widthBits != 32) {
            throw new IllegalArgumentException("Only authoritative 32-bit registers are supported");
        }
        names = List.copyOf(names);
        sourceFiles = List.copyOf(sourceFiles);
        if (names.isEmpty() || sourceFiles.isEmpty()) {
            throw new IllegalArgumentException("Register names and source files must not be empty");
        }
        names.forEach(name -> PackManifest.requireIdentifier(name, "register name"));
    }
}
