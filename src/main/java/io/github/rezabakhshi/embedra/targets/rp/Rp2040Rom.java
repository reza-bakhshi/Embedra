package io.github.rezabakhshi.embedra.targets.rp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Model of the RP2040 internal 16 KiB Mask ROM and its exported function table.
 */
public final class Rp2040Rom {

    public static final long ROM_BASE = 0x00000000L;

    public static final long ROM_SIZE = 16 * 1024L;

    public static final byte MAGIC_M = 0x4D;

    public static final byte MAGIC_U = 0x75;

    private static final Map<String, String> ROM_FUNCTIONS;

    static {
        Map<String, String> funcs = new LinkedHashMap<>();
        funcs.put("P3", "popcount32");
        funcs.put("R3", "reverse32");
        funcs.put("L3", "clz32");
        funcs.put("T3", "ctz32");
        funcs.put("MS", "memset");
        funcs.put("MC", "memcpy");
        funcs.put("RE", "flash_range_erase");
        funcs.put("RP", "flash_range_program");
        funcs.put("FC", "flash_flush_cache");
        funcs.put("CX", "flash_enter_cmd_xip");
        funcs.put("EX", "flash_exit_xip");
        funcs.put("IF", "flash_connect_internal");
        funcs.put("UB", "reset_to_usb_boot");
        ROM_FUNCTIONS = Collections.unmodifiableMap(funcs);
    }

    private Rp2040Rom() {
    }

    public static Map<String, String> exportedFunctions() {
        return ROM_FUNCTIONS;
    }

    public static Optional<String> functionName(String code) {
        return Optional.ofNullable(ROM_FUNCTIONS.get(code));
    }

    public static boolean containsAddress(long address) {
        return address >= ROM_BASE && address < ROM_BASE + ROM_SIZE;
    }
}
