// Auto-labeler for ESP32 CTF Challenge
//@author Antigravity
//@category CTF.ESP32
//@keybinding 
//@menupath Tools.CTF.Label ESP32 Functions
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ESP32_CTF_AutoLabeler extends GhidraScript {

    private void labelFunc(long addrVal, String name, String comment) {
        try {
            Address addr = toAddr(addrVal);
            Function func = getFunctionAt(addr);
            if (func == null) {
                func = createFunction(addr, name);
            } else {
                func.setName(name, SourceType.USER_DEFINED);
            }
            if (comment != null) {
                setPlateComment(addr, comment);
            }
            println("[+] Function labeled: " + name + " @ 0x" + Long.toHexString(addrVal));
        } catch (Exception e) {
            println("[-] Could not label function at 0x" + Long.toHexString(addrVal) + ": " + e.getMessage());
        }
    }

    private void labelData(long addrVal, String name, String comment) {
        try {
            Address addr = toAddr(addrVal);
            createLabel(addr, name, true, SourceType.USER_DEFINED);
            if (comment != null) {
                setPlateComment(addr, comment);
            }
            println("[+] Data labeled: " + name + " @ 0x" + Long.toHexString(addrVal));
        } catch (Exception e) {
            println("[-] Could not label data at 0x" + Long.toHexString(addrVal) + ": " + e.getMessage());
        }
    }

    @Override
    public void run() throws Exception {
        println("=== Starting ESP32 CTF Auto-Labeler ===");

        // Arduino Core Functions
        labelFunc(0x42010f08L, "arduino_delay", "Standard Arduino delay(ms) using FreeRTOS vTaskDelay / esp_rom_delay");
        labelFunc(0x42005aacL, "arduino_digitalWrite", "Standard Arduino digitalWrite(pin, val) / GPIO buzzer/LED control");
        labelFunc(0x4200d928L, "String_append_cstr", "Arduino String::concat(const char*)");
        labelFunc(0x4200e800L, "String_append_String", "Arduino String::concat(const String&)");

        // WebServer Handlers
        labelFunc(0x42004538L, "handler_flag_siren", "WebServer route handler for /flag_siren");
        labelFunc(0x4200493cL, "handler_iran_flag", "WebServer route handler for /iran_flag");
        labelFunc(0x42004a34L, "handler_random", "WebServer route handler for /random");
        labelFunc(0x420045d0L, "handler_led", "WebServer route handler for /led");

        // CTF Flag Morse & Siren
        labelFunc(0x42004f94L, "send_flag_morse_siren", "Formats flag ASIS{...} and transmits it in Morse code via LED/Buzzer");

        // Cryptography & Data
        labelData(0x3c0c30ecL, "AES_KEY_128", "Hardcoded 128-bit AES Key: 20415978fe6fe72a21a5ddaa161f5a21 (' AYx\\xfeo\\xe7*!\\xa5\\xdd\\xaa\\x16\\x1fZ!')");
        labelData(0x3c0c308cL, "AES_CIPHERTEXT", "Encrypted AES-128 blocks -> Decrypts to:\n1) b1ts_0f_l1ght_:)\n2) u_d!d_!t_G0_@hed\n3) Elt3mas_d0a!!");
        labelData(0x3c0b050cL, "CRED_ADMIN_USER", "Hardcoded admin username: 'admin'");
        labelData(0x3c0b0524L, "CRED_ADMIN_PASS", "Hardcoded admin password: 'FreE_PaL3st!ne'");
        labelData(0x3c0b034fL, "MORSE_CODE_TABLE", "Morse code patterns for B, C, F, H, J, L, P, Q, V, X, Y, Z");
        labelData(0x3c0b03c8L, "FMT_FLAG_ASIS", "Flag format string: ASIS{%s}");
        labelData(0x3c0b04c7L, "FMT_WIFI_SSID", "AP SSID format: Hardware-CTF-%s");

        println("=== Auto-Labeling Finished Successfully! ===");
    }
}
