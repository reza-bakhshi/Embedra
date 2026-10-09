// Native Java FindCrypt for Ghidra (no PyGhidra required)
//@author Antigravity
//@category Crypto
//@keybinding 
//@menupath Tools.Crypto.FindCrypt (Java)
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;

public class FindCrypt extends GhidraScript {

    private static class CryptoSignature {
        String name;
        byte[] pattern;

        CryptoSignature(String name, byte[] pattern) {
            this.name = name;
            this.pattern = pattern;
        }
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    @Override
    public void run() throws Exception {
        println("=== Starting FindCrypt (Native Java) ===");

        List<CryptoSignature> sigs = new ArrayList<>();

        // AES S-Box (32 bytes prefix)
        sigs.add(new CryptoSignature("AES_SBox", hexToBytes(
            "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0"
        )));

        // AES Inverse S-Box (32 bytes prefix)
        sigs.add(new CryptoSignature("AES_InvSBox", hexToBytes(
            "52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb"
        )));

        // AES Rcon
        sigs.add(new CryptoSignature("AES_Rcon", hexToBytes(
            "00 00 00 00 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 10 00 00 00 20 00 00 00 40 00 00 00 80 00 00 00 1b 00 00 00 36 00 00 00"
        )));

        // AES Rcon (1-byte version)
        sigs.add(new CryptoSignature("AES_Rcon_byte", hexToBytes(
            "01 02 04 08 10 20 40 80 1b 36"
        )));

        // SHA-256 Initial Constants (H0-H7)
        sigs.add(new CryptoSignature("SHA256_Init", hexToBytes(
            "6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a 51 0e 52 7f 9b 05 68 8c 1f 83 d9 ab 5b e0 cd 19"
        )));

        // MD5 Constants
        sigs.add(new CryptoSignature("MD5_Init", hexToBytes(
            "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
        )));

        // CRC-32 (IEEE 802.3 table prefix)
        sigs.add(new CryptoSignature("CRC32_Table", hexToBytes(
            "00 00 00 00 96 30 07 77 2c 61 0e ee ba 51 09 99 19 c4 6d 07 8f f4 6a 70 35 a5 63 e9 a3 95 64 9e"
        )));

        Memory mem = currentProgram.getMemory();
        int foundCount = 0;

        for (CryptoSignature sig : sigs) {
            Address searchAddr = currentProgram.getMinAddress();
            while (searchAddr != null && !monitor.isCancelled()) {
                Address found = mem.findBytes(searchAddr, currentProgram.getMaxAddress(), sig.pattern, null, true, monitor);
                if (found != null) {
                    foundCount++;
                    String label = "CRYPT_" + sig.name + "_" + found;
                    createLabel(found, label, true, SourceType.USER_DEFINED);
                    createBookmark(found, "FindCrypt", "Identified cryptographic constant: " + sig.name);
                    println(String.format("[+] Found %-16s at 0x%s -> labeled as %s", sig.name, found, label));
                    searchAddr = found.add(sig.pattern.length);
                } else {
                    break;
                }
            }
        }

        println("=== FindCrypt Finished: " + foundCount + " cryptographic constants identified! ===");
    }
}
