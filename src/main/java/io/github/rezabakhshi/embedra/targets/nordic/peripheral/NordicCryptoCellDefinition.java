package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.ArrayList;
import java.util.List;

/**
 * Authoritative hardware peripheral register definitions for Arm CryptoCell CC310 (nRF52840)
 * and CryptoCell CC312 (nRF5340 / nRF9160) crypto accelerators.
 */
public final class NordicCryptoCellDefinition {

    public static final long CC310_BASE = 0x5002A000L;

    public static final long CC310_SIZE = 0x00001000L; // 4 KiB register aperture

    public static final long CC310_END = CC310_BASE + CC310_SIZE;

    public static final long CC312_BASE = 0x50840000L;

    public static final long CC312_SIZE = 0x00001000L; // 4 KiB register aperture

    public static final long CC312_END = CC312_BASE + CC312_SIZE;

    private NordicCryptoCellDefinition() {
    }

    public static NordicPeripheral createCc310Peripheral() {
        List<NordicRegister> regs = new ArrayList<>();

        // Host Control Registers
        regs.add(new NordicRegister(
            "HOST_RGF_ENDIAN", CC310_BASE + 0x430L, 0x430L, 32, "Host Endianness Control",
            List.of(NordicBitField.singleBit("ENDIAN", 0, "R/W", "Little endian (0) / Big endian (1)"))));
        regs.add(new NordicRegister(
            "HOST_CRYPTOKEY_SEL", CC310_BASE + 0x438L, 0x438L, 32, "Hardware Crypto Key Selection",
            List.of(new NordicBitField("KEY_SEL", 0, 2, 0x03L, "R/W", "0=KDR root key, 1=Session key, 2=Kce key"))));
        regs.add(new NordicRegister(
            "HOST_IOT_ARM_CC310_BASE", CC310_BASE + 0x440L, 0x440L, 32, "CC310 Hardware Base Address", List.of()));
        regs.add(new NordicRegister(
            "HOST_AO_LOCK", CC310_BASE + 0x444L, 0x444L, 32, "Always-On Secure Lock Register",
            List.of(NordicBitField.singleBit("LOCK", 0, "R/W", "Secure lock active"))));
        regs.add(new NordicRegister(
            "HOST_ENG_RST", CC310_BASE + 0x448L, 0x448L, 32, "Crypto Engine Reset",
            List.of(NordicBitField.singleBit("RESET", 0, "W", "Assert engine soft reset"))));
        regs.add(new NordicRegister(
            "HOST_IRR", CC310_BASE + 0x44CL, 0x44CL, 32, "Interrupt Raw Status",
            List.of(NordicBitField.singleBit("AES_INT", 0, "R", "AES interrupt active"),
                    NordicBitField.singleBit("HASH_INT", 1, "R", "Hash interrupt active"),
                    NordicBitField.singleBit("PKA_INT", 2, "R", "PKA interrupt active"),
                    NordicBitField.singleBit("RNG_INT", 3, "R", "TRNG interrupt active"))));
        regs.add(new NordicRegister(
            "HOST_IMR", CC310_BASE + 0x450L, 0x450L, 32, "Interrupt Mask",
            List.of(NordicBitField.singleBit("AES_MASK", 0, "R/W", "AES interrupt mask"),
                    NordicBitField.singleBit("HASH_MASK", 1, "R/W", "Hash interrupt mask"),
                    NordicBitField.singleBit("PKA_MASK", 2, "R/W", "PKA interrupt mask"),
                    NordicBitField.singleBit("RNG_MASK", 3, "R/W", "TRNG interrupt mask"))));
        regs.add(new NordicRegister(
            "HOST_ICR", CC310_BASE + 0x454L, 0x454L, 32, "Interrupt Clear",
            List.of(NordicBitField.singleBit("AES_CLR", 0, "W", "Clear AES interrupt"),
                    NordicBitField.singleBit("HASH_CLR", 1, "W", "Clear Hash interrupt"),
                    NordicBitField.singleBit("PKA_CLR", 2, "W", "Clear PKA interrupt"),
                    NordicBitField.singleBit("RNG_CLR", 3, "W", "Clear TRNG interrupt"))));

        // Symmetric Cipher Engine: AES
        regs.add(new NordicRegister(
            "AES_CONTROL", CC310_BASE + 0x600L, 0x600L, 32, "AES Engine Control",
            List.of(NordicBitField.singleBit("DEC_KEY", 0, "R/W", "0=Encrypt, 1=Decrypt"),
                    new NordicBitField("KEY_SIZE", 1, 2, 0x06L, "R/W", "0=128-bit, 1=192-bit, 2=256-bit"),
                    new NordicBitField("MODE", 3, 3, 0x38L, "R/W",
                        "0=ECB, 1=CBC, 2=CTR, 3=XTS, 4=CBC-MAC, 5=CMAC"))));
        for (int i = 0; i < 8; i++) {
            regs.add(new NordicRegister("AES_KEY_" + i, CC310_BASE + 0x604L + (i * 4L), 0x604L + (i * 4L), 32,
                "AES Key Word " + i, List.of()));
        }
        for (int i = 0; i < 4; i++) {
            regs.add(new NordicRegister("AES_IV_" + i, CC310_BASE + 0x624L + (i * 4L), 0x624L + (i * 4L), 32,
                "AES Initialization Vector Word " + i, List.of()));
        }

        // Hash Engine: SHA-1 / SHA-224 / SHA-256
        regs.add(new NordicRegister(
            "HASH_CONTROL", CC310_BASE + 0x640L, 0x640L, 32, "Hash Engine Control",
            List.of(new NordicBitField("HASH_MODE", 0, 3, 0x07L, "R/W", "0=SHA1, 1=SHA256, 2=SHA224"))));
        regs.add(new NordicRegister(
            "HASH_PAD", CC310_BASE + 0x644L, 0x644L, 32, "Hash Auto-Padding Control",
            List.of(NordicBitField.singleBit("AUTO_PAD", 0, "R/W", "Enable hardware SHA auto-padding"))));
        for (int i = 0; i < 8; i++) {
            regs.add(new NordicRegister("HASH_DIGEST_" + i, CC310_BASE + 0x648L + (i * 4L), 0x648L + (i * 4L), 32,
                "Hash Digest Output Word " + i, List.of()));
        }

        // Asymmetric Engine: PKA
        regs.add(new NordicRegister(
            "PKA_CONTROL", CC310_BASE + 0x700L, 0x700L, 32, "PKA Arithmetic Engine Control",
            List.of(NordicBitField.singleBit("START", 0, "W", "Start PKA operation"),
                    new NordicBitField("OPCODE", 1, 6, 0x7EL, "R/W", "PKA mathematical microcode opcode"))));
        regs.add(new NordicRegister(
            "PKA_STATUS", CC310_BASE + 0x704L, 0x704L, 32, "PKA Engine Status",
            List.of(NordicBitField.singleBit("BUSY", 0, "R", "PKA operation in progress"),
                    NordicBitField.singleBit("ALU_OUT_ZERO", 1, "R", "ALU result zero flag"))));

        // Hardware True RNG
        regs.add(new NordicRegister(
            "TRNG_CONTROL", CC310_BASE + 0x800L, 0x800L, 32, "Hardware TRNG Entropy Control",
            List.of(NordicBitField.singleBit("ENABLE", 0, "R/W", "Enable TRNG entropy oscillators"))));
        regs.add(new NordicRegister(
            "TRNG_SAMPLE_CNT", CC310_BASE + 0x804L, 0x804L, 32, "TRNG Sample Count", List.of()));

        return new NordicPeripheral(
            "CRYPTOCELL_CC310",
            CC310_BASE,
            CC310_END,
            "Arm CryptoCell CC310 Hardware Cryptographic Accelerator (nRF52840)",
            regs
        );
    }

    public static NordicPeripheral createCc312Peripheral() {
        List<NordicRegister> regs = new ArrayList<>();

        // Host Control Registers
        regs.add(new NordicRegister(
            "HOST_RGF_ENDIAN", CC312_BASE + 0x430L, 0x430L, 32, "Host Endianness Control",
            List.of(NordicBitField.singleBit("ENDIAN", 0, "R/W", "Little endian (0) / Big endian (1)"))));
        regs.add(new NordicRegister(
            "HOST_CRYPTOKEY_SEL", CC312_BASE + 0x438L, 0x438L, 32, "Hardware Crypto Key Selection",
            List.of(new NordicBitField("KEY_SEL", 0, 2, 0x03L, "R/W", "0=HUK key, 1=Session key, 2=Kce key"))));
        regs.add(new NordicRegister(
            "HOST_AO_LOCK", CC312_BASE + 0x444L, 0x444L, 32, "Always-On Secure Lock Register",
            List.of(NordicBitField.singleBit("LOCK", 0, "R/W", "Secure lock active"))));
        regs.add(new NordicRegister(
            "HOST_ENG_RST", CC312_BASE + 0x448L, 0x448L, 32, "Crypto Engine Reset",
            List.of(NordicBitField.singleBit("RESET", 0, "W", "Assert engine soft reset"))));
        regs.add(new NordicRegister(
            "HOST_IRR", CC312_BASE + 0x44CL, 0x44CL, 32, "Interrupt Raw Status",
            List.of(NordicBitField.singleBit("AES_INT", 0, "R", "AES interrupt active"),
                    NordicBitField.singleBit("HASH_INT", 1, "R", "Hash interrupt active"),
                    NordicBitField.singleBit("PKA_INT", 2, "R", "PKA interrupt active"),
                    NordicBitField.singleBit("RNG_INT", 3, "R", "TRNG interrupt active"))));
        regs.add(new NordicRegister(
            "HOST_IMR", CC312_BASE + 0x450L, 0x450L, 32, "Interrupt Mask",
            List.of(NordicBitField.singleBit("AES_MASK", 0, "R/W", "AES interrupt mask"),
                    NordicBitField.singleBit("HASH_MASK", 1, "R/W", "Hash interrupt mask"),
                    NordicBitField.singleBit("PKA_MASK", 2, "R/W", "PKA interrupt mask"),
                    NordicBitField.singleBit("RNG_MASK", 3, "R/W", "TRNG interrupt mask"))));
        regs.add(new NordicRegister(
            "HOST_ICR", CC312_BASE + 0x454L, 0x454L, 32, "Interrupt Clear",
            List.of(NordicBitField.singleBit("AES_CLR", 0, "W", "Clear AES interrupt"),
                    NordicBitField.singleBit("HASH_CLR", 1, "W", "Clear Hash interrupt"),
                    NordicBitField.singleBit("PKA_CLR", 2, "W", "Clear PKA interrupt"),
                    NordicBitField.singleBit("RNG_CLR", 3, "W", "Clear TRNG interrupt"))));

        // Symmetric Cipher: AES / ChaCha20 / SM4
        regs.add(new NordicRegister(
            "AES_CONTROL", CC312_BASE + 0x600L, 0x600L, 32, "AES / ChaCha Engine Control",
            List.of(NordicBitField.singleBit("DEC_KEY", 0, "R/W", "0=Encrypt, 1=Decrypt"),
                    new NordicBitField("CIPHER_MODE", 1, 3, 0x0EL, "R/W",
                        "0=ECB, 1=CBC, 2=CTR, 3=CCM, 4=GCM, 5=ChaCha20"))));
        regs.add(new NordicRegister(
            "AES_BUSY", CC312_BASE + 0x604L, 0x604L, 32, "AES Engine Busy Status",
            List.of(NordicBitField.singleBit("BUSY", 0, "R", "Engine busy"))));
        for (int i = 0; i < 8; i++) {
            regs.add(new NordicRegister("AES_KEY_" + i, CC312_BASE + 0x608L + (i * 4L), 0x608L + (i * 4L), 32,
                "AES/ChaCha Key Word " + i, List.of()));
        }
        for (int i = 0; i < 4; i++) {
            regs.add(new NordicRegister("AES_IV_" + i, CC312_BASE + 0x628L + (i * 4L), 0x628L + (i * 4L), 32,
                "AES/ChaCha IV Word " + i, List.of()));
        }

        // Hash Engine: SHA-2 / SM3
        regs.add(new NordicRegister(
            "HASH_CONTROL", CC312_BASE + 0x640L, 0x640L, 32, "Hash Engine Control",
            List.of(new NordicBitField("HASH_MODE", 0, 3, 0x07L, "R/W",
                "0=SHA1, 1=SHA256, 2=SHA224, 3=SHA512, 4=SM3"))));
        regs.add(new NordicRegister(
            "HASH_PAD", CC312_BASE + 0x644L, 0x644L, 32, "Hash Auto-Padding Control",
            List.of(NordicBitField.singleBit("AUTO_PAD", 0, "R/W", "Enable hardware SHA auto-padding"))));
        for (int i = 0; i < 8; i++) {
            regs.add(new NordicRegister("HASH_DIGEST_" + i, CC312_BASE + 0x648L + (i * 4L), 0x648L + (i * 4L), 32,
                "Hash Digest Output Word " + i, List.of()));
        }

        // Asymmetric Engine: PKA
        regs.add(new NordicRegister(
            "PKA_CONTROL", CC312_BASE + 0x700L, 0x700L, 32, "PKA Arithmetic Engine Control",
            List.of(NordicBitField.singleBit("START", 0, "W", "Start PKA operation"),
                    new NordicBitField("OPCODE", 1, 6, 0x7EL, "R/W", "PKA mathematical microcode opcode"))));
        regs.add(new NordicRegister(
            "PKA_STATUS", CC312_BASE + 0x704L, 0x704L, 32, "PKA Engine Status",
            List.of(NordicBitField.singleBit("BUSY", 0, "R", "PKA operation in progress"))));

        // Hardware True RNG
        regs.add(new NordicRegister(
            "TRNG_CONTROL", CC312_BASE + 0x800L, 0x800L, 32, "Hardware TRNG Entropy Control",
            List.of(NordicBitField.singleBit("ENABLE", 0, "R/W", "Enable TRNG entropy oscillators"))));
        regs.add(new NordicRegister(
            "TRNG_SAMPLE_CNT", CC312_BASE + 0x804L, 0x804L, 32, "TRNG Sample Count", List.of()));

        return new NordicPeripheral(
            "CRYPTOCELL_CC312",
            CC312_BASE,
            CC312_END,
            "Arm CryptoCell CC312 Hardware Cryptographic Accelerator (nRF5340 / nRF9160)",
            regs
        );
    }
}
