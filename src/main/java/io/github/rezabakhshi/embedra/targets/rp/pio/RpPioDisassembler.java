package io.github.rezabakhshi.embedra.targets.rp.pio;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * Pure 16-bit disassembler and instruction decoder for Raspberry Pi PIO state machines.
 */
public final class RpPioDisassembler {

    private RpPioDisassembler() {
    }

    /**
     * Decodes a single 16-bit PIO instruction with default unconfigured context.
     */
    public static RpPioInstruction decode(int rawWord) {
        return decode(rawWord, RpPioConfig.unconfigured());
    }

    /**
     * Decodes a single 16-bit PIO instruction under a specific PIO configuration context.
     */
    public static RpPioInstruction decode(int rawWord, RpPioConfig config) {
        Objects.requireNonNull(config, "config must not be null");
        int word = rawWord & 0xFFFF;
        int delaySide = (word >> 8) & 0x1F;

        boolean isDelaySideUncertain;
        OptionalInt delay;
        OptionalInt sideSet;

        if (!config.isSideSetKnown()) {
            isDelaySideUncertain = (delaySide != 0);
            delay = OptionalInt.empty();
            sideSet = OptionalInt.empty();
        } else {
            isDelaySideUncertain = false;
            int count = config.sideSetCount();
            int delayVal = delaySide & ((1 << (5 - count)) - 1);
            delay = OptionalInt.of(delayVal);

            if (count == 0) {
                sideSet = OptionalInt.empty();
            } else {
                int rawSide = delaySide >> (5 - count);
                if (config.sideSetOptional()) {
                    int enableBit = 1 << (count - 1);
                    if ((rawSide & enableBit) != 0) {
                        sideSet = OptionalInt.of(rawSide & (enableBit - 1));
                    } else {
                        sideSet = OptionalInt.empty();
                    }
                } else {
                    sideSet = OptionalInt.of(rawSide);
                }
            }
        }

        int op = (word >> 13) & 0x7;
        RpPioOpcode opcode;
        String mnemonic;
        String operands;

        switch (op) {
            case 0 -> { // JMP
                opcode = RpPioOpcode.JMP;
                mnemonic = "jmp";
                int condCode = (word >> 5) & 0x7;
                int addr = word & 0x1F;
                RpPioCondition cond = RpPioCondition.fromCode(condCode);
                if (cond == RpPioCondition.ALWAYS) {
                    operands = String.valueOf(addr);
                } else {
                    operands = cond.syntax() + ", " + addr;
                }
            }
            case 1 -> { // WAIT
                opcode = RpPioOpcode.WAIT;
                mnemonic = "wait";
                int pol = (word >> 7) & 0x1;
                int srcCode = (word >> 5) & 0x3;
                int idx = word & 0x1F;
                RpPioWaitSource src = RpPioWaitSource.fromCode(srcCode);
                if (src == RpPioWaitSource.IRQ) {
                    boolean rel = (idx & 0x10) != 0;
                    int irqIdx = idx & 0x7;
                    operands = pol + " irq " + irqIdx + (rel ? " rel" : "");
                } else {
                    operands = pol + " " + src.syntax() + " " + idx;
                }
            }
            case 2 -> { // IN
                opcode = RpPioOpcode.IN;
                mnemonic = "in";
                int srcCode = (word >> 5) & 0x7;
                int bitCount = word & 0x1F;
                if (bitCount == 0) {
                    bitCount = 32;
                }
                RpPioInSource src = RpPioInSource.fromCode(srcCode);
                operands = src.syntax() + ", " + bitCount;
            }
            case 3 -> { // OUT
                opcode = RpPioOpcode.OUT;
                mnemonic = "out";
                int dstCode = (word >> 5) & 0x7;
                int bitCount = word & 0x1F;
                if (bitCount == 0) {
                    bitCount = 32;
                }
                RpPioOutDestination dst = RpPioOutDestination.fromCode(dstCode);
                operands = dst.syntax() + ", " + bitCount;
            }
            case 4 -> { // PUSH / PULL
                boolean isPull = ((word >> 7) & 0x1) != 0;
                boolean ifCond = ((word >> 6) & 0x1) != 0;
                boolean block = ((word >> 5) & 0x1) != 0;
                if (isPull) {
                    opcode = RpPioOpcode.PULL;
                    mnemonic = "pull";
                    StringBuilder sb = new StringBuilder();
                    if (ifCond) {
                        sb.append("ifempty ");
                    }
                    sb.append(block ? "block" : "noblock");
                    operands = sb.toString();
                } else {
                    opcode = RpPioOpcode.PUSH;
                    mnemonic = "push";
                    StringBuilder sb = new StringBuilder();
                    if (ifCond) {
                        sb.append("iffull ");
                    }
                    sb.append(block ? "block" : "noblock");
                    operands = sb.toString();
                }
            }
            case 5 -> { // MOV
                opcode = RpPioOpcode.MOV;
                mnemonic = "mov";
                int dstCode = (word >> 5) & 0x7;
                int opCode = (word >> 3) & 0x3;
                int srcCode = word & 0x7;
                RpPioMovDestination dst = RpPioMovDestination.fromCode(dstCode);
                RpPioMovOperation movOp = RpPioMovOperation.fromCode(opCode);
                RpPioMovSource src = RpPioMovSource.fromCode(srcCode);
                operands = dst.syntax() + ", " + movOp.prefix() + src.syntax();
            }
            case 6 -> { // IRQ
                opcode = RpPioOpcode.IRQ;
                mnemonic = "irq";
                boolean clr = ((word >> 6) & 0x1) != 0;
                boolean wait = ((word >> 5) & 0x1) != 0;
                boolean rel = ((word >> 4) & 0x1) != 0;
                int idx = word & 0x7;
                StringBuilder sb = new StringBuilder();
                if (clr && wait) {
                    sb.append("clear wait ");
                } else if (clr) {
                    sb.append("clear ");
                } else if (wait) {
                    sb.append("wait ");
                } else {
                    sb.append("set ");
                }
                sb.append(idx);
                if (rel) {
                    sb.append(" rel");
                }
                operands = sb.toString();
            }
            case 7 -> { // SET
                opcode = RpPioOpcode.SET;
                mnemonic = "set";
                int dstCode = (word >> 5) & 0x7;
                int data = word & 0x1F;
                RpPioSetDestination dst = RpPioSetDestination.fromCode(dstCode);
                operands = dst.syntax() + ", " + data;
            }
            default -> throw new IllegalStateException("Unreachable opcode: " + op);
        }

        return new RpPioInstruction(
                word, opcode, mnemonic, operands, delay, sideSet, isDelaySideUncertain, delaySide);
    }

    /**
     * Disassembles a 16-bit word to an assembly string with default configuration.
     */
    public static String disassemble(int rawWord) {
        return decode(rawWord).toAssemblyString();
    }

    /**
     * Disassembles a 16-bit word to an assembly string with explicit configuration.
     */
    public static String disassemble(int rawWord, RpPioConfig config) {
        return decode(rawWord, config).toAssemblyString();
    }

    /**
     * Validates whether a 16-bit word is a structurally valid PIO instruction (not reserved bits).
     */
    public static boolean isValidInstruction(int rawWord) {
        int word = rawWord & 0xFFFF;
        int op = (word >> 13) & 0x7;

        switch (op) {
            case 0 -> { // JMP
                return true;
            }
            case 1 -> { // WAIT
                int srcCode = (word >> 5) & 0x3;
                return srcCode != 3; // 3 is reserved
            }
            case 2 -> { // IN
                int srcCode = (word >> 5) & 0x7;
                return srcCode != 4; // 4 is reserved
            }
            case 3 -> { // OUT
                return true; // all destinations 0..7 are valid
            }
            case 4 -> { // PUSH / PULL
                return (word & 0x1F) == 0; // bits 4:0 should be 0
            }
            case 5 -> { // MOV
                int dstCode = (word >> 5) & 0x7;
                int opCode = (word >> 3) & 0x3;
                int srcCode = word & 0x7;
                return dstCode != 3 && opCode != 3 && srcCode != 4;
            }
            case 6 -> { // IRQ
                return ((word >> 7) & 0x1) == 0 && ((word >> 3) & 0x1) == 0; // bits 7 and 3 reserved 0
            }
            case 7 -> { // SET
                int dstCode = (word >> 5) & 0x7;
                return dstCode == 0 || dstCode == 1 || dstCode == 2 || dstCode == 4;
            }
            default -> {
                return false;
            }
        }
    }

    /**
     * Disassembles an array of 16-bit words.
     */
    public static List<RpPioInstruction> disassembleProgram(short[] words, RpPioConfig config) {
        Objects.requireNonNull(words, "words must not be null");
        List<RpPioInstruction> result = new ArrayList<>(words.length);
        for (short w : words) {
            result.add(decode(Short.toUnsignedInt(w), config));
        }
        return List.copyOf(result);
    }

    /**
     * Disassembles a sequence of 16-bit words from a byte array.
     */
    public static List<RpPioInstruction> disassembleProgram(
            byte[] data, int offset, int lengthWords, RpPioConfig config) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        if (offset < 0 || lengthWords <= 0 || offset + (lengthWords * 2) > data.length) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.READ_OUT_OF_BOUNDS,
                    "PIO instruction range [offset=" + offset + ", words=" + lengthWords + "] exceeds data bounds"));
        }
        ByteBuffer buf = ByteBuffer.wrap(data, offset, lengthWords * 2).order(ByteOrder.LITTLE_ENDIAN);
        List<RpPioInstruction> result = new ArrayList<>(lengthWords);
        for (int i = 0; i < lengthWords; i++) {
            int w = Short.toUnsignedInt(buf.getShort());
            result.add(decode(w, config));
        }
        return List.copyOf(result);
    }
}
