package io.github.rezabakhshi.embedra.analyzers.strings.stack;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Pure instruction model representing a disassembled instruction and its operands.
 *
 * @param address instruction address in memory
 * @param mnemonic operation mnemonic (e.g. "movs", "strb", "li", "sw", "s8i")
 * @param operands list of string representations of operands
 * @param architecture target instruction set architecture
 */
public record StackInstruction(
        long address,
        String mnemonic,
        List<String> operands,
        InstructionArch architecture) {

    public StackInstruction {
        if (address < 0) {
            throw new IllegalArgumentException("Instruction address must not be negative");
        }
        Objects.requireNonNull(mnemonic, "mnemonic must not be null");
        if (mnemonic.isBlank()) {
            throw new IllegalArgumentException("Mnemonic must not be blank");
        }
        mnemonic = mnemonic.trim().toLowerCase(Locale.ROOT);
        Objects.requireNonNull(operands, "operands must not be null");
        operands = List.copyOf(operands);
        Objects.requireNonNull(architecture, "architecture must not be null");
    }

    public static StackInstruction arm(long address, String mnemonic, String... operands) {
        return new StackInstruction(address, mnemonic, List.of(operands), InstructionArch.ARM_THUMB);
    }

    public static StackInstruction riscv(long address, String mnemonic, String... operands) {
        return new StackInstruction(address, mnemonic, List.of(operands), InstructionArch.RISCV32);
    }

    public static StackInstruction xtensa(long address, String mnemonic, String... operands) {
        return new StackInstruction(address, mnemonic, List.of(operands), InstructionArch.XTENSA);
    }

    /**
     * Parses an assembly line into a StackInstruction.
     */
    public static StackInstruction parse(long address, String line, InstructionArch arch) {
        Objects.requireNonNull(line, "line must not be null");
        String trimmed = line.trim();
        int firstSpace = trimmed.indexOf(' ');
        if (firstSpace < 0) {
            firstSpace = trimmed.indexOf('\t');
        }
        if (firstSpace < 0) {
            return new StackInstruction(address, trimmed, List.of(), arch);
        }
        String mnemonic = trimmed.substring(0, firstSpace).trim();
        String operandsPart = trimmed.substring(firstSpace + 1).trim();

        List<String> operands = splitOperands(operandsPart);
        return new StackInstruction(address, mnemonic, operands, arch);
    }

    private static List<String> splitOperands(String text) {
        List<String> result = new ArrayList<>();
        if (text.isBlank()) {
            return result;
        }

        StringBuilder current = new StringBuilder();
        int bracketDepth = 0;
        int parenDepth = 0;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '[') {
                bracketDepth++;
            } else if (c == ']') {
                bracketDepth--;
            } else if (c == '(') {
                parenDepth++;
            } else if (c == ')') {
                parenDepth--;
            }

            if (c == ',' && bracketDepth == 0 && parenDepth == 0) {
                String op = current.toString().trim();
                if (!op.isEmpty()) {
                    result.add(op);
                }
                current.setLength(0);
            } else {
                current.append(c);
            }
        }

        String last = current.toString().trim();
        if (!last.isEmpty()) {
            result.add(last);
        }
        return result;
    }
}
