package io.github.rezabakhshi.embedra.targets.rp.pio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.OptionalInt;
import org.junit.jupiter.api.Test;

public class RpPioDisassemblerTest {

    @Test
    void testDisassembleJmpConditions() {
        // Unconditional JMP to 0: 0x0000 -> "jmp 0"
        assertEquals("jmp 0", RpPioDisassembler.disassemble(0x0000));
        assertEquals("jmp 15", RpPioDisassembler.disassemble(0x000F));

        // JMP !x, 4: (0b000 << 13) | (0b001 << 5) | 4 = 0x0024
        assertEquals("jmp !x, 4", RpPioDisassembler.disassemble(0x0024));

        // JMP x--, 8: (0b000 << 13) | (0b010 << 5) | 8 = 0x0048
        assertEquals("jmp x--, 8", RpPioDisassembler.disassemble(0x0048));

        // JMP !y, 12: (0b000 << 13) | (0b011 << 5) | 12 = 0x006C
        assertEquals("jmp !y, 12", RpPioDisassembler.disassemble(0x006C));

        // JMP y--, 16: (0b000 << 13) | (0b100 << 5) | 16 = 0x0090
        assertEquals("jmp y--, 16", RpPioDisassembler.disassemble(0x0090));

        // JMP x!=y, 20: (0b000 << 13) | (0b101 << 5) | 20 = 0x00B4
        assertEquals("jmp x!=y, 20", RpPioDisassembler.disassemble(0x00B4));

        // JMP pin, 24: (0b000 << 13) | (0b110 << 5) | 24 = 0x00D8
        assertEquals("jmp pin, 24", RpPioDisassembler.disassemble(0x00D8));

        // JMP !osre, 28: (0b000 << 13) | (0b111 << 5) | 28 = 0x00FC
        assertEquals("jmp !osre, 28", RpPioDisassembler.disassemble(0x00FC));
    }

    @Test
    void testDisassembleWaitSources() {
        // WAIT 1 gpio 15: (0b001 << 13) | (1 << 7) | (0b00 << 5) | 15 = 0x208F
        assertEquals("wait 1 gpio 15", RpPioDisassembler.disassemble(0x208F));

        // WAIT 0 pin 7: (0b001 << 13) | (0 << 7) | (0b01 << 5) | 7 = 0x2027
        assertEquals("wait 0 pin 7", RpPioDisassembler.disassemble(0x2027));

        // WAIT 1 irq 3: (0b001 << 13) | (1 << 7) | (0b10 << 5) | 3 = 0x20C3
        assertEquals("wait 1 irq 3", RpPioDisassembler.disassemble(0x20C3));

        // WAIT 0 irq 4 rel: (0b001 << 13) | (0 << 7) | (0b10 << 5) | 0x14 = 0x2054
        assertEquals("wait 0 irq 4 rel", RpPioDisassembler.disassemble(0x2054));
    }

    @Test
    void testDisassembleInSourcesAndCounts() {
        // IN pins, 8: (0b010 << 13) | (0b000 << 5) | 8 = 0x4008
        assertEquals("in pins, 8", RpPioDisassembler.disassemble(0x4008));

        // IN x, 32 (count 0 encodes 32): (0b010 << 13) | (0b001 << 5) | 0 = 0x4020
        assertEquals("in x, 32", RpPioDisassembler.disassemble(0x4020));

        // IN y, 16: (0b010 << 13) | (0b010 << 5) | 16 = 0x4050
        assertEquals("in y, 16", RpPioDisassembler.disassemble(0x4050));

        // IN null, 4: (0b010 << 13) | (0b011 << 5) | 4 = 0x4064
        assertEquals("in null, 4", RpPioDisassembler.disassemble(0x4064));

        // IN isr, 1: (0b010 << 13) | (0b110 << 5) | 1 = 0x40C1
        assertEquals("in isr, 1", RpPioDisassembler.disassemble(0x40C1));

        // IN osr, 2: (0b010 << 13) | (0b111 << 5) | 2 = 0x40E2
        assertEquals("in osr, 2", RpPioDisassembler.disassemble(0x40E2));
    }

    @Test
    void testDisassembleOutDestinations() {
        // OUT pins, 8: (0b011 << 13) | (0b000 << 5) | 8 = 0x6008
        assertEquals("out pins, 8", RpPioDisassembler.disassemble(0x6008));

        // OUT x, 1: (0b011 << 13) | (0b001 << 5) | 1 = 0x6021
        assertEquals("out x, 1", RpPioDisassembler.disassemble(0x6021));

        // OUT y, 32: (0b011 << 13) | (0b010 << 5) | 0 = 0x6040
        assertEquals("out y, 32", RpPioDisassembler.disassemble(0x6040));

        // OUT null, 5: (0b011 << 13) | (0b011 << 5) | 5 = 0x6065
        assertEquals("out null, 5", RpPioDisassembler.disassemble(0x6065));

        // OUT pindirs, 4: (0b011 << 13) | (0b100 << 5) | 4 = 0x6084
        assertEquals("out pindirs, 4", RpPioDisassembler.disassemble(0x6084));

        // OUT pc, 32: (0b011 << 13) | (0b101 << 5) | 0 = 0x60A0
        assertEquals("out pc, 32", RpPioDisassembler.disassemble(0x60A0));

        // OUT isr, 16: (0b011 << 13) | (0b110 << 5) | 16 = 0x60D0
        assertEquals("out isr, 16", RpPioDisassembler.disassemble(0x60D0));

        // OUT exec, 16: (0b011 << 13) | (0b111 << 5) | 16 = 0x60F0
        assertEquals("out exec, 16", RpPioDisassembler.disassemble(0x60F0));
    }

    @Test
    void testDisassemblePushPull() {
        // PUSH block: (0b100 << 13) | (0 << 7) | (0 << 6) | (1 << 5) = 0x8020
        assertEquals("push block", RpPioDisassembler.disassemble(0x8020));

        // PUSH noblock: (0b100 << 13) | (0 << 7) | (0 << 6) | (0 << 5) = 0x8000
        assertEquals("push noblock", RpPioDisassembler.disassemble(0x8000));

        // PUSH iffull block: (0b100 << 13) | (0 << 7) | (1 << 6) | (1 << 5) = 0x8060
        assertEquals("push iffull block", RpPioDisassembler.disassemble(0x8060));

        // PULL block: (0b100 << 13) | (1 << 7) | (0 << 6) | (1 << 5) = 0x80A0
        assertEquals("pull block", RpPioDisassembler.disassemble(0x80A0));

        // PULL noblock: (0b100 << 13) | (1 << 7) | (0 << 6) | (0 << 5) = 0x8080
        assertEquals("pull noblock", RpPioDisassembler.disassemble(0x8080));

        // PULL ifempty noblock: (0b100 << 13) | (1 << 7) | (1 << 6) | (0 << 5) = 0x80C0
        assertEquals("pull ifempty noblock", RpPioDisassembler.disassemble(0x80C0));
    }

    @Test
    void testDisassembleMov() {
        // MOV x, pins: (0b101 << 13) | (0b001 << 5) | (0b00 << 3) | 0b000 = 0xA020
        assertEquals("mov x, pins", RpPioDisassembler.disassemble(0xA020));

        // MOV y, !x: (0b101 << 13) | (0b010 << 5) | (0b01 << 3) | 0b001 = 0xA049
        assertEquals("mov y, !x", RpPioDisassembler.disassemble(0xA049));

        // MOV isr, ::osr: (0b101 << 13) | (0b110 << 5) | (0b10 << 3) | 0b111 = 0xA0D7
        assertEquals("mov isr, ::osr", RpPioDisassembler.disassemble(0xA0D7));

        // MOV exec, null: (0b101 << 13) | (0b100 << 5) | (0b00 << 3) | 0b011 = 0xA083
        assertEquals("mov exec, null", RpPioDisassembler.disassemble(0xA083));

        // MOV pc, status: (0b101 << 13) | (0b101 << 5) | (0b00 << 3) | 0b101 = 0xA0A5
        assertEquals("mov pc, status", RpPioDisassembler.disassemble(0xA0A5));
    }

    @Test
    void testDisassembleIrq() {
        // IRQ set 0: (0b110 << 13) | (0 << 6) | (0 << 5) | (0 << 4) | 0 = 0xC000
        assertEquals("irq set 0", RpPioDisassembler.disassemble(0xC000));

        // IRQ clear 3: (0b110 << 13) | (1 << 6) | (0 << 5) | (0 << 4) | 3 = 0xC043
        assertEquals("irq clear 3", RpPioDisassembler.disassemble(0xC043));

        // IRQ wait 2: (0b110 << 13) | (0 << 6) | (1 << 5) | (0 << 4) | 2 = 0xC022
        assertEquals("irq wait 2", RpPioDisassembler.disassemble(0xC022));

        // IRQ clear wait 1 rel: (0b110 << 13) | (1 << 6) | (1 << 5) | (1 << 4) | 1 = 0xC071
        assertEquals("irq clear wait 1 rel", RpPioDisassembler.disassemble(0xC071));
    }

    @Test
    void testDisassembleSet() {
        // SET pins, 1: (0b111 << 13) | (0b000 << 5) | 1 = 0xE001
        assertEquals("set pins, 1", RpPioDisassembler.disassemble(0xE001));

        // SET pins, 0: (0b111 << 13) | (0b000 << 5) | 0 = 0xE000
        assertEquals("set pins, 0", RpPioDisassembler.disassemble(0xE000));

        // SET x, 31: (0b111 << 13) | (0b001 << 5) | 31 = 0xE03F
        assertEquals("set x, 31", RpPioDisassembler.disassemble(0xE03F));

        // SET y, 0: (0b111 << 13) | (0b010 << 5) | 0 = 0xE040
        assertEquals("set y, 0", RpPioDisassembler.disassemble(0xE040));

        // SET pindirs, 5: (0b111 << 13) | (0b100 << 5) | 5 = 0xE085
        assertEquals("set pindirs, 5", RpPioDisassembler.disassemble(0xE085));
    }

    @Test
    void testSideSetAndDelayFormatting() {
        // SET pins, 1 with delay 4 when side-set count = 0
        RpPioConfig cfgNoSide = RpPioConfig.of(0, false, false, 0, 31);
        // word: 0xE001 | (4 << 8) = 0xE401
        RpPioInstruction instr1 = RpPioDisassembler.decode(0xE401, cfgNoSide);
        assertEquals("set pins, 1 [4]", instr1.toAssemblyString());
        assertEquals(OptionalInt.of(4), instr1.delay());
        assertFalse(instr1.sideSet().isPresent());
        assertFalse(instr1.isDelaySideUncertain());

        // SET pins, 1 with 1-bit sideSet=1, delay=2 when sideSetCount = 1
        // delaySide = 5 bits: bit 4 is side-set, bits 3:0 is delay
        // side-set = 1 (bit 4 = 1), delay = 2 (bits 3:0 = 0010) -> delaySide = 0b10010 = 0x12
        RpPioConfig cfgSide1 = RpPioConfig.of(1, false, false, 0, 31);
        int wordSide1 = 0xE001 | (0x12 << 8);
        RpPioInstruction instr2 = RpPioDisassembler.decode(wordSide1, cfgSide1);
        assertEquals("set pins, 1 side 1 [2]", instr2.toAssemblyString());
        assertEquals(OptionalInt.of(2), instr2.delay());
        assertEquals(OptionalInt.of(1), instr2.sideSet());
        assertFalse(instr2.isDelaySideUncertain());

        // Side-set optional: 2 bits total (1 enable bit, 1 data bit), delay 3 bits
        // sideSetCount = 2, optional = true
        // rawSide = 0b11 (enable=1, data=1), delay = 1 -> delaySide = (0b11 << 3) | 1 = 0b11001 = 25
        RpPioConfig cfgOptSide = RpPioConfig.of(2, true, false, 0, 31);
        int wordOptSide = 0xE001 | (25 << 8);
        RpPioInstruction instr3 = RpPioDisassembler.decode(wordOptSide, cfgOptSide);
        assertEquals("set pins, 1 side 1 [1]", instr3.toAssemblyString());

        // Optional side-set disabled: enable bit = 0 -> rawSide = 0b01 (enable=0)
        // delaySide = (0b01 << 3) | 1 = 0b01001 = 9
        int wordOptDisabled = 0xE001 | (9 << 8);
        RpPioInstruction instr4 = RpPioDisassembler.decode(wordOptDisabled, cfgOptSide);
        assertEquals("set pins, 1 [1]", instr4.toAssemblyString());
        assertFalse(instr4.sideSet().isPresent());

        // Uncertainty tracking when side-set is unconfigured:
        RpPioConfig uncfg = RpPioConfig.unconfigured();
        RpPioInstruction instrUncert = RpPioDisassembler.decode(0xE401, uncfg);
        assertTrue(instrUncert.isDelaySideUncertain());
        assertEquals("set pins, 1 [delay/side: 0x4 (uncertain)]", instrUncert.toAssemblyString());

        // When delaySide is 0, no uncertainty is printed
        RpPioInstruction instrZero = RpPioDisassembler.decode(0xE001, uncfg);
        assertFalse(instrZero.isDelaySideUncertain());
        assertEquals("set pins, 1", instrZero.toAssemblyString());
    }

    @Test
    void testInstructionValidity() {
        assertTrue(RpPioDisassembler.isValidInstruction(0x0000)); // JMP 0
        assertTrue(RpPioDisassembler.isValidInstruction(0xE001)); // SET pins, 1
        assertTrue(RpPioDisassembler.isValidInstruction(0x8020)); // PUSH block
        assertFalse(RpPioDisassembler.isValidInstruction(0x8021)); // PUSH with non-zero lower bits
        assertFalse(RpPioDisassembler.isValidInstruction(0x2060)); // WAIT with reserved source 3
    }
}
