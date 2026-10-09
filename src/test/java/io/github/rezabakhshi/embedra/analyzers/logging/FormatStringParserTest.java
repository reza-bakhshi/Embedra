package io.github.rezabakhshi.embedra.analyzers.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.logging.scanner.FormatStringParser;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FormatStringParserTest {

    private FormatStringParser parser;

    private ParserLimits limits;

    @BeforeEach
    void setUp() {
        parser = new FormatStringParser();
        limits = ParserLimits.defaults();
    }

    @Test
    void parsesEmptyAndPlainTextStrings() {
        FormatStringDescriptor empty = parser.parse("", limits);
        assertEquals(0, empty.expectedArgumentCount());
        assertFalse(empty.hasSpecifiers());

        FormatStringDescriptor plain = parser.parse("Hello, embedded world!", limits);
        assertEquals(0, plain.expectedArgumentCount());
        assertFalse(plain.hasSpecifiers());
        assertEquals("Hello, embedded world!", plain.rawText());
    }

    @Test
    void parsesBasicSpecifiers() {
        FormatStringDescriptor desc = parser.parse("Error code: %d, name: %s, addr: 0x%08X", limits);
        assertTrue(desc.hasSpecifiers());
        assertEquals(3, desc.expectedArgumentCount());

        List<FormatSpecifier> specs = desc.specifiers();
        assertEquals(3, specs.size());

        assertEquals("%d", specs.get(0).specifierText());
        assertEquals(FormatArgumentType.INTEGER, specs.get(0).type());

        assertEquals("%s", specs.get(1).specifierText());
        assertEquals(FormatArgumentType.STRING, specs.get(1).type());

        assertEquals("%08X", specs.get(2).specifierText());
        assertEquals(FormatArgumentType.HEX_INTEGER, specs.get(2).type());
        assertEquals(8, specs.get(2).width());
    }

    @Test
    void parsesEscapedPercentWithoutConsumingArgument() {
        FormatStringDescriptor desc = parser.parse("Progress: 100%% complete in %d ms", limits);
        assertTrue(desc.hasSpecifiers());
        assertEquals(1, desc.expectedArgumentCount());
        assertEquals(1, desc.specifiers().size());
        assertEquals("%d", desc.specifiers().get(0).specifierText());
        assertEquals(FormatArgumentType.INTEGER, desc.specifiers().get(0).type());
    }

    @Test
    void parsesPositionalSpecifiers() {
        FormatStringDescriptor desc = parser.parse("%2$s was born on %1$d", limits);
        assertTrue(desc.hasSpecifiers());
        assertEquals(2, desc.expectedArgumentCount());

        List<FormatSpecifier> specs = desc.specifiers();
        assertEquals(2, specs.size());

        assertTrue(specs.get(0).isPositional());
        assertEquals(2, specs.get(0).positionalIndex());
        assertEquals(FormatArgumentType.STRING, specs.get(0).type());

        assertTrue(specs.get(1).isPositional());
        assertEquals(1, specs.get(1).positionalIndex());
        assertEquals(FormatArgumentType.INTEGER, specs.get(1).type());
    }

    @Test
    void parsesVariableWidthAndPrecisionAsterisks() {
        FormatStringDescriptor desc = parser.parse("Padded string: %*.*s", limits);
        assertTrue(desc.hasSpecifiers());
        // width '*', precision '*', and target '%s' -> 3 arguments
        assertEquals(3, desc.expectedArgumentCount());
        assertEquals(List.of(
                FormatArgumentType.INTEGER,
                FormatArgumentType.INTEGER,
                FormatArgumentType.STRING), desc.argumentTypes());
    }

    @Test
    void handlesFloatPointersAndCustomTypes() {
        FormatStringDescriptor desc = parser.parse("Value: %3.2f, Buffer: %p, Char: %c", limits);
        assertEquals(3, desc.expectedArgumentCount());
        assertEquals(FormatArgumentType.FLOAT, desc.argumentTypes().get(0));
        assertEquals(FormatArgumentType.POINTER, desc.argumentTypes().get(1));
        assertEquals(FormatArgumentType.CHARACTER, desc.argumentTypes().get(2));
    }
}
