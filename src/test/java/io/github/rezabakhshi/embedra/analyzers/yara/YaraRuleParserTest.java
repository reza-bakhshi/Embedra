package io.github.rezabakhshi.embedra.analyzers.yara;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.List;
import org.junit.jupiter.api.Test;

class YaraRuleParserTest {

    @Test
    void parsesSimpleRuleWithMetaStringsCondition() throws Exception {
        String ruleSrc = """
            // Comment before rule
            rule Test_Rule : test_tag {
                meta:
                    description = "A test rule"
                    category = "CIPHER_SYMMETRIC"
                    version = 1
                    active = true
                strings:
                    $text = "test string" ascii wide nocase
                    $hex = { 01 02 ?? 04 [1-3] 08 }
                    $re = /pattern[0-9]+/ nocase
                condition:
                    $text and ($hex or $re)
            }
            """;

        List<YaraRule> rules = YaraRuleParser.parse(ruleSrc);
        assertEquals(1, rules.size());

        YaraRule rule = rules.get(0);
        assertEquals("Test_Rule", rule.name());
        assertTrue(rule.tags().contains("test_tag"));
        assertEquals("A test rule", rule.description());
        assertEquals("CIPHER_SYMMETRIC", rule.category());
        assertEquals(1L, rule.meta().get("version"));
        assertEquals(true, rule.meta().get("active"));

        assertEquals(3, rule.patterns().size());
        assertTrue(rule.patterns().get("$text") instanceof YaraPattern.TextPattern);
        assertTrue(rule.patterns().get("$hex") instanceof YaraPattern.HexPattern);
        assertTrue(rule.patterns().get("$re") instanceof YaraPattern.RegexPattern);

        YaraPattern.TextPattern tp = (YaraPattern.TextPattern) rule.patterns().get("$text");
        assertEquals("test string", tp.text());
        assertTrue(tp.isAscii());
        assertTrue(tp.isWide());
        assertTrue(tp.isNocase());
    }

    @Test
    void parsesHexPatternWithNibbleWildcards() throws Exception {
        String ruleSrc = """
            rule Hex_Nibbles {
                strings:
                    $nibble = { ?A B? ?? }
                condition:
                    $nibble
            }
            """;

        List<YaraRule> rules = YaraRuleParser.parse(ruleSrc);
        assertEquals(1, rules.size());
        YaraPattern.HexPattern hp = (YaraPattern.HexPattern) rules.get(0).patterns().get("$nibble");
        assertEquals(3, hp.tokens().size());

        YaraPattern.ByteToken t1 = (YaraPattern.ByteToken) hp.tokens().get(0);
        assertEquals(0x0A, t1.value());
        assertEquals(0x0F, t1.mask());

        YaraPattern.ByteToken t2 = (YaraPattern.ByteToken) hp.tokens().get(1);
        assertEquals(0xB0, t2.value());
        assertEquals(0xF0, t2.mask());

        YaraPattern.ByteToken t3 = (YaraPattern.ByteToken) hp.tokens().get(2);
        assertEquals(0x00, t3.mask());
    }

    @Test
    void parsesQuantifiersAndOffsetConditions() throws Exception {
        String ruleSrc = """
            rule Quantifiers {
                strings:
                    $a = "alpha"
                    $b = "beta"
                    $c = "gamma"
                condition:
                    any of them and 2 of ($a, $b) and $a at 0x10 and $b in (0x20..0x50)
            }
            """;

        List<YaraRule> rules = YaraRuleParser.parse(ruleSrc);
        assertEquals(1, rules.size());
        assertNotNull(rules.get(0).condition());
    }

    @Test
    void parsesCountConditions() throws Exception {
        String ruleSrc = """
            rule Count_Rule {
                strings:
                    $a = "test"
                condition:
                    #a > 2 and #a != 0
            }
            """;

        List<YaraRule> rules = YaraRuleParser.parse(ruleSrc);
        assertEquals(1, rules.size());
    }

    @Test
    void handlesMultiLineAndNestedComments() throws Exception {
        String ruleSrc = """
            /* Multi-line
               comment here */
            rule Commented_Rule {
                strings:
                    $str = "value" // inline comment
                condition:
                    /* block */ $str
            }
            """;

        List<YaraRule> rules = YaraRuleParser.parse(ruleSrc);
        assertEquals(1, rules.size());
        assertEquals("Commented_Rule", rules.get(0).name());
    }

    @Test
    void throwsDetailedYaraParseExceptionOnInvalidSyntax() {
        String badRule = """
            rule Bad_Rule {
                strings:
                    $a = "missing quote
                condition:
                    $a
            }
            """;

        YaraParseException ex = assertThrows(YaraParseException.class, () -> YaraRuleParser.parse(badRule));
        assertTrue(ex.line() > 0);
        assertTrue(ex.getMessage().contains("YARA parse error"));
    }

    @Test
    void enforcesMaxRulesLimit() {
        String twoRules = """
            rule R1 { condition: true }
            rule R2 { condition: true }
            """;

        ParserLimits limits = ParserLimits.defaults().withMaxAllocationBytes(1024);
        ParserLimits strictLimits = new ParserLimits(1024, 1024, 1024, 1, 10, limits.maxWallTime());

        YaraRuleParser parser = new YaraRuleParser(twoRules, strictLimits);
        assertThrows(YaraParseException.class, parser::parseRules);
    }
}
