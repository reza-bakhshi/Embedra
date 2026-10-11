package io.github.rezabakhshi.embedra.core.budget;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class AdversarialXmlGuardTest {

    @Test
    void rejectsNullInputs() {
        SharedResourceBudget budget = SharedResourceBudget.defaults();
        assertThrows(NullPointerException.class, () -> AdversarialXmlGuard.parseXmlSafely(null, budget));
        assertThrows(NullPointerException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(new ByteArrayInputStream(new byte[0]), null));
    }

    @Test
    void createsSecureDocumentBuilderFactory() throws Exception {
        DocumentBuilderFactory factory = AdversarialXmlGuard.createSecureDocumentBuilderFactory();
        assertNotNull(factory);
        assertTrue(factory.isNamespaceAware());
        assertNotNull(factory.newDocumentBuilder());
    }

    @Test
    void parsesValidXmlSafely() throws Exception {
        String xml = """
                <?xml version="1.0" encoding="UTF-8"?>
                <device name="STM32F401">
                    <cpu>Cortex-M4</cpu>
                    <memory>
                        <flash size="512KB"/>
                        <sram size="96KB"/>
                    </memory>
                </device>
                """;

        SharedResourceBudget budget = SharedResourceBudget.defaults();
        Document doc = AdversarialXmlGuard.parseXmlSafely(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)),
                budget);

        assertNotNull(doc);
        assertEquals("device", doc.getDocumentElement().getTagName());
        assertTrue(budget.createdObjects() > 0);
    }

    @Test
    void rejectsDoctypeAndBillionLaughsExpansion() {
        String attackXml = """
                <?xml version="1.0"?>
                <!DOCTYPE lolz [
                 <!ENTITY lol "lol">
                 <!ELEMENT lolz (#PCDATA)>
                 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
                 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
                ]>
                <lolz>&lol2;</lolz>
                """;

        SharedResourceBudget budget = SharedResourceBudget.defaults();
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(
                        new ByteArrayInputStream(attackXml.getBytes(StandardCharsets.UTF_8)),
                        budget));

        assertEquals(DiagnosticCode.XML_ENTITY_EXPANSION_DETECTED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Adversarial XML entity or DOCTYPE expansion rejected"));
    }

    @Test
    void rejectsExcessiveElementNestingDepth() {
        String deeplyNestedXml = """
                <l1>
                    <l2>
                        <l3>
                            <l4>
                                <l5>deep</l5>
                            </l4>
                        </l3>
                    </l2>
                </l1>
                """;

        ParserLimits limits = new ParserLimits(10_000, 10_000, 10_000, 100, 3, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(
                        new ByteArrayInputStream(deeplyNestedXml.getBytes(StandardCharsets.UTF_8)),
                        budget));

        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("nesting depth"));
    }

    @Test
    void rejectsExcessiveObjectCount() {
        String wideXml = """
                <root>
                    <e1/><e2/><e3/><e4/><e5/><e6/><e7/><e8/>
                </root>
                """;

        ParserLimits limits = new ParserLimits(10_000, 10_000, 10_000, 4, 10, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(
                        new ByteArrayInputStream(wideXml.getBytes(StandardCharsets.UTF_8)),
                        budget));

        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Object count budget exceeded"));
    }

    @Test
    void checksLivenessDuringXmlParsing() {
        CancellationToken cancelled = () -> true;
        SharedResourceBudget budget = new SharedResourceBudget(ParserLimits.defaults(), cancelled);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(
                        new ByteArrayInputStream("<root/>".getBytes(StandardCharsets.UTF_8)),
                        budget));

        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }

    @Test
    void handlesMalformedXmlGracefully() {
        String malformed = "<root><unclosed>";
        SharedResourceBudget budget = SharedResourceBudget.defaults();

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(
                        new ByteArrayInputStream(malformed.getBytes(StandardCharsets.UTF_8)),
                        budget));

        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Failed to parse XML safely"));
    }

    @Test
    void rejectsEntityExpansionMessage() {
        InputStream evilStream = new InputStream() {
            @Override
            public int read() throws java.io.IOException {
                throw new java.io.IOException("Exceeded entity expansion limit");
            }
        };

        SharedResourceBudget budget = SharedResourceBudget.defaults();
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(evilStream, budget));

        assertEquals(DiagnosticCode.XML_ENTITY_EXPANSION_DETECTED, ex.diagnostic().code());
    }

    @Test
    void handlesNullMessageException() {
        InputStream nullMsgStream = new InputStream() {
            @Override
            public int read() throws java.io.IOException {
                throw new java.io.IOException((String) null);
            }
        };

        SharedResourceBudget budget = SharedResourceBudget.defaults();
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialXmlGuard.parseXmlSafely(nullMsgStream, budget));

        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void testPrivateConstructor() throws Exception {
        Constructor<AdversarialXmlGuard> constructor = AdversarialXmlGuard.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        assertNotNull(constructor.newInstance());
    }
}
