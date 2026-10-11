package io.github.rezabakhshi.embedra.core.budget;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.InputStream;
import java.util.Objects;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Hardened XML parser guard protecting against XML Entity Expansion (Billion Laughs),
 * XML External Entity (XXE) injection, schema poisoning, and excessive nesting depth (Section 5.3).
 */
public final class AdversarialXmlGuard {

    private AdversarialXmlGuard() {
    }

    /**
     * Creates a hardened DocumentBuilderFactory with secure processing and disabled external entities.
     */
    public static DocumentBuilderFactory createSecureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);

        // Enable secure processing
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        // Disallow external DTDs and entities to prevent XXE and Billion Laughs
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException ignored) {
            // Fall back to disabling external entities individually
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        }

        try {
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) {
            // Older JAXP implementations may not support these attributes
        }

        return dbf;
    }

    /**
     * Parses an XML stream safely under a SharedResourceBudget, checking nesting depth and object counts.
     */
    public static Document parseXmlSafely(
            InputStream xmlStream,
            SharedResourceBudget budget) throws DiagnosticException {
        Objects.requireNonNull(xmlStream, "xmlStream must not be null");
        Objects.requireNonNull(budget, "budget must not be null");

        budget.checkLiveness();

        try {
            DocumentBuilderFactory dbf = createSecureDocumentBuilderFactory();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(xmlStream);

            // Validate DOM structure against nesting and element count budgets
            validateDomNode(doc.getDocumentElement(), 1, budget);

            return doc;
        } catch (Exception e) {
            String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
            if (msg.contains("doctype") || msg.contains("entity expansion")) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.XML_ENTITY_EXPANSION_DETECTED,
                        "Adversarial XML entity or DOCTYPE expansion rejected: " + e.getMessage()));
            }
            if (e instanceof DiagnosticException de) {
                throw de;
            }
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.RESOURCE_BUDGET_EXCEEDED,
                    "Failed to parse XML safely: " + e.getMessage()));
        }
    }

    private static void validateDomNode(
            Node node,
            int currentDepth,
            SharedResourceBudget budget) throws DiagnosticException {
        budget.checkLiveness();
        budget.trackObjects(1);

        if (currentDepth > budget.limits().maxNestingDepth()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.RESOURCE_BUDGET_EXCEEDED,
                    String.format("XML element nesting depth %d exceeded maximum %d",
                            currentDepth, budget.limits().maxNestingDepth())));
        }

        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                validateDomNode(child, currentDepth + 1, budget);
            }
        }
    }
}
