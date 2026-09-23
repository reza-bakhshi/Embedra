package io.github.rezabakhshi.embedra.svd;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayInputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalLong;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/** Bounded XXE-safe parser for the Espressif CMSIS-SVD subset used by Embedra. */
public final class EspSvdParser {
    private EspSvdParser() {
    }

    public static EspSvdDevice parse(byte[] xml, String sourceRevision,
            ParserLimits limits, CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(xml, "xml");
        Objects.requireNonNull(sourceRevision, "sourceRevision");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        if (xml.length > limits.maxInputBytes() || xml.length > limits.maxAllocationBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "SVD input exceeds the configured byte limit");
        }
        String declarationScan = new String(xml, java.nio.charset.StandardCharsets.US_ASCII)
            .toUpperCase(Locale.ROOT);
        if (declarationScan.contains("<!DOCTYPE")
            || declarationScan.contains("<!ENTITY")) {
            throw failure(DiagnosticCode.PACK_CONTENT_INVALID,
                "SVD document types and entities are forbidden");
        }
        Instant started = Instant.now();
        try {
            DocumentBuilderFactory factory = secureFactory();
            Document document = factory.newDocumentBuilder().parse(
                new ByteArrayInputStream(xml));
            Element root = document.getDocumentElement();
            Budget budget = new Budget(limits, token, started);
            budget.visit(root, 1);
            if (!"device".equals(root.getTagName())) {
                throw failure(DiagnosticCode.PACK_CONTENT_INVALID,
                    "SVD root element must be device");
            }
            String name = requiredText(root, "name");
            Element peripherals = requiredChild(root, "peripherals");
            List<EspSvdPeripheral> parsed = new ArrayList<>();
            for (Element peripheral : children(peripherals, "peripheral")) {
                token.throwIfCancellationRequested();
                parsed.add(parsePeripheral(peripheral));
            }
            parsed.sort(Comparator.comparingLong(EspSvdPeripheral::baseAddress)
                .thenComparing(EspSvdPeripheral::name));
            budget.checkTime();
            return new EspSvdDevice(name, sourceRevision, parsed);
        }
        catch (ParserConfigurationException | SAXException | java.io.IOException exception) {
            throw failure(DiagnosticCode.PACK_CONTENT_INVALID,
                "SVD XML could not be parsed safely");
        }
        catch (IllegalArgumentException exception) {
            throw failure(DiagnosticCode.PACK_CONTENT_INVALID,
                "SVD model is invalid: " + safeMessage(exception));
        }
    }

    private static DocumentBuilderFactory secureFactory()
            throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd",
            false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(false);
        return factory;
    }

    private static EspSvdPeripheral parsePeripheral(Element element) {
        String name = requiredText(element, "name");
        String description = optionalText(element, "description", "");
        long base = number(requiredText(element, "baseAddress"));
        EspSvdAccess inheritedAccess = EspSvdAccess.parse(
            optionalText(element, "access", ""), EspSvdAccess.UNKNOWN);
        int inheritedSize = (int) number(optionalText(element, "size", "32"));
        OptionalLong inheritedReset = optionalNumber(element, "resetValue");
        List<EspSvdRegister> registers = new ArrayList<>();
        Element registerRoot = optionalChild(element, "registers");
        if (registerRoot != null) {
            for (Element register : children(registerRoot, "register")) {
                registers.addAll(parseRegister(register, base, inheritedSize,
                    inheritedAccess, inheritedReset));
            }
        }
        registers.sort(Comparator.comparingLong(EspSvdRegister::address)
            .thenComparing(EspSvdRegister::name));
        long end = addressBlockEnd(element, base);
        for (EspSvdRegister register : registers) {
            end = Math.max(end, register.address() + Math.max(1, register.sizeBits() / 8));
        }
        if (end <= base) {
            end = base + 4;
        }
        return new EspSvdPeripheral(name, description, base, end, registers);
    }

    private static List<EspSvdRegister> parseRegister(Element element, long base,
            int inheritedSize, EspSvdAccess inheritedAccess,
            OptionalLong inheritedReset) {
        String template = requiredText(element, "name");
        String description = optionalText(element, "description", "");
        long offset = number(requiredText(element, "addressOffset"));
        int size = (int) number(optionalText(element, "size",
            Integer.toString(inheritedSize)));
        EspSvdAccess access = EspSvdAccess.parse(optionalText(element, "access", ""),
            inheritedAccess);
        OptionalLong reset = optionalNumber(element, "resetValue");
        if (reset.isEmpty()) {
            reset = inheritedReset;
        }
        List<EspSvdField> fields = parseFields(element, access);
        int dimension = (int) number(optionalText(element, "dim", "1"));
        long increment = number(optionalText(element, "dimIncrement", "0"));
        if (dimension <= 0 || dimension > 65536 || (dimension > 1 && increment <= 0)) {
            throw new IllegalArgumentException("SVD register dimension is invalid");
        }
        List<EspSvdRegister> result = new ArrayList<>();
        for (int index = 0; index < dimension; index++) {
            String name = dimension == 1 ? template
                : template.replace("%s", Integer.toString(index));
            long address = Math.addExact(base, Math.addExact(offset,
                Math.multiplyExact(index, increment)));
            result.add(new EspSvdRegister(name, description, address, size, access,
                reset, fields));
        }
        return result;
    }

    private static List<EspSvdField> parseFields(Element register,
            EspSvdAccess inheritedAccess) {
        Element fieldRoot = optionalChild(register, "fields");
        if (fieldRoot == null) {
            return List.of();
        }
        List<EspSvdField> result = new ArrayList<>();
        for (Element field : children(fieldRoot, "field")) {
            String name = requiredText(field, "name");
            String description = optionalText(field, "description", "");
            int offset = (int) number(requiredText(field, "bitOffset"));
            int width = (int) number(requiredText(field, "bitWidth"));
            EspSvdAccess access = EspSvdAccess.parse(optionalText(field, "access", ""),
                inheritedAccess);
            List<EspSvdEnumeratedValue> values = new ArrayList<>();
            Element enumerated = optionalChild(field, "enumeratedValues");
            if (enumerated != null) {
                for (Element value : children(enumerated, "enumeratedValue")) {
                    values.add(new EspSvdEnumeratedValue(requiredText(value, "name"),
                        number(requiredText(value, "value")),
                        optionalText(value, "description", "")));
                }
            }
            result.add(new EspSvdField(name, description, offset, width, access,
                values));
        }
        return List.copyOf(result);
    }

    private static long addressBlockEnd(Element peripheral, long base) {
        Element block = optionalChild(peripheral, "addressBlock");
        if (block == null) {
            return base;
        }
        return Math.addExact(base, Math.addExact(number(requiredText(block, "offset")),
            number(requiredText(block, "size"))));
    }

    private static OptionalLong optionalNumber(Element parent, String name) {
        String value = optionalText(parent, name, "");
        return value.isBlank() ? OptionalLong.empty() : OptionalLong.of(number(value));
    }

    private static long number(String value) {
        String normalized = value.strip().replace("_", "");
        if (normalized.startsWith("#")) {
            normalized = normalized.substring(1);
        }
        return Long.decode(normalized);
    }

    private static Element requiredChild(Element parent, String name) {
        Element child = optionalChild(parent, name);
        if (child == null) {
            throw new IllegalArgumentException("Missing SVD element: " + name);
        }
        return child;
    }

    private static Element optionalChild(Element parent, String name) {
        NodeList nodes = parent.getChildNodes();
        for (int index = 0; index < nodes.getLength(); index++) {
            Node node = nodes.item(index);
            if (node instanceof Element element && name.equals(element.getTagName())) {
                return element;
            }
        }
        return null;
    }

    private static List<Element> children(Element parent, String name) {
        List<Element> result = new ArrayList<>();
        NodeList nodes = parent.getChildNodes();
        for (int index = 0; index < nodes.getLength(); index++) {
            Node node = nodes.item(index);
            if (node instanceof Element element && name.equals(element.getTagName())) {
                result.add(element);
            }
        }
        return result;
    }

    private static String requiredText(Element parent, String name) {
        String value = optionalText(parent, name, "");
        if (value.isBlank()) {
            throw new IllegalArgumentException("Missing SVD text: " + name);
        }
        return value;
    }

    private static String optionalText(Element parent, String name, String fallback) {
        Element child = optionalChild(parent, name);
        return child == null ? fallback : child.getTextContent().strip();
    }

    private static DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, null));
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName()
            : message;
    }

    private static final class Budget {
        private final ParserLimits limits;

        private final CancellationToken token;

        private final Instant started;

        private long objects;

        private Budget(ParserLimits limits, CancellationToken token, Instant started) {
            this.limits = limits;
            this.token = token;
            this.started = started;
        }

        private void visit(Node node, int depth) throws DiagnosticException {
            token.throwIfCancellationRequested();
            if (depth > limits.maxNestingDepth() || ++objects > limits.maxObjects()) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "SVD structure exceeds configured limits");
            }
            checkTime();
            NodeList children = node.getChildNodes();
            for (int index = 0; index < children.getLength(); index++) {
                if (children.item(index) instanceof Element child) {
                    visit(child, depth + 1);
                }
            }
        }

        private void checkTime() throws DiagnosticException {
            if (Duration.between(started, Instant.now()).compareTo(limits.maxWallTime()) > 0) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "SVD parsing exceeded the configured time limit");
            }
        }
    }
}
