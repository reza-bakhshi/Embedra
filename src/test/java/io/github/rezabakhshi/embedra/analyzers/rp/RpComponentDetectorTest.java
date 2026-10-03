package io.github.rezabakhshi.embedra.analyzers.rp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class RpComponentDetectorTest {

    @Test
    void testTinyUsbDetector() throws Exception {
        byte[] data = new byte[256];
        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Standard USB Device Descriptor at offset 0 (18 bytes)
        bb.put((byte) 18); // bLength
        bb.put((byte) 1);  // bDescriptorType = DEVICE
        bb.putShort((short) 0x0200); // bcdUSB = 2.0
        bb.put((byte) 0);  // bDeviceClass
        bb.put((byte) 0);  // bDeviceSubClass
        bb.put((byte) 0);  // bDeviceProtocol
        bb.put((byte) 64); // bMaxPacketSize0
        bb.putShort((short) 0x2E8A); // idVendor = Raspberry Pi
        bb.putShort((short) 0x000A); // idProduct = Pico CDC
        bb.putShort((short) 0x0100); // bcdDevice
        bb.put((byte) 1);  // iManufacturer
        bb.put((byte) 2);  // iProduct
        bb.put((byte) 0);  // iSerialNumber
        bb.put((byte) 1);  // bNumConfigurations

        // Standard Configuration Descriptor at offset 32 (9 bytes)
        bb.position(32);
        bb.put((byte) 9);  // bLength
        bb.put((byte) 2);  // bDescriptorType = CONFIG
        bb.putShort((short) 32); // wTotalLength
        bb.put((byte) 1);  // bNumInterfaces
        bb.put((byte) 1);  // bConfigurationValue
        bb.put((byte) 0);  // iConfiguration
        bb.put((byte) 0x80); // bmAttributes
        bb.put((byte) 50); // bMaxPower

        // Interface Descriptor at offset 48 (9 bytes)
        bb.position(48);
        bb.put((byte) 9);  // bLength
        bb.put((byte) 4);  // bDescriptorType = INTERFACE
        bb.put((byte) 0);  // bInterfaceNumber
        bb.put((byte) 0);  // bAlternateSetting
        bb.put((byte) 1);  // bNumEndpoints
        bb.put((byte) 0x02); // bInterfaceClass (CDC)
        bb.put((byte) 0x02);
        bb.put((byte) 0x01);
        bb.put((byte) 0);

        // Endpoint Descriptor at offset 64 (7 bytes)
        bb.position(64);
        bb.put((byte) 7);  // bLength
        bb.put((byte) 5);  // bDescriptorType = ENDPOINT
        bb.put((byte) 0x81); // bEndpointAddress (IN 1)
        bb.put((byte) 0x02); // bmAttributes (Bulk)
        bb.putShort((short) 64); // wMaxPacketSize
        bb.put((byte) 1);  // bInterval

        List<RpUf2Segment> segments = List.of(new RpUf2Segment(0x10000000L, data, Optional.empty()));
        List<String> symbols = List.of("tud_init", "tud_task", "tud_cdc_connected");
        List<String> strings = List.of("TinyUSB", "CDC_ACM");

        RpAnalysisContext ctx = new RpAnalysisContext(segments, symbols, strings);
        RpTinyUsbDetector detector = new RpTinyUsbDetector();

        RpTinyUsbMatch match = detector.detect(ctx, ParserLimits.defaults(), CancellationToken.none());
        assertTrue(match.detected());
        assertEquals(Confidence.VERIFIED, match.confidence());
        assertEquals(4, match.descriptors().size());
        assertTrue(match.apis().contains("tud_init"));
        assertTrue(match.apis().contains("tud_task"));
    }

    @Test
    void testTinyUsbNegative() throws Exception {
        byte[] empty = new byte[64];
        RpAnalysisContext ctx = RpAnalysisContext.fromBytes(empty, 0x10000000L);
        RpTinyUsbDetector detector = new RpTinyUsbDetector();

        RpTinyUsbMatch match = detector.detect(ctx, ParserLimits.defaults(), CancellationToken.none());
        assertFalse(match.detected());
        assertEquals(0, match.descriptors().size());
    }

    @Test
    void testLwIpDetector() throws Exception {
        List<RpUf2Segment> segments = List.of(new RpUf2Segment(0x10000000L, new byte[32], Optional.empty()));
        List<String> symbols = List.of("lwip_init", "netif_add", "tcp_connect", "dhcp_start");
        List<String> strings = List.of("lwIP v2.1.2", "netif_default", "DHCP bound");

        RpAnalysisContext ctx = new RpAnalysisContext(segments, symbols, strings);
        RpLwIpDetector detector = new RpLwIpDetector();

        RpLwIpMatch match = detector.detect(ctx, ParserLimits.defaults(), CancellationToken.none());
        assertTrue(match.detected());
        assertEquals(Confidence.VERIFIED, match.confidence());
        assertTrue(match.version().isPresent());
        assertEquals("2.1.2", match.version().get());
        assertTrue(match.protocols().contains("TCP"));
        assertTrue(match.protocols().contains("DHCP"));
        assertTrue(match.protocols().contains("NETIF"));
        assertTrue(match.apis().contains("lwip_init"));
    }

    @Test
    void testLwIpNegative() throws Exception {
        RpAnalysisContext ctx = RpAnalysisContext.fromBytes(new byte[32], 0x10000000L);
        RpLwIpDetector detector = new RpLwIpDetector();
        RpLwIpMatch match = detector.detect(ctx, ParserLimits.defaults(), CancellationToken.none());
        assertFalse(match.detected());
    }

    @Test
    void testCyw43Detector() throws Exception {
        List<RpUf2Segment> segments = List.of(new RpUf2Segment(0x10000000L, new byte[32], Optional.empty()));
        List<String> symbols = List.of("cyw43_arch_init", "cyw43_pio_init", "cyw43_arch_wifi_connect_blocking");
        List<String> strings = List.of("CYW43439", "43439A0.bin", "CYW43_COUNTRY_WW");

        RpAnalysisContext ctx = new RpAnalysisContext(segments, symbols, strings);
        RpCyw43Detector detector = new RpCyw43Detector();

        RpCyw43Match match = detector.detect(ctx, ParserLimits.defaults(), CancellationToken.none());
        assertTrue(match.detected());
        assertEquals("Infineon CYW43439", match.chipModel());
        assertTrue(match.busInterface().isPresent());
        assertEquals("PIO", match.busInterface().get());
        assertTrue(match.firmwareBlobPresent());
        assertTrue(match.countryCodes().contains("WW"));
        assertTrue(match.apis().contains("cyw43_arch_init"));
        assertEquals(Confidence.VERIFIED, match.confidence());
    }

    @Test
    void testCyw43Negative() throws Exception {
        RpAnalysisContext ctx = RpAnalysisContext.fromBytes(new byte[32], 0x10000000L);
        RpCyw43Detector detector = new RpCyw43Detector();
        RpCyw43Match match = detector.detect(ctx, ParserLimits.defaults(), CancellationToken.none());
        assertFalse(match.detected());
    }

    @Test
    void testCompositeComponentAnalyzer() throws Exception {
        byte[] dummy = new byte[32];
        List<RpUf2Segment> segments = List.of(new RpUf2Segment(0x10000000L, dummy, Optional.empty()));
        List<String> symbols = List.of("tud_init", "lwip_init", "cyw43_arch_init", "cyw43_spi_init");
        List<String> strings = List.of("lwIP v2.2.0", "CYW43439");

        RpAnalysisContext ctx = new RpAnalysisContext(segments, symbols, strings);
        RpComponentEnrichmentAnalyzer analyzer = new RpComponentEnrichmentAnalyzer();

        RpComponentEnrichmentReport report = analyzer.analyze(ctx, ParserLimits.defaults(), CancellationToken.none());
        assertTrue(report.hasAnyComponentDetected());
        assertTrue(report.tinyUsb().detected());
        assertTrue(report.lwIp().detected());
        assertTrue(report.cyw43().detected());
        assertEquals(3, report.overallEvidence().size());

        // Test cancellation
        CancellationToken cancelled = () -> true;
        assertThrows(DiagnosticException.class,
                () -> analyzer.analyze(ctx, ParserLimits.defaults(), cancelled));
    }
}
