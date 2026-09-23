package io.github.rezabakhshi.embedra.svd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class EspSvdParserTest {
    private static final String REVISION = "be20aa12560889d6125d144cdb48cf615ac17628";

    private static final String MINIMAL_SVD = """
        <?xml version="1.0" encoding="UTF-8"?>
        <device schemaVersion="1.1">
          <vendor>Espressif Systems</vendor>
          <name>ESP32-S3</name>
          <peripherals>
            <peripheral>
              <name>AES</name>
              <description>AES accelerator</description>
              <baseAddress>0x6003A000</baseAddress>
              <addressBlock><offset>0</offset><size>0xB8</size><usage>registers</usage></addressBlock>
              <registers>
                <register>
                  <name>MODE</name><description>AES mode</description>
                  <addressOffset>0x40</addressOffset><size>32</size><access>read-write</access>
                  <resetValue>0</resetValue>
                  <fields>
                    <field><name>MODE</name><bitOffset>0</bitOffset><bitWidth>3</bitWidth>
                      <enumeratedValues><enumeratedValue><name>AES_256</name><value>2</value>
                        <description>256-bit key</description></enumeratedValue></enumeratedValues>
                    </field>
                  </fields>
                </register>
                <register>
                  <dim>2</dim><dimIncrement>4</dimIncrement><name>TEXT_IN[%s]</name>
                  <addressOffset>0x20</addressOffset><size>32</size>
                </register>
              </registers>
            </peripheral>
          </peripherals>
        </device>
        """;

    @Test
    void parsesBoundedRegistersFieldsAndArraysWithPinnedProvenance() throws Exception {
        EspSvdDevice device = EspSvdParser.parse(bytes(MINIMAL_SVD), REVISION,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals("ESP32-S3", device.name());
        assertEquals(REVISION, device.sourceRevision());
        EspSvdPeripheral aes = device.requirePeripheral("AES");
        assertEquals(0x6003_a000L, aes.baseAddress());
        assertEquals(0x6003_a040L, aes.requireRegister("MODE").address());
        assertEquals(EspSvdAccess.READ_WRITE, aes.requireRegister("MODE").access());
        assertEquals(3, aes.requireRegister("MODE").fields().get(0).bitWidth());
        assertEquals("AES_256", aes.requireRegister("MODE").fields().get(0)
            .enumeratedValues().get(0).name());
        assertEquals(0x6003_a020L, aes.requireRegister("TEXT_IN[0]").address());
        assertEquals(0x6003_a024L, aes.requireRegister("TEXT_IN[1]").address());
    }

    @Test
    void rejectsDoctypeExternalEntitiesOversizeDepthAndCancellation() {
        String entity = """
            <?xml version="1.0"?>
            <!DOCTYPE device [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <device><name>&xxe;</name><peripherals/></device>
            """;
        assertCode(DiagnosticCode.PACK_CONTENT_INVALID, entity,
            ParserLimits.defaults(), CancellationToken.none());

        ParserLimits tiny = new ParserLimits(32, 32, 32, 10, 4,
            ParserLimits.defaults().maxWallTime());
        assertCode(DiagnosticCode.LIMIT_EXCEEDED, MINIMAL_SVD, tiny,
            CancellationToken.none());

        ParserLimits shallow = new ParserLimits(1_000_000, 1_000_000, 1_000_000,
            100, 2, ParserLimits.defaults().maxWallTime());
        assertCode(DiagnosticCode.LIMIT_EXCEEDED, MINIMAL_SVD, shallow,
            CancellationToken.none());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        assertCode(DiagnosticCode.CANCELLED, MINIMAL_SVD, ParserLimits.defaults(),
            cancellation.token());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void assertCode(DiagnosticCode code, String xml, ParserLimits limits,
            CancellationToken cancellation) {
        DiagnosticException failure = assertThrows(DiagnosticException.class,
            () -> EspSvdParser.parse(bytes(xml), REVISION, limits, cancellation));
        assertEquals(code, failure.diagnostic().code());
    }
}
