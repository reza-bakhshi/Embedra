package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class EspressifChipIdRegistryTest {
    private static final String ROW =
        "9\tesp32s3\tESP32-S3\tesptool/targets/esp32s3.py\tv5.4.0\tGPL-2.0-or-later\n";

    @Test
    void parsesCommentsAndExactDefinitions() throws Exception {
        EspressifChipIdRegistry registry = parse("# schema\n\n" + ROW);

        assertEquals("esp32s3", registry.requireByChipId(9).deviceId());
        assertThrows(IllegalArgumentException.class, () -> registry.requireByChipId(0));
    }

    @Test
    void rejectsMalformedDuplicateEmptyAndNonNumericDefinitions() {
        assertThrows(IOException.class, () -> parse("9\ttoo\tfew\n"));
        assertThrows(IOException.class, () -> parse(ROW + ROW));
        assertThrows(IOException.class, () -> parse("# comments only\n"));
        assertThrows(IOException.class, () -> parse(
            "nine\tesp32s3\tESP32-S3\tpath\trevision\tGPL-2.0-or-later\n"));
    }

    private static EspressifChipIdRegistry parse(String contents) throws IOException {
        return EspressifChipIdRegistry.parse(new ByteArrayInputStream(
            contents.getBytes(StandardCharsets.UTF_8)));
    }
}
