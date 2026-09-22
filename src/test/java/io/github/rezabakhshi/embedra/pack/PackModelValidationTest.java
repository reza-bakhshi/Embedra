package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class PackModelValidationTest {
    @Test
    void versionsCompareNumericallyAndRejectInvalidForms() {
        assertEquals(0, PackVersion.parse("1.2.3").compareTo(PackVersion.parse("1.2.3")));
        assertEquals(-1, Integer.signum(PackVersion.parse("1.2.3").compareTo(
            PackVersion.parse("2.0.0"))));
        assertEquals(-1, Integer.signum(PackVersion.parse("1.2.3").compareTo(
            PackVersion.parse("1.3.0"))));
        assertEquals(-1, Integer.signum(PackVersion.parse("1.2.3").compareTo(
            PackVersion.parse("1.2.4"))));
        assertThrows(IllegalArgumentException.class, () -> PackVersion.parse("01.0.0"));
        assertThrows(IllegalArgumentException.class, () -> PackVersion.parse("2147483648.0.0"));
        assertThrows(IllegalArgumentException.class, () -> new PackVersion(-1, 0, 0));
    }

    @Test
    void provenanceAndRequirementsRejectIncompleteIdentity() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new PackProvenance(
            new URI("relative"), "revision", "Apache-2.0", "none",
            RedistributionStatus.ALLOWED));
        assertThrows(IllegalArgumentException.class, () -> new PackProvenance(
            new URI("https://example.invalid"), " ", "Apache-2.0", "none",
            RedistributionStatus.ALLOWED));
        assertThrows(IllegalArgumentException.class,
            () -> new PackRequirement("Bad/ID", Optional.empty(), Optional.empty()));
        assertThrows(IllegalArgumentException.class,
            () -> new PackRequirement("valid.id", Optional.empty(), Optional.of("bad/device")));
    }

    @Test
    void fileRecordsRejectUnsafePathsSizesAndDigests() {
        List<String> paths = List.of("", "/absolute", "../escape", "dir/../escape",
            "dir\\file", "C:/file", "dir//file", "dir/");
        for (String path : paths) {
            assertThrows(IllegalArgumentException.class,
                () -> new PackFile(path, 0, "0".repeat(64)), path);
        }
        assertThrows(IllegalArgumentException.class,
            () -> new PackFile("safe.bin", -1, "0".repeat(64)));
        assertThrows(IllegalArgumentException.class,
            () -> new PackFile("safe.bin", 0, "invalid"));
    }
}
