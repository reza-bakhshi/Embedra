package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class EspCommonCodeArchitectureTest {
    @Test
    void sharedImportAndTargetServicesContainNoXtensaAssumption() throws Exception {
        for (String source : List.of(
                "ghidra/esp/EspApplicationImportService.java",
                "ghidra/esp/EspApplicationImageMapper.java",
                "ghidra/esp/EspApplicationImageLoader.java",
                "targets/esp/EspTargetResolver.java",
                "targets/esp/EspEntryPointValidator.java")) {
            String text = Files.readString(Path.of("src/main/java/io/github/rezabakhshi/embedra")
                .resolve(source));
            assertFalse(text.contains("Xtensa"), source);
        }
    }
}
