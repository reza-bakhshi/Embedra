package io.github.rezabakhshi.embedra.targets.stm32.catalog;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/** Exact IDs from the digest-pinned T032 selection, pending the T038 registry. */
public final class Stm32CuratedPartIds implements Stm32PartSelection {
    public static final String SELECTION_SHA256 =
        "1d4b971f0264815492bf644552b8c83abf0393b627216a89640080b8ccf8b3b4";

    private final Set<String> ids;

    private Stm32CuratedPartIds(Set<String> ids) {
        this.ids = Set.copyOf(ids);
    }

    public static Stm32CuratedPartIds load(Path selectionPath, ParserLimits limits,
            CancellationToken cancellation) throws IOException, DiagnosticException {
        Objects.requireNonNull(selectionPath, "selectionPath");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        if (!Files.isRegularFile(selectionPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("STM32 selection path is not a regular file");
        }
        long length = Files.size(selectionPath);
        if (length > limits.maxInputBytes() || length > limits.maxAllocationBytes()) {
            throw new IOException("STM32 selection exceeds parser byte limits");
        }
        byte[] input = Files.readAllBytes(selectionPath);
        cancellation.throwIfCancellationRequested();
        if (!SELECTION_SHA256.equals(sha256(input))) {
            throw new IOException("STM32 selection digest does not match the pinned snapshot");
        }
        Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(input, limits, cancellation);
        List<?> parts = (List<?>) root.get("parts");
        return new Stm32CuratedPartIds(parts.stream()
            .map(part -> (String) ((Map<?, ?>) part).get("exactPart"))
            .collect(Collectors.toUnmodifiableSet()));
    }

    @Override
    public boolean containsExactPart(String exactPart) {
        return ids.contains(exactPart);
    }

    public int size() {
        return ids.size();
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
