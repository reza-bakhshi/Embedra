package io.github.rezabakhshi.embedra.formats.rp.uf2;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Bounded, integrity-first parser for UF2 container files targeting Raspberry Pi devices.
 */
public final class RpUf2Parser {

    private RpUf2Parser() {
    }

    public static RpUf2Image parse(Path path, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(path, "path must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        try {
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(path)
                    || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw failure(DiagnosticCode.RP_UF2_INVALID, "UF2 file must be a regular non-symlink file: " + path);
            }
            long size = Files.size(path);
            if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED, "UF2 file exceeds maximum input bytes: " + size);
            }
            byte[] bytes = Files.readAllBytes(path);
            token.throwIfCancellationRequested();
            return parse(bytes, limits, token);
        } catch (DiagnosticException e) {
            throw e;
        } catch (IOException e) {
            throw failure(DiagnosticCode.RP_UF2_INVALID, "Failed to read UF2 file: " + e.getMessage());
        }
    }

    public static RpUf2Image parse(byte[] bytes, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (bytes.length < RpUf2Block.BLOCK_SIZE || bytes.length % RpUf2Block.BLOCK_SIZE != 0) {
            throw failure(DiagnosticCode.RP_UF2_INVALID,
                    "UF2 payload length (" + bytes.length + ") is not a non-zero multiple of 512 bytes");
        }

        int totalBlocks = bytes.length / RpUf2Block.BLOCK_SIZE;
        if (totalBlocks > limits.maxObjects()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED, "UF2 block count exceeds limit: " + totalBlocks);
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        List<RpUf2Block> blocks = new ArrayList<>(totalBlocks);
        Set<RpUf2Family> detectedFamilies = new LinkedHashSet<>();

        for (int i = 0; i < totalBlocks; i++) {
            token.throwIfCancellationRequested();

            long magicStart0 = Integer.toUnsignedLong(buffer.getInt());
            long magicStart1 = Integer.toUnsignedLong(buffer.getInt());
            if (magicStart0 != RpUf2Block.EXPECTED_MAGIC_START0 || magicStart1 != RpUf2Block.EXPECTED_MAGIC_START1) {
                throw failure(DiagnosticCode.RP_UF2_MAGIC_MISMATCH,
                        "UF2 block " + i + " magic start mismatch: 0x" + Long.toHexString(magicStart0)
                                + ", 0x" + Long.toHexString(magicStart1));
            }

            int flags = buffer.getInt();
            long targetAddr = Integer.toUnsignedLong(buffer.getInt());
            int payloadSize = buffer.getInt();
            int blockNo = buffer.getInt();
            int numBlocks = buffer.getInt();
            long familyId = Integer.toUnsignedLong(buffer.getInt());

            if (payloadSize <= 0 || payloadSize > 476) {
                throw failure(DiagnosticCode.RP_UF2_INVALID,
                        "UF2 block " + i + " has invalid payload size: " + payloadSize);
            }
            if (numBlocks != totalBlocks) {
                throw failure(DiagnosticCode.RP_UF2_INVALID,
                        "UF2 block " + i + " declares total blocks " + numBlocks + " but file has " + totalBlocks);
            }
            if (blockNo < 0 || blockNo >= numBlocks) {
                throw failure(DiagnosticCode.RP_UF2_INVALID,
                        "UF2 block " + i + " has invalid block number: " + blockNo);
            }

            byte[] fullData = new byte[476];
            buffer.get(fullData);
            byte[] payload = Arrays.copyOf(fullData, payloadSize);

            long magicEnd = Integer.toUnsignedLong(buffer.getInt());
            if (magicEnd != RpUf2Block.EXPECTED_MAGIC_END) {
                throw failure(DiagnosticCode.RP_UF2_MAGIC_MISMATCH,
                        "UF2 block " + i + " magic end mismatch: 0x" + Long.toHexString(magicEnd));
            }

            RpUf2Block block = new RpUf2Block(
                    magicStart0, magicStart1, flags, targetAddr,
                    payloadSize, blockNo, numBlocks, familyId, payload, magicEnd);
            blocks.add(block);

            if (block.hasFamilyId()) {
                Optional<RpUf2Family> familyOpt = RpUf2Family.fromFamilyId(familyId);
                if (familyOpt.isEmpty()) {
                    throw failure(DiagnosticCode.RP_UF2_FAMILY_MISMATCH,
                            "UF2 block " + i + " has unsupported Raspberry Pi family ID: 0x"
                                    + Long.toHexString(familyId));
                }
                detectedFamilies.add(familyOpt.get());
            }
        }

        if (detectedFamilies.isEmpty()) {
            throw failure(DiagnosticCode.RP_UF2_FAMILY_MISMATCH,
                    "UF2 file does not specify a valid Raspberry Pi family ID");
        }

        return new RpUf2Image(blocks, detectedFamilies);
    }

    private static DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, null));
    }
}
