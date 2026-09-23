package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;

/** Pure bounded contract for one partition category. */
public interface EspPartitionHandler {
    EspPartitionHandlerKind kind();

    boolean supports(EspPartitionEntry entry);

    EspPartitionInspection inspect(EspExtractedPartition partition,
            ParserLimits limits, CancellationToken cancellation)
            throws DiagnosticException;
}
