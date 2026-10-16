package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * End-to-end verified path connecting a taint source to a cryptographic sink across function boundaries.
 */
public record TaintPropagationPath(
        TaintSource source,
        TaintSink sink,
        List<TaintPropagationStep> steps,
        boolean isSanitized,
        int depth) {

    public TaintPropagationPath {
        Objects.requireNonNull(source, "source must not be null");
        Objects.requireNonNull(sink, "sink must not be null");
        steps = steps == null ? List.of() : Collections.unmodifiableList(List.copyOf(steps));
    }
}
