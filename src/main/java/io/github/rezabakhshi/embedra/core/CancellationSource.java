package io.github.rezabakhshi.embedra.core;

import java.util.concurrent.atomic.AtomicBoolean;

/** Thread-safe owner of a cooperative cancellation token. */
public final class CancellationSource {
    private final AtomicBoolean cancelled = new AtomicBoolean();

    private final CancellationToken token = cancelled::get;

    public CancellationToken token() {
        return token;
    }

    public void cancel() {
        cancelled.set(true);
    }
}
