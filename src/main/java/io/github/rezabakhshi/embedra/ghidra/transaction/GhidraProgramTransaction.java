package io.github.rezabakhshi.embedra.ghidra.transaction;

import ghidra.program.model.listing.Program;
import java.util.Objects;

/** One explicit Ghidra program transaction that rolls back unless committed. */
public final class GhidraProgramTransaction implements AutoCloseable {
    private final Program program;

    private final int transactionId;

    private boolean commitRequested;

    private boolean closed;

    private GhidraProgramTransaction(Program program, String description) {
        this.program = Objects.requireNonNull(program, "program");
        if (description == null || description.isBlank()) {
            throw new IllegalArgumentException("Transaction description must not be blank");
        }
        transactionId = program.startTransaction(description);
    }

    public static GhidraProgramTransaction start(Program program, String description) {
        return new GhidraProgramTransaction(program, description);
    }

    public void commit() {
        if (closed) {
            throw new IllegalStateException("Transaction is already closed");
        }
        commitRequested = true;
    }

    public boolean isClosed() {
        return closed;
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            program.endTransaction(transactionId, commitRequested);
        }
    }
}
