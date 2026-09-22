package io.github.rezabakhshi.embedra.ghidra.transaction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class GhidraProgramTransactionTest {
    @Test
    void closesAsRollbackUnlessCommitWasRequested() {
        RecordingProgram rollbackProgram = new RecordingProgram();
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                rollbackProgram.proxy(), "Embedra rollback")) {
            assertFalse(transaction.isClosed());
            assertEquals(List.of("start:Embedra rollback"), rollbackProgram.events);
        }
        assertEquals(List.of("start:Embedra rollback", "end:42:false"), rollbackProgram.events);

        RecordingProgram commitProgram = new RecordingProgram();
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                commitProgram.proxy(), "Embedra commit")) {
            transaction.commit();
        }
        assertEquals(List.of("start:Embedra commit", "end:42:true"), commitProgram.events);
    }

    @Test
    void cannotCommitOrCloseTwiceAfterCompletion() {
        RecordingProgram recording = new RecordingProgram();
        GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
            recording.proxy(), "Embedra once");
        assertFalse(transaction.isClosed());
        transaction.commit();
        transaction.close();
        assertTrue(transaction.isClosed());

        assertThrows(IllegalStateException.class, transaction::commit);
        transaction.close();
        assertEquals(List.of("start:Embedra once", "end:42:true"), recording.events);
    }

    private static final class RecordingProgram {
        private final List<String> events = new ArrayList<>();

        Program proxy() {
            return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[] {Program.class}, (proxy, method, arguments) -> switch (method.getName()) {
                    case "startTransaction" -> {
                        events.add("start:" + arguments[0]);
                        yield 42;
                    }
                    case "endTransaction" -> {
                        events.add("end:" + arguments[0] + ":" + arguments[1]);
                        yield true;
                    }
                    case "toString" -> "RecordingProgram";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    default -> defaultValue(method.getReturnType());
                });
        }

        private static Object defaultValue(Class<?> type) {
            if (!type.isPrimitive() || type == void.class) {
                return null;
            }
            if (type == boolean.class) {
                return false;
            }
            if (type == char.class) {
                return '\0';
            }
            return 0;
        }
    }
}
