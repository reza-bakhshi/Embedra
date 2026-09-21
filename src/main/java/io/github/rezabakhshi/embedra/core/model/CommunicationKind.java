package io.github.rezabakhshi.embedra.core.model;

/** Inter-processor communication or synchronization mechanism. */
public enum CommunicationKind {
    MAILBOX,
    FIFO,
    HARDWARE_SEMAPHORE,
    INTER_CORE_INTERRUPT
}
