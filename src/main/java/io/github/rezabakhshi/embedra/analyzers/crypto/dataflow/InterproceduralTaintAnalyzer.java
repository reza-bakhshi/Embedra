package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;

/**
 * Pure static analysis engine performing interprocedural taint propagation across
 * whole-program call graphs and function parameter boundaries (AN-010, AN-013, AN-014).
 *
 * <p>Tracks cryptographic taint sources (e.g., constant tables, OTP/eFuse reads, candidate keys)
 * across call edges to verified cryptographic sinks (e.g., hardware MMIO writes, encryption APIs).</p>
 */
public final class InterproceduralTaintAnalyzer {

    private static final Set<String> SANITIZING_OPERATIONS = Set.of(
            "MEMSET_ZERO", "SECURE_ZERO", "EXPLICIT_BZERO", "FREE", "WIPE"
    );

    /**
     * Executes interprocedural taint analysis across call edges.
     *
     * @param sources list of taint source locations
     * @param sinks list of target cryptographic sinks
     * @param edges list of interprocedural call graph edges
     * @param limits parser and resource limits
     * @param token cancellation token
     * @return verified taint propagation report
     * @throws DiagnosticException if limits are exceeded or cancellation occurs
     */
    public InterproceduralTaintReport analyze(
            List<TaintSource> sources,
            List<TaintSink> sinks,
            List<InterproceduralCallEdge> edges,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        List<TaintSource> safeSources = sources == null ? List.of() : List.copyOf(sources);
        List<TaintSink> safeSinks = sinks == null ? List.of() : List.copyOf(sinks);
        List<InterproceduralCallEdge> safeEdges = edges == null ? List.of() : List.copyOf(edges);

        long totalObjects = (long) safeSources.size() + safeSinks.size() + safeEdges.size();
        if (totalObjects > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_CALLGRAPH_EXCEEDED,
                    "Interprocedural taint analysis exceeded max objects limit: " + totalObjects, null));
        }

        // Index sinks by target function name and address
        Map<String, List<TaintSink>> sinksByFunction = new HashMap<>();
        Map<Long, List<TaintSink>> sinksByAddress = new HashMap<>();
        for (TaintSink sink : safeSinks) {
            sinksByFunction.computeIfAbsent(sink.targetFunctionOrRegister(), k -> new ArrayList<>()).add(sink);
            sinksByAddress.computeIfAbsent(sink.address(), k -> new ArrayList<>()).add(sink);
        }

        // Build outgoing call graph adjacency list
        Map<String, List<InterproceduralCallEdge>> outgoingByFunction = new HashMap<>();
        for (InterproceduralCallEdge edge : safeEdges) {
            outgoingByFunction.computeIfAbsent(edge.callerFunction(), k -> new ArrayList<>()).add(edge);
        }

        List<TaintPropagationPath> verifiedPaths = new ArrayList<>();
        Set<String> taintedFunctions = new LinkedHashSet<>();
        List<CryptoFinding> findings = new ArrayList<>();
        int maxDepthReached = 0;

        for (TaintSource source : safeSources) {
            token.throwIfCancellationRequested();

            Queue<PathState> worklist = new ArrayDeque<>();
            worklist.add(new PathState(source.label(), 0, new ArrayList<>(), false));
            taintedFunctions.add(source.label());

            Set<String> visitedStates = new HashSet<>();

            while (!worklist.isEmpty()) {
                token.throwIfCancellationRequested();
                PathState current = worklist.poll();

                maxDepthReached = Math.max(maxDepthReached, current.depth);

                if (current.depth >= limits.maxNestingDepth()) {
                    continue;
                }

                // Check direct sink match in current function
                List<TaintSink> directSinks = sinksByFunction.get(current.currentFunction);
                if (directSinks != null) {
                    for (TaintSink sink : directSinks) {
                        TaintPropagationPath path = new TaintPropagationPath(
                                source, sink, current.steps, current.isSanitized, current.depth);
                        verifiedPaths.add(path);

                        findings.add(createCorrelatedFinding(source, sink, path));
                    }
                }

                // Propagate along outgoing interprocedural call edges
                List<InterproceduralCallEdge> outgoing = outgoingByFunction.get(current.currentFunction);
                if (outgoing != null) {
                    for (InterproceduralCallEdge edge : outgoing) {
                        String stateKey = edge.calleeFunction() + ":" + edge.parameterIndex();
                        if (visitedStates.add(stateKey)) {
                            taintedFunctions.add(edge.calleeFunction());

                            boolean sanitized = current.isSanitized || isSanitizingEdge(edge);
                            List<TaintPropagationStep> nextSteps = new ArrayList<>(current.steps);
                            nextSteps.add(new TaintPropagationStep(
                                    edge.callSiteAddress(),
                                    edge.calleeAddress(),
                                    edge.callerFunction(),
                                    edge.calleeFunction(),
                                    "PARAM_TRANSFER(arg=" + edge.taintedArgument()
                                            + ", param=" + edge.parameterIndex() + ")",
                                    edge.taintedArgument()
                            ));

                            worklist.add(new PathState(
                                    edge.calleeFunction(),
                                    current.depth + 1,
                                    nextSteps,
                                    sanitized
                            ));
                        }
                    }
                }
            }
        }

        return new InterproceduralTaintReport(
                verifiedPaths,
                taintedFunctions,
                safeSources.size(),
                safeSinks.size(),
                maxDepthReached,
                findings
        );
    }

    private boolean isSanitizingEdge(InterproceduralCallEdge edge) {
        String calleeUpper = edge.calleeFunction().toUpperCase();
        for (String op : SANITIZING_OPERATIONS) {
            if (calleeUpper.contains(op)) {
                return true;
            }
        }
        return false;
    }

    private CryptoFinding createCorrelatedFinding(
            TaintSource source,
            TaintSink sink,
            TaintPropagationPath path) {

        String findingId = "TAINT_" + source.id() + "_" + sink.id();
        CryptoCategory category = CryptoCategory.CIPHER_SYMMETRIC;
        CryptoAlgorithm algorithm = CryptoAlgorithm.AES_256;

        if (sink.targetFunctionOrRegister().toLowerCase().contains("sha")) {
            category = CryptoCategory.HASH_MAC;
            algorithm = CryptoAlgorithm.SHA256;
        }

        CryptoConfidence confidence = path.isSanitized() ? CryptoConfidence.PLAUSIBLE : CryptoConfidence.CONFIRMED;

        Set<CryptoEvidenceLayer> layers = Set.of(
                CryptoEvidenceLayer.DATA_FLOW,
                CryptoEvidenceLayer.HARDWARE_PERIPHERAL
        );

        String explanation = String.format(
                "Interprocedural dataflow verified from source [%s at 0x%08X] to sink [%s at 0x%08X] "
                        + "across %d call boundaries (sanitized=%b)",
                source.label(), source.address(), sink.targetFunctionOrRegister(),
                sink.address(), path.depth(), path.isSanitized()
        );

        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("sourceKind", source.kind().name());
        attrs.put("sinkKind", sink.kind().name());
        attrs.put("callDepth", String.valueOf(path.depth()));
        attrs.put("sanitized", String.valueOf(path.isSanitized()));

        return new CryptoFinding(
                findingId,
                sink.address(),
                16,
                category,
                algorithm,
                confidence,
                layers,
                explanation,
                "[REDACTED_SECRET]",
                true,
                attrs
        );
    }

    private record PathState(
            String currentFunction,
            int depth,
            List<TaintPropagationStep> steps,
            boolean isSanitized) {
    }
}
