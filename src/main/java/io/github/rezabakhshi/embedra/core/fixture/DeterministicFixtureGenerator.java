package io.github.rezabakhshi.embedra.core.fixture;

import java.util.Map;

/**
 * Contract for reproducible fixture generators (SPEC-12, SPEC-13).
 */
public interface DeterministicFixtureGenerator {

    /**
     * Unique identifier for this deterministic generator.
     */
    String generatorId();

    /**
     * Generates fixture bytes deterministically from input parameters.
     *
     * @param parameters key-value parameters guiding generation
     * @return generated binary fixture bytes
     * @throws Exception if generation fails
     */
    byte[] generate(Map<String, Object> parameters) throws Exception;
}
