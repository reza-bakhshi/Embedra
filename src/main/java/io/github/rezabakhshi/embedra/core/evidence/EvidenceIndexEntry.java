package io.github.rezabakhshi.embedra.core.evidence;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Single machine-readable evidence record tying a requirement and task to its test and artifacts.
 */
public record EvidenceIndexEntry(
        String requirementId,
        String taskId,
        String testName,
        String fixtureId,
        EvidenceResultStatus resultStatus,
        List<String> retainedArtifacts,
        String notes) {

    public EvidenceIndexEntry {
        Objects.requireNonNull(requirementId, "requirementId");
        if (requirementId.isBlank()) {
            throw new IllegalArgumentException("requirementId must not be blank");
        }
        Objects.requireNonNull(taskId, "taskId");
        if (taskId.isBlank()) {
            throw new IllegalArgumentException("taskId must not be blank");
        }
        Objects.requireNonNull(testName, "testName");
        if (testName.isBlank()) {
            throw new IllegalArgumentException("testName must not be blank");
        }
        Objects.requireNonNull(resultStatus, "resultStatus");
        Objects.requireNonNull(retainedArtifacts, "retainedArtifacts");
        List<String> sortedArtifacts = new ArrayList<>(retainedArtifacts);
        Collections.sort(sortedArtifacts);
        retainedArtifacts = List.copyOf(sortedArtifacts);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("requirementId", requirementId);
        map.put("taskId", taskId);
        map.put("testName", testName);
        if (fixtureId != null && !fixtureId.isBlank()) {
            map.put("fixtureId", fixtureId);
        }
        map.put("resultStatus", resultStatus.name());
        map.put("retainedArtifacts", retainedArtifacts);
        if (notes != null && !notes.isBlank()) {
            map.put("notes", notes);
        }
        return map;
    }

    public static EvidenceIndexEntry fromMap(Map<?, ?> map) {
        String requirementId = requireString(map, "requirementId");
        String taskId = requireString(map, "taskId");
        String testName = requireString(map, "testName");
        String fixtureId = map.get("fixtureId") instanceof String s ? s : null;
        String statusStr = requireString(map, "resultStatus");
        EvidenceResultStatus resultStatus = EvidenceResultStatus.parse(statusStr);

        List<String> artifacts = new ArrayList<>();
        if (map.get("retainedArtifacts") instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof String s && !s.isBlank()) {
                    artifacts.add(s);
                }
            }
        }
        String notes = map.get("notes") instanceof String s ? s : null;

        return new EvidenceIndexEntry(requirementId, taskId, testName, fixtureId, resultStatus, artifacts, notes);
    }

    private static String requireString(Map<?, ?> map, String key) {
        Object val = map.get(key);
        if (val instanceof String s && !s.isBlank()) {
            return s;
        }
        throw new IllegalArgumentException("Missing or blank string field: " + key);
    }
}
