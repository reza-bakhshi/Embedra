package io.github.rezabakhshi.embedra.targets.rp.catalog;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Authoritative in-memory catalog containing Raspberry Pi silicon parts and board profiles.
 */
public final class RpDeviceCatalog {

    private final Map<String, RpSiliconRecord> siliconByPart;

    private final Map<String, RpBoardProfile> profilesById;

    private final String catalogSha256;

    private final String boardProfilesSha256;

    public RpDeviceCatalog(
            List<RpSiliconRecord> siliconRecords,
            List<RpBoardProfile> boardProfiles,
            String catalogSha256,
            String boardProfilesSha256) {
        Objects.requireNonNull(siliconRecords, "siliconRecords must not be null");
        Objects.requireNonNull(boardProfiles, "boardProfiles must not be null");
        this.catalogSha256 = Objects.requireNonNull(catalogSha256, "catalogSha256 must not be null");
        this.boardProfilesSha256 = Objects.requireNonNull(boardProfilesSha256, "boardProfilesSha256 must not be null");

        Map<String, RpSiliconRecord> siliconMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (RpSiliconRecord record : siliconRecords) {
            if (siliconMap.put(record.exactPart(), record) != null) {
                throw new IllegalArgumentException("Duplicate silicon exact part: " + record.exactPart());
            }
        }
        this.siliconByPart = Collections.unmodifiableMap(siliconMap);

        Map<String, RpBoardProfile> boardMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (RpBoardProfile profile : boardProfiles) {
            if (!this.siliconByPart.containsKey(profile.siliconPart())) {
                throw new IllegalArgumentException("Board profile " + profile.profileId()
                        + " references unknown silicon part: " + profile.siliconPart());
            }
            if (boardMap.put(profile.profileId(), profile) != null) {
                throw new IllegalArgumentException("Duplicate board profile ID: " + profile.profileId());
            }
        }
        this.profilesById = Collections.unmodifiableMap(boardMap);
    }

    public static RpDeviceCatalog empty() {
        return new RpDeviceCatalog(List.of(), List.of(), "", "");
    }

    public List<RpSiliconRecord> siliconRecords() {
        return List.copyOf(siliconByPart.values());
    }

    public List<RpBoardProfile> boardProfiles() {
        return List.copyOf(profilesById.values());
    }

    public Optional<RpSiliconRecord> findExactPart(String part) {
        if (part == null || part.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(siliconByPart.get(part.trim()));
    }

    public RpSiliconRecord requireExactPart(String part) {
        return findExactPart(part).orElseThrow(() ->
                new IllegalArgumentException("Unknown Raspberry Pi silicon part: " + part));
    }

    public Optional<RpBoardProfile> findBoardProfile(String profileId) {
        if (profileId == null || profileId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(profilesById.get(profileId.trim()));
    }

    public RpBoardProfile requireBoardProfile(String profileId) {
        return findBoardProfile(profileId).orElseThrow(() ->
                new IllegalArgumentException("Unknown Raspberry Pi board profile: " + profileId));
    }

    public String catalogSha256() {
        return catalogSha256;
    }

    public String boardProfilesSha256() {
        return boardProfilesSha256;
    }
}
