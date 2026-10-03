package io.github.rezabakhshi.embedra.targets.rp;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.rp.board.RpBoardPlan;
import io.github.rezabakhshi.embedra.targets.rp.board.RpBoardProfileEngine;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import java.util.Objects;
import java.util.Optional;

/**
 * Resolves RP target providers from device catalog entries and board profiles.
 */
public final class RpTargetResolver {

    private final RpDeviceCatalog catalog;

    public RpTargetResolver(RpDeviceCatalog catalog) {
        this.catalog = Objects.requireNonNull(catalog, "catalog must not be null");
    }

    public Optional<RpTargetProvider> resolvePart(String partName) {
        if (partName == null || partName.isBlank()) {
            return Optional.empty();
        }
        Optional<RpSiliconRecord> siliconOpt = catalog.findExactPart(partName.trim());
        if (siliconOpt.isEmpty()) {
            return Optional.empty();
        }
        RpSiliconRecord silicon = siliconOpt.get();
        return Optional.of(createProvider(silicon));
    }

    public Optional<RpTargetProvider> resolveBoard(String boardId) {
        if (boardId == null || boardId.isBlank()) {
            return Optional.empty();
        }
        Optional<RpBoardProfile> boardOpt = catalog.findBoardProfile(boardId.trim());
        if (boardOpt.isEmpty()) {
            return Optional.empty();
        }
        return resolvePart(boardOpt.get().siliconPart());
    }

    /**
     * Resolves target provider together with optional board profile and board plan.
     */
    public Optional<RpTargetResolution> resolveTarget(String partName, String boardId)
            throws DiagnosticException {
        boolean hasBoard = boardId != null && !boardId.isBlank();
        boolean hasPart = partName != null && !partName.isBlank();

        if (!hasBoard && !hasPart) {
            return Optional.empty();
        }

        if (hasBoard) {
            Optional<RpBoardProfile> boardOpt = catalog.findBoardProfile(boardId.trim());
            if (boardOpt.isEmpty()) {
                return Optional.empty();
            }
            RpBoardProfile profile = boardOpt.get();
            String siliconPart = profile.siliconPart();

            if (hasPart && !siliconPart.equalsIgnoreCase(partName.trim())) {
                // Explicit silicon part requested does not match board profile
                return Optional.empty();
            }

            RpSiliconRecord silicon = catalog.requireExactPart(siliconPart);
            RpTargetProvider provider = createProvider(silicon);
            RpBoardPlan plan = RpBoardProfileEngine.plan(profile, silicon);
            return Optional.of(new RpTargetResolution(provider, Optional.of(profile), Optional.of(plan)));
        }

        Optional<RpSiliconRecord> siliconOpt = catalog.findExactPart(partName.trim());
        if (siliconOpt.isEmpty()) {
            return Optional.empty();
        }
        RpTargetProvider provider = createProvider(siliconOpt.get());
        return Optional.of(new RpTargetResolution(provider, Optional.empty(), Optional.empty()));
    }

    public RpTargetProvider createProvider(RpSiliconRecord silicon) {
        Objects.requireNonNull(silicon, "silicon must not be null");
        if ("RP2040".equalsIgnoreCase(silicon.exactPart())) {
            return new Rp2040TargetProvider(silicon);
        } else if (silicon.exactPart().toUpperCase().startsWith("RP2350")
                || silicon.exactPart().toUpperCase().startsWith("RP2354")) {
            return new Rp2350TargetProvider(silicon);
        }
        throw new IllegalArgumentException("Unsupported RP silicon part: " + silicon.exactPart());
    }

    public RpDeviceCatalog catalog() {
        return catalog;
    }

    /**
     * Complete target resolution carrying target provider, optional board profile, and optional board plan.
     */
    public record RpTargetResolution(
            RpTargetProvider provider,
            Optional<RpBoardProfile> boardProfile,
            Optional<RpBoardPlan> boardPlan) {

        public RpTargetResolution {
            Objects.requireNonNull(provider, "provider must not be null");
            Objects.requireNonNull(boardProfile, "boardProfile must not be null");
            Objects.requireNonNull(boardPlan, "boardPlan must not be null");
        }
    }
}
