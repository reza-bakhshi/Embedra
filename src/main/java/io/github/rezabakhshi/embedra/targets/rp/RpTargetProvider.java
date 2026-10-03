package io.github.rezabakhshi.embedra.targets.rp;

import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import java.util.List;

/**
 * Pure contract for Raspberry Pi silicon families isolating memory layout,
 * execution topology, and ISA selection.
 */
public interface RpTargetProvider {

    String providerId();

    String series();

    RpSiliconRecord siliconRecord();

    LanguageSelection selectLanguage(String bootArchitecture);

    ExecutionTopology buildTopology(String bootArchitecture, RpBoardProfile boardProfile);

    List<RpMemoryRegion> memoryRegions(RpBoardProfile boardProfile);

    boolean isAddressMapped(long address, RpBoardProfile boardProfile);

    boolean isValidEntryPoint(long address, String bootArchitecture, RpBoardProfile boardProfile);

    List<RpPioBlock> pioBlocks();
}
