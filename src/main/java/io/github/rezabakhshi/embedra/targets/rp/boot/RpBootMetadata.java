package io.github.rezabakhshi.embedra.targets.rp.boot;

import java.util.Map;

/**
 * Common pure interface for Raspberry Pi boot metadata parsed from flash images.
 */
public interface RpBootMetadata {

    String series();

    long flashBaseAddress();

    long entryPoint();

    boolean isValid();

    Map<String, Object> metadataProperties();
}
