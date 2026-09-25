package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCatalogRecord;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspDeviceCatalog;
import java.util.List;
import java.util.Locale;

/** Pure contract isolating all SoC and ISA knowledge from shared ESP workflows. */
public interface EspTargetProvider {
    String providerId();

    String providerVersion();

    String canonicalIdentity();

    int chipId();

    SupportDecision supports(EspImage image);

    LanguageSelection language();

    MemoryClassification classify(AddressRange range);

    EntryPointDecision validateEntry(long address, EspImage image);

    ExecutionTopology topology(EspImage image);

    /** Exact silicon variants sourced from the generated Espressif catalog. */
    default List<EspCatalogRecord> catalogVariants(EspDeviceCatalog catalog) {
        String providerDevice = providerId().substring(providerId().lastIndexOf('.') + 1)
            .replaceAll("[^a-z0-9]", "");
        return catalog.silicon().stream()
            .filter(record -> record.series().toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]", "").equals(providerDevice))
            .toList();
    }
}
