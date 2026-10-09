package io.github.rezabakhshi.embedra.ghidra.findings;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

/**
 * Ghidra plugin hosting the Embedra findings panel, suppression engine, and export actions (AN-006, AN-008).
 */
@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = "Embedra",
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Embedra Findings and Lead Management",
        description = "Sortable findings panel, suppression rules, bookmarks, and export (AN-006, AN-008)"
)
public class EmbedraFindingsPlugin extends ProgramPlugin {

    private EmbedraFindingsProvider provider;

    public EmbedraFindingsPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        provider = new EmbedraFindingsProvider(tool, getName());
    }

    @Override
    protected void programActivated(Program program) {
        if (provider != null) {
            provider.setProgram(program);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        if (provider != null) {
            provider.setProgram(null);
        }
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            provider.dispose();
            provider = null;
        }
        super.dispose();
    }

    public EmbedraFindingsProvider getProvider() {
        return provider;
    }
}
