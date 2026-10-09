package io.github.rezabakhshi.embedra.ghidra.diff;

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

/**
 * Ghidra plugin hosting the Embedra firmware and workspace differential analysis provider (AN-006, AN-008).
 */
@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = "Embedra",
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Embedra Firmware Workspace Diff",
        description = "Differential comparison across functions, symbols, strings, metadata, memory, and partitions"
)
public class EmbedraDiffPlugin extends ProgramPlugin {

    private EmbedraDiffProvider provider;

    public EmbedraDiffPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        provider = new EmbedraDiffProvider(tool, getName());

        DockingAction diffAction = new DockingAction("Compare Firmware Workspaces", getName()) {
            @Override
            public void actionPerformed(docking.ActionContext context) {
                if (provider != null) {
                    refreshPrograms();
                    tool.showComponentProvider(provider, true);
                }
            }
        };
        diffAction.setMenuBarData(new MenuData(
                new String[]{"Tools", "Embedra", "Compare Firmware Workspaces..."}, null, "EmbedraDiff"));
        diffAction.setDescription("Open the Embedra Firmware and Workspace Diff panel");
        tool.addAction(diffAction);
    }

    private void refreshPrograms() {
        if (provider != null) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            Program[] openProgs = pm != null ? pm.getAllOpenPrograms() : new Program[0];
            provider.updateOpenPrograms(openProgs, getCurrentProgram());
        }
    }

    @Override
    protected void programActivated(Program program) {
        refreshPrograms();
    }

    @Override
    protected void programDeactivated(Program program) {
        refreshPrograms();
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            provider.dispose();
            provider = null;
        }
        super.dispose();
    }

    public EmbedraDiffProvider getProvider() {
        return provider;
    }
}
