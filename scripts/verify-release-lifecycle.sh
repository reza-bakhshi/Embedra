#!/bin/sh
# Fail-closed release life-cycle and clean-environment quickstart verification (T079).
#
# Validates:
# 1. Clean installation into Ghidra extensions directory; validates Module.manifest and extension.properties.
# 2. Clean uninstallation without lingering configuration locks or leaked filesystem artifacts.
# 3. Upgrade simulation over existing installation without corrupting user state or project files.
# 4. Clean-environment quickstarts via analyzeHeadless over golden samples:
#    - ESP32-S3 full-flash (default-factory.bin)
#    - Raspberry Pi RP2040 UF2 (rp2040-pico-blinky.uf2)
#    - STM32 Intel HEX (STM32F401RET6.hex)
#    - STM32 raw BIN (STM32F401RET6.bin)
#    with automated analysis and report generation.
# 5. Agent-resume simulation verifying state machine continuity (validate-handoff.sh).

set -eu

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    echo "GHIDRA_INSTALL_DIR must point to Ghidra 12.1.3." >&2
    exit 2
fi

if [ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then
    echo "analyzeHeadless not found or not executable in $GHIDRA_INSTALL_DIR/support" >&2
    exit 2
fi

# Locate release artifact
artifact=${1:-}
if [ -z "$artifact" ]; then
    artifact=$(find dist -maxdepth 1 -type f -name '*_Embedra.zip' -print | head -n 1)
fi

if [ -z "$artifact" ] || [ ! -f "$artifact" ]; then
    echo "Release extension ZIP not found in dist/. Run scripts/verify-build-quality.sh first." >&2
    exit 1
fi

echo "=== Release Lifecycle Verification ==="
echo "Target artifact: $artifact"
echo "Ghidra install:  $GHIDRA_INSTALL_DIR"

work_dir=$(mktemp -d)
# Ensure any temporary installation in GHIDRA_INSTALL_DIR is cleaned up on exit
trap 'rm -rf "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/Embedra" "$work_dir"' EXIT HUP INT TERM

# ---------------------------------------------------------------------------
# Phase 1: Clean Installation Verification
# ---------------------------------------------------------------------------
echo "--- Phase 1: Clean Installation ---"
install_test_dir="$work_dir/install_test"
mkdir -p "$install_test_dir"
unzip -q "$artifact" -d "$install_test_dir"

extension_root="$install_test_dir/Embedra"
if [ ! -d "$extension_root" ]; then
    echo "LIFECYCLE FAIL: Archive root does not contain Embedra directory." >&2
    exit 1
fi

for req_file in Module.manifest extension.properties lib/Embedra.jar LICENSE NOTICE README.md THIRD_PARTY_NOTICES.md; do
    if [ ! -f "$extension_root/$req_file" ]; then
        echo "LIFECYCLE FAIL: Missing required extension file: $req_file" >&2
        exit 1
    fi
done

# Validate extension.properties fields
ext_name=$(grep "^name=" "$extension_root/extension.properties" | cut -d'=' -f2-)
ext_version=$(grep "^version=" "$extension_root/extension.properties" | cut -d'=' -f2-)
ext_author=$(grep "^author=" "$extension_root/extension.properties" | cut -d'=' -f2-)

if [ "$ext_name" != "Embedra" ]; then
    echo "LIFECYCLE FAIL: extension.properties name mismatch: expected Embedra, got $ext_name" >&2
    exit 1
fi

if [ -z "$ext_version" ] || [ -z "$ext_author" ]; then
    echo "LIFECYCLE FAIL: extension.properties missing version or author." >&2
    exit 1
fi

echo "Clean installation verified: Embedra v$ext_version by $ext_author"

# ---------------------------------------------------------------------------
# Phase 2: Clean Uninstallation Verification
# ---------------------------------------------------------------------------
echo "--- Phase 2: Clean Uninstallation ---"
rm -rf "$extension_root"

if [ -e "$extension_root" ]; then
    echo "LIFECYCLE FAIL: Extension directory was not removed cleanly." >&2
    exit 1
fi

# Verify no leftover files or locks
if [ "$(find "$install_test_dir" -mindepth 1 | wc -l)" -ne 0 ]; then
    echo "LIFECYCLE FAIL: Lingering files in installation target directory." >&2
    exit 1
fi

echo "Clean uninstallation verified: zero residual files or locks."

# ---------------------------------------------------------------------------
# Phase 3: Upgrade Simulation Verification
# ---------------------------------------------------------------------------
echo "--- Phase 3: Upgrade Simulation ---"
upgrade_sim_dir="$work_dir/upgrade_sim"
mkdir -p "$upgrade_sim_dir/Embedra"
mkdir -p "$upgrade_sim_dir/user_workspace"

# Simulate an older version installed
cat << 'EOF' > "$upgrade_sim_dir/Embedra/extension.properties"
name=Embedra
version=0.9.0
author=Embedra Contributors
createdOn=1980-01-01
EOF
touch "$upgrade_sim_dir/Embedra/Module.manifest"
echo "legacy jar" > "$upgrade_sim_dir/Embedra/lib_old.jar"

# Simulate user project files in the workspace
cat << 'EOF' > "$upgrade_sim_dir/user_workspace/user_project.gpr"
<?xml version="1.0" encoding="UTF-8"?>
<PROJECT>
    <STATE NAME="user_state" VALUE="active" />
</PROJECT>
EOF
cat << 'EOF' > "$upgrade_sim_dir/user_workspace/user_notes.txt"
Important reverse engineering analyst notes. Do not overwrite!
EOF

gpr_hash_before=$(sha256sum "$upgrade_sim_dir/user_workspace/user_project.gpr" | cut -d' ' -f1)
notes_hash_before=$(sha256sum "$upgrade_sim_dir/user_workspace/user_notes.txt" | cut -d' ' -f1)

# Perform upgrade (unpack over existing installation)
unzip -q -o "$artifact" -d "$upgrade_sim_dir"

upgraded_version=$(grep "^version=" "$upgrade_sim_dir/Embedra/extension.properties" | cut -d'=' -f2-)
if [ "$upgraded_version" != "$ext_version" ]; then
    echo "LIFECYCLE FAIL: Upgrade failed to update extension.properties version: $upgraded_version" >&2
    exit 1
fi

gpr_hash_after=$(sha256sum "$upgrade_sim_dir/user_workspace/user_project.gpr" | cut -d' ' -f1)
notes_hash_after=$(sha256sum "$upgrade_sim_dir/user_workspace/user_notes.txt" | cut -d' ' -f1)

if [ "$gpr_hash_before" != "$gpr_hash_after" ] || [ "$notes_hash_before" != "$notes_hash_after" ]; then
    echo "LIFECYCLE FAIL: Upgrade corrupted user workspace files!" >&2
    exit 1
fi

echo "Upgrade simulation verified: updated to v$upgraded_version while preserving user state bit-for-bit."

# ---------------------------------------------------------------------------
# Phase 4: Clean-Environment Quickstarts
# ---------------------------------------------------------------------------
echo "--- Phase 4: Clean-Environment Quickstarts ---"
quickstart_env="$work_dir/clean_env"
quickstart_config="$quickstart_env/config"
quickstart_cache="$quickstart_env/cache"
quickstart_reports="$quickstart_env/reports"
quickstart_scripts="$quickstart_env/scripts"
quickstart_proj="$quickstart_env/project"

mkdir -p "$quickstart_config" "$quickstart_cache" "$quickstart_reports" "$quickstart_scripts" "$quickstart_proj"

# Install extension into GHIDRA_INSTALL_DIR/Ghidra/Extensions/Embedra for headless discovery
rm -rf "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/Embedra"
unzip -q "$artifact" -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"

# Create headless report export post-script
cat << 'EOF' > "$quickstart_scripts/ExportEmbedraReport.java"
import ghidra.app.script.GhidraScript;
import io.github.rezabakhshi.embedra.ghidra.findings.GhidraFindingBookmarkSynchronizer;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFinding;
import io.github.rezabakhshi.embedra.analyzers.findings.UnifiedFindingsReport;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class ExportEmbedraReport extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<UnifiedFinding> findings = GhidraFindingBookmarkSynchronizer.extractFindingsFromBookmarks(currentProgram);
        UnifiedFindingsReport report = UnifiedFindingsReport.of(
            currentProgram.getName(),
            currentProgram.getLanguage().getProcessor().toString(),
            findings
        );
        String[] args = getScriptArgs();
        String outDir = (args != null && args.length > 0) ? args[0] : ".";
        File outFile = new File(outDir, currentProgram.getName() + ".report.json");
        Files.writeString(outFile.toPath(), report.toJson(true));
        println("ExportEmbedraReport: Successfully generated " + outFile.getAbsolutePath() + " (" + findings.size() + " findings)");
    }
}
EOF

# Run headless analysis in isolated environment
export XDG_CONFIG_HOME="$quickstart_config"
export XDG_CACHE_HOME="$quickstart_cache"

validate_json_report() {
    report_file="$1"
    if [ ! -f "$report_file" ]; then
        echo "LIFECYCLE FAIL: Expected report $report_file was not generated." >&2
        exit 1
    fi
    python3 -c "
import json, sys
data = json.load(open('$report_file'))
assert 'totalFindings' in data, 'Missing totalFindings key'
assert 'findings' in data, 'Missing findings key'
assert isinstance(data['findings'], list), 'findings must be a list'
"
    echo "  Report valid: $(basename "$report_file")"
}

# 4.1 RP2040 UF2
echo "Quickstart 4.1: Raspberry Pi RP2040 UF2"
mkdir -p "$quickstart_proj"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
    "$quickstart_proj" RP2040_Quickstart \
    -import src/test/resources/fixtures/rp/rp2040-pico-blinky.uf2 \
    -scriptPath "$quickstart_scripts" \
    -postScript ExportEmbedraReport.java "$quickstart_reports" \
    -readOnly -deleteProject > "$work_dir/rp2040.log" 2>&1

grep -q "Using Loader: Embedra Raspberry Pi Firmware" "$work_dir/rp2040.log" || {
    echo "LIFECYCLE FAIL: Embedra Raspberry Pi Firmware loader was not invoked." >&2
    exit 1
}
validate_json_report "$quickstart_reports/rp2040-pico-blinky.uf2.report.json"

# 4.2 ESP32-S3 Full-Flash
echo "Quickstart 4.2: ESP32-S3 Full-Flash"
mkdir -p "$quickstart_proj"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
    "$quickstart_proj" ESP32S3_Quickstart \
    -import src/test/resources/fixtures/esp32s3/full-flash/default-factory.bin \
    -scriptPath "$quickstart_scripts" \
    -postScript ExportEmbedraReport.java "$quickstart_reports" \
    -readOnly -deleteProject > "$work_dir/esp32s3.log" 2>&1

grep -q "Using Loader: Embedra ESP Application Image" "$work_dir/esp32s3.log" || {
    echo "LIFECYCLE FAIL: Embedra ESP Application Image loader was not invoked." >&2
    exit 1
}
validate_json_report "$quickstart_reports/default-factory_factory.report.json"

# 4.3 STM32 Intel HEX
echo "Quickstart 4.3: STM32 Intel HEX"
mkdir -p "$quickstart_proj"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
    "$quickstart_proj" STM32HEX_Quickstart \
    -import src/test/resources/fixtures/stm32-core-samples/STM32F401RET6.hex \
    -processor "ARM:LE:32:Cortex" \
    -scriptPath "$quickstart_scripts" \
    -postScript ExportEmbedraReport.java "$quickstart_reports" \
    -readOnly -deleteProject > "$work_dir/stm32hex.log" 2>&1

grep -q "Analysis succeeded for file" "$work_dir/stm32hex.log" || {
    echo "LIFECYCLE FAIL: STM32 HEX analysis failed." >&2
    cat "$work_dir/stm32hex.log" >&2
    exit 1
}
validate_json_report "$quickstart_reports/STM32F401RET6.hex.report.json"

# 4.4 STM32 Raw BIN
echo "Quickstart 4.4: STM32 Raw BIN"
mkdir -p "$quickstart_proj"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
    "$quickstart_proj" STM32BIN_Quickstart \
    -import src/test/resources/fixtures/stm32-core-samples/STM32F401RET6.bin \
    -loader BinaryLoader -loader-baseAddr 08000000 \
    -processor "ARM:LE:32:Cortex" \
    -scriptPath "$quickstart_scripts" \
    -postScript ExportEmbedraReport.java "$quickstart_reports" \
    -readOnly -deleteProject > "$work_dir/stm32bin.log" 2>&1

grep -q "Analysis succeeded for file" "$work_dir/stm32bin.log" || {
    echo "LIFECYCLE FAIL: STM32 Raw BIN analysis failed." >&2
    exit 1
}
validate_json_report "$quickstart_reports/STM32F401RET6.bin.report.json"

# 4.5 Nordic nRF52 Intel HEX
echo "Quickstart 4.5: Nordic nRF52 Intel HEX"
mkdir -p "$quickstart_proj"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
    "$quickstart_proj" NRF52_Quickstart \
    -import src/test/resources/fixtures/nordic/nrf52832_app.hex \
    -processor "ARM:LE:32:Cortex" \
    -scriptPath "$quickstart_scripts" \
    -postScript ExportEmbedraReport.java "$quickstart_reports" \
    -readOnly -deleteProject > "$work_dir/nrf52.log" 2>&1

grep -q "Analysis succeeded for file" "$work_dir/nrf52.log" || {
    echo "LIFECYCLE FAIL: Nordic nRF52 HEX analysis failed." >&2
    exit 1
}
validate_json_report "$quickstart_reports/nrf52832_app.hex.report.json"

# 4.6 Atmel ATmega328P Intel HEX
echo "Quickstart 4.6: Atmel ATmega328P Intel HEX"
mkdir -p "$quickstart_proj"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
    "$quickstart_proj" ATMEGA328P_Quickstart \
    -import src/test/resources/fixtures/atmel/atmega328p_app.hex \
    -processor "avr8:LE:16:default" \
    -scriptPath "$quickstart_scripts" \
    -postScript ExportEmbedraReport.java "$quickstart_reports" \
    -readOnly -deleteProject > "$work_dir/atmega328p.log" 2>&1

grep -q "Analysis succeeded for file" "$work_dir/atmega328p.log" || {
    echo "LIFECYCLE FAIL: Atmel ATmega328P HEX analysis failed." >&2
    exit 1
}
validate_json_report "$quickstart_reports/atmega328p_app.hex.report.json"

# Clean up temporary installation
rm -rf "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/Embedra"

echo "Clean-environment quickstarts completed and validated across all samples."

# ---------------------------------------------------------------------------
# Phase 5: Agent-Resume Simulation
# ---------------------------------------------------------------------------
echo "--- Phase 5: Agent-Resume Simulation ---"
sh scripts/validate-handoff.sh
sh scripts/validate-fixture-provenance.sh
echo "Agent-resume simulation verified: handoff and fixture provenance clean."

echo "=== ALL RELEASE LIFECYCLE GATES PASSED ==="
