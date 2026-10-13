#!/bin/sh

set -eu

if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    echo "GHIDRA_INSTALL_DIR must point to Ghidra 12.1.3." >&2
    exit 2
fi

task_list=$(mktemp)
work_dir=$(mktemp -d)
trap 'rm -f "$task_list"; rm -rf "$work_dir"' EXIT HUP INT TERM

"$GHIDRA_INSTALL_DIR/support/sleigh" \
    data/languages/embedra_esp32s3.slaspec \
    "$work_dir/embedra_esp32s3.sla" >"$work_dir/sleigh.log" 2>&1
cmp data/languages/embedra_esp32s3.sla "$work_dir/embedra_esp32s3.sla"

./gradlew --offline -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" tasks --all >"$task_list"

for required_task in \
    checkstyleMain \
    checkstyleTest \
    ghidraIntegrationTest \
    jacocoTestReport \
    jacocoTestCoverageVerification \
    test \
    verifyFormatting \
    verifySTM32CatalogGenerator \
    verifySTM32FixtureCatalog \
    buildExtension
do
    if ! grep -Eq "^${required_task}( |$)" "$task_list"; then
        echo "Missing required build-quality task: ${required_task}" >&2
        exit 1
    fi
done

run_build() {
    ./gradlew \
        --offline \
        --no-build-cache --rerun-tasks \
        -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" \
        clean check jacocoTestReport jacocoTestCoverageVerification buildExtension
}

rm -f dist/*_Embedra.zip
run_build
artifact=$(find dist -maxdepth 1 -type f -name '*_Embedra.zip' -print)
if [ -z "$artifact" ] || [ "$(printf '%s\n' "$artifact" | wc -l)" -ne 1 ]; then
    echo "Expected exactly one Embedra extension ZIP." >&2
    exit 1
fi
first_digest=$(sha256sum "$artifact" | cut -d' ' -f1)
cp "$artifact" "$work_dir/first.zip"

run_build
artifact=$(find dist -maxdepth 1 -type f -name '*_Embedra.zip' -print)
second_digest=$(sha256sum "$artifact" | cut -d' ' -f1)

if [ "$first_digest" != "$second_digest" ]; then
    echo "Extension ZIP is not reproducible: $first_digest != $second_digest" >&2
    exit 1
fi

cmp "$work_dir/first.zip" "$artifact"
unzip -t "$artifact" >/dev/null

expected_entries='Embedra/
Embedra/extension.properties
Embedra/lib/
Embedra/lib/Embedra.jar
Embedra/LICENSE
Embedra/Module.manifest
Embedra/NOTICE
Embedra/README.md
Embedra/THIRD_PARTY_NOTICES.md
Embedra/catalogs/
Embedra/catalogs/espressif/
Embedra/catalogs/espressif/2026-09-23/
Embedra/catalogs/espressif/2026-09-23/catalog.json
Embedra/catalogs/espressif/2026-09-23/catalog.sha256
Embedra/catalogs/rp/
Embedra/catalogs/rp/2026-10-02/
Embedra/catalogs/rp/2026-10-02/board-profiles.json
Embedra/catalogs/rp/2026-10-02/board-profiles.sha256
Embedra/catalogs/rp/2026-10-02/catalog.json
Embedra/catalogs/rp/2026-10-02/catalog.sha256
Embedra/catalogs/stm32/
Embedra/catalogs/stm32/2026-09-29/
Embedra/catalogs/stm32/2026-09-29/board-profiles.json
Embedra/catalogs/stm32/2026-09-29/board-profiles.sha256
Embedra/catalogs/stm32/2026-09-29/curated-catalog.json
Embedra/catalogs/stm32/2026-09-29/curated-catalog.sha256
Embedra/catalogs/stm32/2026-09-29/memory-plans.json
Embedra/catalogs/stm32/2026-09-29/memory-plans.sha256
Embedra/catalogs/stm32/2026-09-29/security-domains.json
Embedra/catalogs/stm32/2026-09-29/security-domains.sha256
Embedra/catalogs/stm32/2026-09-29/selection.json
Embedra/catalogs/stm32/2026-09-29/svd-applicability.json
Embedra/catalogs/stm32/2026-09-29/svd-applicability.sha256
Embedra/data/
Embedra/data/languages/
Embedra/data/languages/cust.sinc
Embedra/data/languages/embedra_esp32s3.ldefs
Embedra/data/languages/embedra_esp32s3.sinc
Embedra/data/languages/embedra_esp32s3.sla
Embedra/data/languages/embedra_esp32s3.slaspec
Embedra/data/languages/flix.sinc
Embedra/data/languages/xtensa.cspec
Embedra/data/languages/xtensa.pspec
Embedra/data/languages/xtensaArch.sinc
Embedra/data/languages/xtensaInstructions.sinc
Embedra/data/languages/xtensaMain.sinc
Embedra/docs/
Embedra/docs/architecture.md
Embedra/docs/compatibility-matrix.md
Embedra/docs/crypto-coverage.md
Embedra/docs/device-catalog.md
Embedra/docs/fixture-policy.md
Embedra/docs/headless.md
Embedra/docs/license-audit.md
Embedra/docs/pack-format.md
Embedra/docs/support-matrix.md
Embedra/docs/troubleshooting.md
Embedra/fid/
Embedra/fid/esp32s3/
Embedra/fid/esp32s3/README.md
Embedra/fid/esp32s3/esp-idf-v6.0-662a3be35475-esp32s3-Os.audit.json
Embedra/fid/esp32s3/esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb
Embedra/fid/esp32s3/esp-idf-v6.0-662a3be35475-esp32s3-Os.json
Embedra/licenses/
Embedra/licenses/STMicroelectronics-STM32-open-pin-data-BSD-3-Clause.txt
Embedra/licenses/license-audit.sha256
Embedra/packs/
Embedra/packs/espressif.esp32.peripherals/
Embedra/packs/espressif.esp32.peripherals/1.0.0/
Embedra/packs/espressif.esp32.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32.rom/
Embedra/packs/espressif.esp32.rom/1.0.0/
Embedra/packs/espressif.esp32.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32.svd/
Embedra/packs/espressif.esp32.svd/1.0.0/
Embedra/packs/espressif.esp32.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32.svd/1.0.0/registers.json
Embedra/packs/espressif.esp32c2.peripherals/
Embedra/packs/espressif.esp32c2.peripherals/1.0.0/
Embedra/packs/espressif.esp32c2.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32c2.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32c2.rom/
Embedra/packs/espressif.esp32c2.rom/1.0.0/
Embedra/packs/espressif.esp32c2.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32c2.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32c2.svd/
Embedra/packs/espressif.esp32c2.svd/1.0.0/
Embedra/packs/espressif.esp32c2.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32c2.svd/1.0.0/registers.json
Embedra/packs/espressif.esp32c3.peripherals/
Embedra/packs/espressif.esp32c3.peripherals/1.0.0/
Embedra/packs/espressif.esp32c3.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32c3.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32c3.rom/
Embedra/packs/espressif.esp32c3.rom/1.0.0/
Embedra/packs/espressif.esp32c3.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32c3.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32c3.svd/
Embedra/packs/espressif.esp32c3.svd/1.0.0/
Embedra/packs/espressif.esp32c3.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32c3.svd/1.0.0/registers.json
Embedra/packs/espressif.esp32c5.peripherals/
Embedra/packs/espressif.esp32c5.peripherals/1.0.0/
Embedra/packs/espressif.esp32c5.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32c5.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32c5.rom/
Embedra/packs/espressif.esp32c5.rom/1.0.0/
Embedra/packs/espressif.esp32c5.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32c5.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32c6.peripherals/
Embedra/packs/espressif.esp32c6.peripherals/1.0.0/
Embedra/packs/espressif.esp32c6.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32c6.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32c6.rom/
Embedra/packs/espressif.esp32c6.rom/1.0.0/
Embedra/packs/espressif.esp32c6.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32c6.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32c6.svd/
Embedra/packs/espressif.esp32c6.svd/1.0.0/
Embedra/packs/espressif.esp32c6.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32c6.svd/1.0.0/registers.json
Embedra/packs/espressif.esp32c61.peripherals/
Embedra/packs/espressif.esp32c61.peripherals/1.0.0/
Embedra/packs/espressif.esp32c61.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32c61.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32c61.rom/
Embedra/packs/espressif.esp32c61.rom/1.0.0/
Embedra/packs/espressif.esp32c61.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32c61.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32h2.peripherals/
Embedra/packs/espressif.esp32h2.peripherals/1.0.0/
Embedra/packs/espressif.esp32h2.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32h2.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32h2.rom/
Embedra/packs/espressif.esp32h2.rom/1.0.0/
Embedra/packs/espressif.esp32h2.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32h2.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32h2.svd/
Embedra/packs/espressif.esp32h2.svd/1.0.0/
Embedra/packs/espressif.esp32h2.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32h2.svd/1.0.0/registers.json
Embedra/packs/espressif.esp32h21.peripherals/
Embedra/packs/espressif.esp32h21.peripherals/1.0.0/
Embedra/packs/espressif.esp32h21.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32h21.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32h21.rom/
Embedra/packs/espressif.esp32h21.rom/1.0.0/
Embedra/packs/espressif.esp32h21.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32h21.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32h4.peripherals/
Embedra/packs/espressif.esp32h4.peripherals/1.0.0/
Embedra/packs/espressif.esp32h4.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32h4.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32h4.rom/
Embedra/packs/espressif.esp32h4.rom/1.0.0/
Embedra/packs/espressif.esp32h4.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32h4.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32p4.peripherals/
Embedra/packs/espressif.esp32p4.peripherals/1.0.0/
Embedra/packs/espressif.esp32p4.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32p4.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32p4.rom/
Embedra/packs/espressif.esp32p4.rom/1.0.0/
Embedra/packs/espressif.esp32p4.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32p4.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32p4.svd/
Embedra/packs/espressif.esp32p4.svd/1.0.0/
Embedra/packs/espressif.esp32p4.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32p4.svd/1.0.0/registers.json
Embedra/packs/espressif.esp32s2.peripherals/
Embedra/packs/espressif.esp32s2.peripherals/1.0.0/
Embedra/packs/espressif.esp32s2.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32s2.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32s2.rom/
Embedra/packs/espressif.esp32s2.rom/1.0.0/
Embedra/packs/espressif.esp32s2.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32s2.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32s2.svd/
Embedra/packs/espressif.esp32s2.svd/1.0.0/
Embedra/packs/espressif.esp32s2.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32s2.svd/1.0.0/registers.json
Embedra/packs/espressif.esp32s3.peripherals/
Embedra/packs/espressif.esp32s3.peripherals/1.0.0/
Embedra/packs/espressif.esp32s3.peripherals/1.0.0/pack.json
Embedra/packs/espressif.esp32s3.peripherals/1.0.0/peripherals.json
Embedra/packs/espressif.esp32s3.rom/
Embedra/packs/espressif.esp32s3.rom/1.0.0/
Embedra/packs/espressif.esp32s3.rom/1.0.0/pack.json
Embedra/packs/espressif.esp32s3.rom/1.0.0/rom-symbols.json
Embedra/packs/espressif.esp32s3.svd/
Embedra/packs/espressif.esp32s3.svd/1.0.0/
Embedra/packs/espressif.esp32s3.svd/1.0.0/pack.json
Embedra/packs/espressif.esp32s3.svd/1.0.0/registers.json
Embedra/packs/stm32.stm32c031.svd/
Embedra/packs/stm32.stm32c031.svd/1.0.0/
Embedra/packs/stm32.stm32c031.svd/1.0.0/pack.json
Embedra/packs/stm32.stm32c031.svd/1.0.0/registers.json
Embedra/packs/stm32.stm32f1.signatures/
Embedra/packs/stm32.stm32f1.signatures/1.0.0/
Embedra/packs/stm32.stm32f1.signatures/1.0.0/pack.json
Embedra/packs/stm32.stm32f1.signatures/1.0.0/signatures.json
Embedra/packs/stm32.stm32f103.svd/
Embedra/packs/stm32.stm32f103.svd/1.0.0/
Embedra/packs/stm32.stm32f103.svd/1.0.0/pack.json
Embedra/packs/stm32.stm32f103.svd/1.0.0/registers.json
Embedra/packs/stm32.stm32f401.svd/
Embedra/packs/stm32.stm32f401.svd/1.0.0/
Embedra/packs/stm32.stm32f401.svd/1.0.0/pack.json
Embedra/packs/stm32.stm32f401.svd/1.0.0/registers.json
Embedra/packs/stm32.stm32h503.svd/
Embedra/packs/stm32.stm32h503.svd/1.0.0/
Embedra/packs/stm32.stm32h503.svd/1.0.0/pack.json
Embedra/packs/stm32.stm32h503.svd/1.0.0/registers.json
Embedra/packs/stm32.stm32h735.svd/
Embedra/packs/stm32.stm32h735.svd/1.0.0/
Embedra/packs/stm32.stm32h735.svd/1.0.0/pack.json
Embedra/packs/stm32.stm32h735.svd/1.0.0/registers.json
Embedra/packs/stm32.stm32wb55-cm0p.svd/
Embedra/packs/stm32.stm32wb55-cm0p.svd/1.0.0/
Embedra/packs/stm32.stm32wb55-cm0p.svd/1.0.0/pack.json
Embedra/packs/stm32.stm32wb55-cm0p.svd/1.0.0/registers.json
Embedra/packs/stm32.stm32wb55-cm4.svd/
Embedra/packs/stm32.stm32wb55-cm4.svd/1.0.0/
Embedra/packs/stm32.stm32wb55-cm4.svd/1.0.0/pack.json
Embedra/packs/stm32.stm32wb55-cm4.svd/1.0.0/registers.json'
if find src/main/java -type f -name '*.java' -print -quit | grep -q .; then
    expected_entries="${expected_entries}
Embedra/lib/Embedra-src.zip"
fi
actual_entries=$(unzip -Z1 "$artifact")
if [ "$actual_entries" != "$expected_entries" ]; then
    echo "Unexpected extension ZIP contents:" >&2
    printf '%s\n' "$actual_entries" >&2
    exit 1
fi

if unzip -p "$artifact" $(printf '%s\n' "$actual_entries" |
        grep -E '\.(json|md|properties|sha256)$') |
    grep -qE '/home/|/Users/|/private/var/|esp32s3_ctf_dump_4MB|flash_dump\.bin'
then
    echo "Extension ZIP text content contains host paths or restricted capture names." >&2
    exit 1
fi

python3 scripts/audit-licenses.py --check --zip "$artifact"

# T078 supply-chain release bundle: source bundle, deterministic CycloneDX
# SBOM, and a sorted sha256sum-compatible checksum manifest, all fail-closed.
sh scripts/build-release-artifacts.sh "$artifact"

if printf '%s\n' "$actual_entries" | grep -q '^Embedra/lib/Embedra-src.zip$'; then
    unzip -p "$artifact" Embedra/lib/Embedra-src.zip >"$work_dir/source.zip"
    unzip -t "$work_dir/source.zip" >/dev/null
fi

printf 'Reproducible extension SHA-256: %s\n' "$second_digest"
