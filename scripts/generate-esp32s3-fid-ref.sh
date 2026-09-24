#!/usr/bin/env bash
# Generate the T026A ESP32-S3 ESP-IDF Function ID pilot artifacts.
#
# Prerequisites (all checked): pinned ESP-IDF v6.0 checkout, Espressif
# esp-15.2.0_20251204 toolchain, esptool 5.4.0, and Ghidra 12.1.3 for FIDB
# creation. Builds are pinned with SOURCE_DATE_EPOCH and
# CONFIG_APP_REPRODUCIBLE_BUILD. Outputs and their digests are reported for
# the committed fixtures; regeneration is a documented, explicit workflow and
# the resulting .fidb is content-equivalent but not byte-identical (Ghidra
# assigns time-based record ids).
set -eu

expected_idf_revision=662a3be354759d9487bf4b1a629fadb766cb1800
expected_idf_version=v6.0
expected_compiler_version=esp-15.2.0_20251204
expected_esptool_version=5.4.0
expected_ghidra_version=12.1.3
source_date_epoch=1761609600
variant=refapp-esp32s3-Os

if [ -z "${IDF_PATH:-}" ] || [ ! -d "$IDF_PATH/.git" ]; then
    echo "IDF_PATH must point to the pinned ESP-IDF v6.0 checkout." >&2
    exit 1
fi
if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    echo "GHIDRA_INSTALL_DIR must point to Ghidra $expected_ghidra_version." >&2
    exit 1
fi
actual_idf_revision=$(git -C "$IDF_PATH" rev-parse HEAD)
if [ "$actual_idf_revision" != "$expected_idf_revision" ]; then
    echo "ESP-IDF revision mismatch: $actual_idf_revision" >&2
    exit 1
fi
actual_idf_describe=$(git -C "$IDF_PATH" describe --tags)
if [ "$actual_idf_describe" != "$expected_idf_version" ]; then
    echo "ESP-IDF version mismatch: $actual_idf_describe" >&2
    exit 1
fi
esptool_binary=$(command -v esptool)
actual_esptool_version=$("$esptool_binary" version | tail -n 1)
if [ "$actual_esptool_version" != "$expected_esptool_version" ]; then
    echo "esptool version mismatch: $actual_esptool_version" >&2
    exit 1
fi
ghidra_version=$(grep '^application.version=' \
    "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" | cut -d= -f2)
if [ "$ghidra_version" != "$expected_ghidra_version" ]; then
    echo "Ghidra version mismatch: $ghidra_version" >&2
    exit 1
fi

# shellcheck disable=SC1091
source "$IDF_PATH/export.sh" >/dev/null 2>&1

compiler_line=$(xtensa-esp32s3-elf-gcc --version | head -n 1)
if ! printf '%s\n' "$compiler_line" | grep -Fq "$expected_compiler_version"; then
    echo "Unexpected ESP32-S3 compiler version: $compiler_line" >&2
    exit 1
fi
toolchain_root=$(dirname "$(dirname "$(command -v xtensa-esp32s3-elf-gcc)")")

if [ -z "${JAVA_HOME:-}" ]; then
    echo "Set JAVA_HOME to a 64-bit JDK 21 (Ghidra 12.1.3 baseline)." >&2
    exit 1
fi
java_major=$("$JAVA_HOME/bin/java" -version 2>&1 | head -1 |
    sed -E 's/[^"]*"([0-9]+).*/\1/')
if [ "$java_major" != "21" ]; then
    echo "JDK 21 required for the Ghidra FIDB step; found $java_major." >&2
    exit 1
fi
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ref_dir="$project_root/fixtures/generators/esp32s3-fid-ref"
cross_dir="$project_root/fixtures/generators/esp32s3-fid-cross"
fixture_dir="$project_root/src/test/resources/fixtures/esp32s3/fid"
oracle_dir="$project_root/src/test/resources/oracles/esp32s3/fid"
fid_dir="$project_root/fid/esp32s3"
work_dir=$(mktemp -d)
export SOURCE_DATE_EPOCH=$source_date_epoch
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

build_project()
{
    source_dir=$1
    build_name=$2
    defaults=$3
    target_dir="$work_dir/$build_name"
    cp -R "$source_dir" "$target_dir"
    rm -f "$target_dir/sdkconfig"
    (
        cd "$target_dir"
        if [ -n "$defaults" ]; then
            idf.py -B build -D SDKCONFIG_DEFAULTS="$defaults" \
                set-target esp32s3 >/dev/null
        else
            idf.py -B build set-target esp32s3 >/dev/null
        fi
        idf.py -B build build >/dev/null
    )
}

sha256_file()
{
    sha256sum "$1" | cut -d' ' -f1
}

build_project "$ref_dir" app-a ""
build_project "$ref_dir" app-a-o2 "sdkconfig.defaults;sdkconfig.defaults.O2"
build_project "$cross_dir" app-b ""

for sdkconfig in "$work_dir/app-a/sdkconfig" \
    "$work_dir/app-a-o2/sdkconfig" "$work_dir/app-b/sdkconfig"
do
    if [ ! -f "$sdkconfig" ]; then
        echo "Expected generated sdkconfig is missing: $sdkconfig" >&2
        exit 1
    fi
done

xtensa-esp32s3-elf-objcopy --strip-debug \
    "$work_dir/app-a/build/embedra_fid_ref.elf" \
    "$work_dir/embedra-fid-ref-app-a.elf"
xtensa-esp32s3-elf-objcopy --strip-debug \
    "$work_dir/app-a-o2/build/embedra_fid_ref.elf" \
    "$work_dir/embedra-fid-ref-app-a-o2.elf"
xtensa-esp32s3-elf-objcopy --strip-debug \
    "$work_dir/app-b/build/embedra_fid_cross.elf" \
    "$work_dir/embedra-fid-cross-app-b.elf"

for out_name in embedra-fid-ref-app-a embedra-fid-ref-app-a-o2 \
    embedra-fid-cross-app-b
do
    "$esptool_binary" --chip esp32s3 elf2image --flash-mode dio --flash-freq 40m \
        --flash-size 2MB --output "$work_dir/$out_name.bin" \
        "$work_dir/$out_name.elf" >/dev/null
done

# The stripped reference image must interlock: esp_app_desc records the exact
# SHA-256 of the ELF that produced it.
python3 - "$work_dir/embedra-fid-ref-app-a.bin" \
    "$work_dir/embedra-fid-ref-app-a.elf" <<'PYEOF'
import hashlib, sys
image = open(sys.argv[1], 'rb').read()
desc = image.find(bytes.fromhex('3254cdab'))
elf_sha = hashlib.sha256(open(sys.argv[2], 'rb').read()).hexdigest()
recorded = image[desc + 144:desc + 176].hex()
assert elf_sha == recorded, f'app desc ELF digest mismatch: {elf_sha} != {recorded}'
PYEOF

write_symbols_oracle()
{
    elf=$1
    bin=$2
    out=$3
    xtensa-esp32s3-elf-nm --defined-only --print-size "$elf" > "$out.nm"
    python3 - "$elf" "$bin" "$out" "$out.nm" <<'PYEOF'
import hashlib, json, sys
def sha(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()
functions = []
for line in open(sys.argv[4]):
    parts = line.split()
    if len(parts) >= 4 and parts[2] in ('T', 't'):
        try:
            functions.append({'name': parts[3], 'address': int(parts[0], 16),
                              'size': int(parts[1], 16), 'linkage': parts[2]})
        except ValueError:
            continue
json.dump({
    'schemaId': 'urn:embedra:schema:esp32s3-fid-symbol-ranges:1',
    'elfSha256': sha(sys.argv[1]),
    'binSha256': sha(sys.argv[2]),
    'functions': functions,
}, open(sys.argv[3], 'w'), indent=1, sort_keys=True)
PYEOF
}

write_symbols_oracle "$work_dir/embedra-fid-ref-app-a.elf" \
    "$work_dir/embedra-fid-ref-app-a.bin" "$work_dir/symbols-appa.json"
write_symbols_oracle "$work_dir/embedra-fid-ref-app-a-o2.elf" \
    "$work_dir/embedra-fid-ref-app-a-o2.bin" "$work_dir/symbols-appa-o2.json"
write_symbols_oracle "$work_dir/embedra-fid-cross-app-b.elf" \
    "$work_dir/embedra-fid-cross-app-b.bin" "$work_dir/symbols-appb.json"

python3 "$project_root/scripts/audit-fid-license.py" \
    "$work_dir/app-a/build/embedra_fid_ref.map" "$IDF_PATH" "$toolchain_root" \
    "$work_dir/app-a" > "$work_dir/audit.json"

python3 - "$work_dir/audit.json" "$work_dir/components.tsv" <<'PYEOF'
import json, sys
audit = json.load(open(sys.argv[1]))
with open(sys.argv[2], 'w') as out:
    for name, entry in sorted(audit['components'].items()):
        license_ = '+'.join(sorted(entry['licenses']))
        out.write(f"{name}\t{license_}\n")
PYEOF

for lib_name in libc.a libstdc++.a libgcc.a libm.a
do
    archive_path=$(xtensa-esp32s3-elf-gcc -print-file-name="$lib_name")
    if [ -f "$archive_path" ]; then
        xtensa-esp32s3-elf-nm --defined-only "$archive_path" 2>/dev/null |
            awk 'NF >= 2 && $2 ~ /^[TtWwDDBRGV]$/ {print $NF}'
    fi
done | sort -u > "$work_dir/exclusions.txt"

mkdir -p "$work_dir/ghidra"
GHIDRA_HEADLESS_JAVA_OPTIONS="-Dghidra.external.modules=$project_root" \
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$work_dir/ghidra" embedra_fid \
    -import "$work_dir/embedra-fid-ref-app-a.elf" \
    -processor Xtensa:LE:32:esp32s3 -cspec default \
    -scriptPath "$project_root/scripts/ghidra" \
    -preScript FunctionIDHeadlessPrescript.java >"$work_dir/ghidra-import.log" 2>&1
GHIDRA_HEADLESS_JAVA_OPTIONS="-Dghidra.external.modules=$project_root" \
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$work_dir/ghidra" embedra_fid \
    -process embedra-fid-ref-app-a.elf -noanalysis \
    -scriptPath "$project_root/scripts/ghidra" \
    -postScript EmbedraEsp32S3FidbBuilder.java \
    -scriptArgs -out "$work_dir/esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb" \
        -variant "$variant" \
        -elfsha "$(sha256_file "$work_dir/embedra-fid-ref-app-a.elf")" \
        -binsha "$(sha256_file "$work_dir/embedra-fid-ref-app-a.bin")" \
        -sdkconfigsha "$(sha256_file "$work_dir/app-a/sdkconfig")" \
        -components "$work_dir/components.tsv" \
        -exclusions "$work_dir/exclusions.txt"

mkdir -p "$fixture_dir" "$oracle_dir" "$fid_dir"
cp "$work_dir/embedra-fid-ref-app-a.elf" "$fixture_dir/embedra-fid-ref-app-a.elf"
cp "$work_dir/embedra-fid-ref-app-a.bin" "$fixture_dir/embedra-fid-ref-app-a.bin"
cp "$work_dir/embedra-fid-ref-app-a-o2.bin" \
    "$fixture_dir/embedra-fid-ref-app-a-o2.bin"
cp "$work_dir/embedra-fid-cross-app-b.bin" \
    "$fixture_dir/embedra-fid-cross-app-b.bin"
cp "$work_dir/esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb" \
    "$fid_dir/esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb"
cp "$work_dir/esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb.json" \
    "$fid_dir/esp-idf-v6.0-662a3be35475-esp32s3-Os.json"
cp "$work_dir/audit.json" \
    "$fid_dir/esp-idf-v6.0-662a3be35475-esp32s3-Os.audit.json"

{
    printf '{\n  "artifactId": "esp32s3-fid-reference-digests",\n'
    printf '  "appA": {\n    "elfSha256": "%s",\n' \
        "$(sha256_file "$fixture_dir/embedra-fid-ref-app-a.elf")"
    printf '    "binSha256": "%s",\n    "sdkconfigSha256": "%s"\n  },\n' \
        "$(sha256_file "$fixture_dir/embedra-fid-ref-app-a.bin")" \
        "$(sha256_file "$work_dir/app-a/sdkconfig")"
    printf '  "appAO2": {\n    "binSha256": "%s"\n  },\n' \
        "$(sha256_file "$fixture_dir/embedra-fid-ref-app-a-o2.bin")"
    printf '  "appB": {\n    "binSha256": "%s"\n  },\n' \
        "$(sha256_file "$fixture_dir/embedra-fid-cross-app-b.bin")"
    printf '  "database": {\n    "fidbSha256": "%s"\n  }\n}\n' \
        "$(sha256_file "$fid_dir/esp-idf-v6.0-662a3be35475-esp32s3-Os.fidb")"
} > "$oracle_dir/esp32s3-fid-reference-digests.json"

cp "$work_dir/symbols-appa.json" \
    "$oracle_dir/esp32s3-fid-reference-appa.symbols.json"
cp "$work_dir/symbols-appa-o2.json" \
    "$oracle_dir/esp32s3-fid-reference-appa-o2.symbols.json"
cp "$work_dir/symbols-appb.json" \
    "$oracle_dir/esp32s3-fid-reference-appb.symbols.json"

echo "Generated:"
sha256sum "$fixture_dir"/embedra-fid-* \
    "$fid_dir"/esp-idf-v6.0-662a3be35475-esp32s3-Os.* \
    "$oracle_dir"/esp32s3-fid-reference-*
