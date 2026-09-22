#!/bin/sh

set -eu

if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    echo "GHIDRA_INSTALL_DIR must point to Ghidra 12.1.3." >&2
    exit 2
fi

task_list=$(mktemp)
work_dir=$(mktemp -d)
trap 'rm -f "$task_list"; rm -rf "$work_dir"' EXIT HUP INT TERM

./gradlew -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" tasks --all >"$task_list"

for required_task in \
    checkstyleMain \
    checkstyleTest \
    ghidraIntegrationTest \
    jacocoTestReport \
    jacocoTestCoverageVerification \
    test \
    verifyFormatting \
    buildExtension
do
    if ! grep -Eq "^${required_task}( |$)" "$task_list"; then
        echo "Missing required build-quality task: ${required_task}" >&2
        exit 1
    fi
done

run_build() {
    ./gradlew \
        -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" \
        clean check jacocoTestReport jacocoTestCoverageVerification buildExtension
}

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
Embedra/README.md
Embedra/THIRD_PARTY_NOTICES.md
Embedra/docs/
Embedra/docs/architecture.md
Embedra/docs/fixture-policy.md
Embedra/docs/pack-format.md
Embedra/docs/support-matrix.md'
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

if printf '%s\n' "$actual_entries" | grep -q '^Embedra/lib/Embedra-src.zip$'; then
    unzip -p "$artifact" Embedra/lib/Embedra-src.zip >"$work_dir/source.zip"
    unzip -t "$work_dir/source.zip" >/dev/null
fi

printf 'Reproducible extension SHA-256: %s\n' "$second_digest"
