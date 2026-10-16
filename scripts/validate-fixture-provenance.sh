#!/bin/sh

set -eu

fixture_root=${1:-src/test/resources/fixtures}

if [ ! -e "$fixture_root" ]; then
    exit 0
fi
if [ ! -d "$fixture_root" ] || [ -L "$fixture_root" ]; then
    echo "Fixture root must be a real directory." >&2
    exit 1
fi
if find "$fixture_root" -type l -print -quit | grep -q .; then
    echo "Fixture tree contains a symbolic link." >&2
    exit 1
fi

find "$fixture_root" -type f ! -name '*.manifest.json' ! -name 'README.md' -print | sort |
while IFS= read -r fixture
do
    manifest="${fixture}.manifest.json"
    if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
        echo "Fixture is missing its manifest: $fixture" >&2
        exit 1
    fi
    if ! jq -e '
        type == "object" and
        (.fixtureId | type == "string" and length > 0) and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.target | type == "string" and length > 0) and
        (.inputFormat | type == "string" and length > 0) and
        (.origin | type == "string" and length > 0) and
        (.license | type == "string" and length > 0) and
        .redistributionStatus == "REDISTRIBUTABLE" and
        (.generatorRevision | type == "string" and length > 0) and
        (.generationCommand | type == "string" and length > 0) and
        (.toolchain | type == "string" and length > 0) and
        (.oracleCommands | type == "array" and length > 0) and
        (.expectedSnapshot | type == "string" and length > 0) and
        (.requirements | type == "array" and length > 0)
    ' "$manifest" >/dev/null
    then
        echo "Fixture manifest is incomplete or not redistributable: $manifest" >&2
        exit 1
    fi
    expected_digest=$(jq -r '.sha256' "$manifest")
    if command -v sha256sum >/dev/null 2>&1; then
        actual_digest=$(sha256sum "$fixture" | cut -d' ' -f1)
    else
        actual_digest=$(shasum -a 256 "$fixture" | cut -d' ' -f1)
    fi
    if [ "$actual_digest" != "$expected_digest" ]; then
        echo "Fixture digest mismatch: $fixture" >&2
        exit 1
    fi
done

find "$fixture_root" -type f -name '*.manifest.json' -print | sort |
while IFS= read -r manifest
do
    fixture=${manifest%.manifest.json}
    if [ ! -f "$fixture" ] || [ -L "$fixture" ]; then
        echo "Fixture manifest has no regular fixture: $manifest" >&2
        exit 1
    fi
done
