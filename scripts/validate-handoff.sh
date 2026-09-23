#!/bin/sh

set -eu

repository=${1:-.}
state="$repository/.embedra/state.json"
commands="$repository/.embedra/evidence/commands.jsonl"

for required in "$repository/Embedra-SpecKit.md" "$repository/PROJECT_STATE.md" "$state" "$commands"
do
    if [ ! -f "$required" ] || [ -L "$required" ]; then
        echo "Required continuity file is missing or unsafe: $required" >&2
        exit 1
    fi
done

jq -e 'type == "object" and .schemaVersion == 1' "$state" >/dev/null
jq -s -e 'all(.[]; type == "object" and (.task | type == "string") and
    (.exitStatus | type == "number"))' "$commands" >/dev/null

specification_path=$(jq -r '.specification.path' "$state")
if [ "$specification_path" != "Embedra-SpecKit.md" ]; then
    echo "Continuity state references an unexpected specification path." >&2
    exit 1
fi
expected_digest=$(jq -r '.specification.sha256' "$state")
actual_digest=$(sha256sum "$repository/$specification_path" | cut -d' ' -f1)
if [ "$actual_digest" != "$expected_digest" ]; then
    echo "Specification digest does not match continuity state." >&2
    exit 1
fi

evidence_path=$(jq -r '.evidence.task' "$state")
case "$evidence_path" in
    .embedra/evidence/tasks/T[0-9][0-9][0-9].md | \
    .embedra/evidence/tasks/T[0-9][0-9][0-9][A-Z].md) ;;
    *)
        echo "Task evidence path is invalid." >&2
        exit 1
        ;;
esac
if [ ! -f "$repository/$evidence_path" ] || [ -L "$repository/$evidence_path" ]; then
    echo "Recorded task evidence is missing or unsafe." >&2
    exit 1
fi

jq -r '.completedTasks[]' "$state" |
while IFS= read -r task
do
    if ! grep -Fq -- "- [x] $task " "$repository/Embedra-SpecKit.md"; then
        echo "Completed task is not checked in the specification: $task" >&2
        exit 1
    fi
done

current_task=$(jq -r '.currentTask.id' "$state")
case "$current_task" in
    *_GATE)
        gate_name=$(printf '%s' "${current_task%_GATE}" | tr '[:upper:]' '[:lower:]')
        gate_evidence=$(jq -r --arg gate "$gate_name" '.acceptanceGates[$gate].evidence // ""' "$state")
        if [ -z "$gate_evidence" ] || [ ! -f "$repository/$gate_evidence" ]; then
            echo "Current acceptance gate has no evidence file." >&2
            exit 1
        fi
        ;;
    *)
        if ! grep -Eq "^- \\[[ x]\\] ${current_task} " "$repository/Embedra-SpecKit.md"; then
            echo "Current task is absent from the specification." >&2
            exit 1
        fi
        ;;
esac
