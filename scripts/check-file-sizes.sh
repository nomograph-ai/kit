#!/bin/sh
# File size gate: fails if any tracked .rs file exceeds MAX_LINES.
#
# Rationale: small files = small LLM context windows per file =
# cheaper restarts + more reviewable diffs + healthier module seams.
# See feedback-audit Governance + Brevity principles.
#
# A .file-size-waiver file at the repo root can temporarily exempt
# paths that are scheduled for a split. Keep that list short and
# always shrinking. Adding an entry requires a commit message that
# names the MR that will remove it.
set -eu

MAX_LINES="${MAX_LINES:-500}"
WAIVER_FILE=".file-size-waiver"

is_waived() {
    [ -f "$WAIVER_FILE" ] || return 1
    grep -Fxq "$1" "$WAIVER_FILE"
}

violations=""
# Iterate via find -exec-style while loop so filenames with spaces or
# newlines are handled correctly (shellcheck SC2044).
while IFS= read -r f; do
    if is_waived "$f"; then
        continue
    fi
    lines=$(wc -l < "$f")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        violations="${violations}  ${f}: ${lines} lines\n"
    fi
done <<EOF
$(find src tests -name '*.rs' -type f 2>/dev/null)
EOF

if [ -n "$violations" ]; then
    printf '%s\n' "file-size gate: one or more .rs files exceed ${MAX_LINES} lines."
    printf '%b' "$violations"
    printf '\n%s\n' "Fix: split into submodules, or (if truly temporary) add the path to ${WAIVER_FILE}"
    printf '%s\n' "and reference the MR that will remove it in your commit message."
    exit 1
fi

waiver_count=0
if [ -f "$WAIVER_FILE" ]; then
    waiver_count=$(wc -l < "$WAIVER_FILE")
fi
echo "file-size gate: ok (limit ${MAX_LINES} lines, ${waiver_count} path(s) waived)"
