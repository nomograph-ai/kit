#!/usr/bin/env bash
# Fail if any committed symlink resolves to an absolute path.
#
# Backstop against the `.agent/skills` recurrence class: even if a tool
# rewrites a tracked symlink to absolute on a developer machine, this
# check fails the commit/CI before the bad target propagates. The
# relative form is the only form that resolves correctly across the
# local checkout AND the CI clone path (which uses different roots).

set -euo pipefail

bad=()
while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    # entry: "<mode> <oid> <stage>\t<path>"
    mode=$(printf '%s' "$entry" | awk '{print $1}')
    oid=$(printf '%s' "$entry" | awk '{print $2}')
    path=$(printf '%s' "$entry" | sed -E 's/^[^\t]+\t//')
    [ "$mode" = "120000" ] || continue
    target=$(git cat-file -p "$oid")
    case "$target" in
        /*)
            bad+=("$path -> $target")
            ;;
    esac
done < <(git ls-files -s)

if [ "${#bad[@]}" -ne 0 ]; then
    echo "absolute symlink(s) committed (must be relative):"
    printf '  %s\n' "${bad[@]}"
    exit 1
fi
echo "no absolute symlinks committed"
