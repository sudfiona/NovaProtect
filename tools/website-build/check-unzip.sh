#!/usr/bin/env bash
# Extracts the shipped package with the platform's own unzip and reports what a
# Linux operator would actually get: directory layout, root files, and whether
# the shell scripts arrive executable.
set -uo pipefail
zip=$1
work=/tmp/np-unzip-check

rm -rf "$work"
mkdir -p "$work"
cd "$work" || exit 1
unzip -q "$zip" || { echo "unzip failed"; exit 1; }

echo "  top-level entries:"
ls -p | sed 's/^/    /'
echo "  nested files under public/:"
find public -type f | sort | head -14 | sed 's/^/    /'
echo "  script permissions:"
for f in install.sh deploy/install.sh deploy/rollback.sh deploy/health-check.sh; do
    if [ -f "$f" ]; then
        printf '    %-26s %s\n' "$f" "$(stat -c '%A' "$f")"
    else
        printf '    %-26s MISSING\n' "$f"
    fi
done
echo "  install.sh first line: $(head -1 install.sh)"
# grep -l and -c are mutually exclusive; count occurrences instead, and search
# the whole tree so a stray CRLF anywhere is caught.
crlf=0
while IFS= read -r f; do
    if LC_ALL=C grep -q $'\r' "$f" 2>/dev/null; then
        echo "    CRLF: $f"
        crlf=$((crlf + 1))
    fi
done < <(find . -name '*.sh' -type f)
echo "  scripts with CRLF: $crlf"
