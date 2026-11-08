#!/usr/bin/env bash
# Exercise the manifest-coverage branch of deploy/install.sh in --check-package
# mode against four bundles: clean, one stray file, a stray checksum sidecar, and
# a bundle missing a file that the manifest still lists.
set -u
pkgdir=$1
failures=0

run_case() {
    local label=$1 expected=$2
    shift 2
    local out status
    out=$(bash "$pkgdir/install.sh" --check-package 2>&1)
    status=$?
    echo "=== $label (expect exit $expected) ==="
    printf '%s\n' "$out" | sed 's/^/  /'
    echo "  exit=$status"
    if [[ $status -ne $expected ]]; then
        echo "  RESULT: WRONG EXIT CODE"
        failures=$((failures + 1))
    else
        echo "  RESULT: ok"
    fi
    echo
}

run_case 'clean bundle' 0

touch "$pkgdir/public/stray-file.html"
run_case 'stray file added' 1
rm -f "$pkgdir/public/stray-file.html"

echo 'deadbeef  whatever.zip' > "$pkgdir/package.zip.sha256"
run_case 'archive sidecar copied in' 0
rm -f "$pkgdir/package.zip.sha256"

mv "$pkgdir/public/sdk.html" "$pkgdir/public/sdk.html.away"
run_case 'manifest lists a missing file' 1
mv "$pkgdir/public/sdk.html.away" "$pkgdir/public/sdk.html"

echo "FAILURES=$failures"
exit $([[ $failures -eq 0 ]] && echo 0 || echo 1)
