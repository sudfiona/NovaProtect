#!/usr/bin/env bash
set -u
cd -- "$1" || exit 1
touch public/stray-file.html

payload=$(find . -type f ! -name SHA256SUMS ! -name '*.zip.sha256' | sed 's|^\./||' | sort)
listing=$(awk 'NF>=2 { $1=""; sub(/^[[:space:]]+/,""); print }' SHA256SUMS | sort)

echo "payload lines: $(printf '%s\n' "$payload" | wc -l)"
echo "listing lines: $(printf '%s\n' "$listing" | wc -l)"
echo "--- comm -23 payload listing ---"
LC_ALL=C comm -23 <(printf '%s\n' "$payload") <(printf '%s\n' "$listing")
echo "--- end ---"
echo "--- plain grep for the stray file ---"
printf '%s\n' "$payload" | grep stray || echo '(not in payload)'
printf '%s\n' "$listing" | grep stray || echo '(not in listing)'
rm -f public/stray-file.html
