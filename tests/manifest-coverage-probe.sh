#!/usr/bin/env bash
# Reproduce the install.sh manifest-coverage comparison on an extracted package.
set -u
cd -- "$1" || exit 1

echo "--- payload (files except SHA256SUMS) ---"
find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort > /tmp/np-payload.txt
wc -l < /tmp/np-payload.txt

echo "--- listing (manifest, awk-normalized) ---"
awk 'NF>=2 { $1=""; sub(/^ /,""); print }' SHA256SUMS | sort > /tmp/np-listing.txt
wc -l < /tmp/np-listing.txt

echo "--- first 3 payload, cat -A ---"
head -3 /tmp/np-payload.txt | cat -A
echo "--- first 3 listing, cat -A ---"
head -3 /tmp/np-listing.txt | cat -A

echo "--- diff (payload vs listing) ---"
if diff -u /tmp/np-payload.txt /tmp/np-listing.txt > /tmp/np-diff.txt; then
    echo "IDENTICAL"
else
    head -24 /tmp/np-diff.txt
fi

echo "--- manifest line count / entries on disk ---"
wc -l < SHA256SUMS
find . -type f | wc -l
