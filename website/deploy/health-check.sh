#!/usr/bin/env bash
# Health check for the static site.
#
# The old check asserted on a JSON body from /health. A static site has no
# endpoint, so this one asserts on what a static site can actually promise: the
# pages are served, they are the build we deployed (the version marker is in the
# HTML), and the assets the pages reference resolve.
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
    echo '用法：bash health-check.sh <website-version> <diagnostic-directory>' >&2
    exit 2
fi

version=$1
diagnostics=$2
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid website version: $version" >&2; exit 2; }
mkdir -p -- "$diagnostics"

host=nova.fbi.plus

fetch() {
    # $1 scheme, $2 path, $3 label
    local scheme=$1 path=$2 label=$3
    local headers="$diagnostics/$label-$scheme.headers" body="$diagnostics/$label-$scheme.body"
    local code=000
    if [[ $scheme == http ]]; then
        code=$(curl --noproxy '*' --silent --show-error --max-time 10 \
            -D "$headers" -o "$body" -w '%{http_code}' \
            -H "Host: $host" "http://127.0.0.1$path" 2>/dev/null) || code=000
    else
        code=$(curl --noproxy '*' --silent --show-error --insecure \
            --resolve "$host:443:127.0.0.1" --max-time 10 \
            -D "$headers" -o "$body" -w '%{http_code}' "https://$host$path" 2>/dev/null) || code=000
    fi
    [[ $code =~ ^[0-9]{3}$ ]] || code=000
    printf '%s\n' "$code" > "$diagnostics/$label-$scheme.status"
    LAST_CODE=$code
    LAST_BODY=$body
}

# Everything the site must serve after an install: the pages, the feed, the
# assets they reference, and the 404 document nginx falls back to.
check_site() {
    local scheme=$1 failures=0
    local path
    for path in / /download /client-updates /sdk /privacy /data/releases.json /css/site.css /js/site.js /assets/novaprotect.png /favicon.ico; do
        fetch "$scheme" "$path" "$(echo "$path" | tr '/' '_' | tr -d '.-')"
        if [[ $LAST_CODE != 200 ]]; then
            echo "  $scheme $path -> $LAST_CODE" >&2
            failures=$((failures + 1))
        fi
    done

    # The deployed pages carry the version in the markup; a stale slot shows the
    # old number, which is the failure this check exists to catch.
    fetch "$scheme" / "home" || true
    if [[ $LAST_CODE == 200 ]] && ! grep -q "网站版本 $version" "$LAST_BODY"; then
        echo "  $scheme version marker '$version' not found in the home page" >&2
        failures=$((failures + 1))
    fi

    # A missing path must produce the 404 document, not a directory listing or
    # an origin error page.
    fetch "$scheme" "/this-path-must-not-exist-np" "missing" || true
    if [[ $LAST_CODE != 404 ]]; then
        echo "  $scheme missing path -> $LAST_CODE (expected 404)" >&2
        failures=$((failures + 1))
    fi

    [[ $failures -eq 0 ]]
}

# HTTP may redirect to HTTPS; either origin answering correctly is a pass.
if check_site https; then exit 0; fi
if check_site http; then exit 0; fi
exit 1
