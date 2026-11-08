#!/usr/bin/env bash
set -Eeuo pipefail

site_url=${1:-${NOVAPROTECT_SITE_URL:-https://nova.fbi.plus}}
site_url=${site_url%/}
case "$site_url" in
    https://*) ;;
    *) echo "Usage: bash deploy/cdnfly-check.sh https://nova.fbi.plus" >&2; exit 2 ;;
esac

timeout_seconds=${NOVAPROTECT_PREFLIGHT_TIMEOUT:-15}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/novaprotect-cdnfly.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT

failures=0
warnings=0
site_installed=unknown

contains_status() {
    local allowed=$1 actual=$2
    case " $allowed " in
        *" $actual "*) return 0 ;;
        *) return 1 ;;
    esac
}

check_response() {
    local name=$1 path=$2 method=$3 allowed=$4 body_payload=${5:-} mode=${6:-normal}
    local headers="$tmp/$name.headers" body="$tmp/$name.body" status curl_rc
    local url="$site_url$path"
    local -a curl_args=(
        --silent --show-error --compressed --http1.1
        --connect-timeout 8 --max-time "$timeout_seconds"
        --dump-header "$headers" --output "$body" --write-out '%{http_code}'
        -H 'Accept: application/json, text/html;q=0.9, */*;q=0.1'
        -H 'Cache-Control: no-cache'
        -H 'X-NovaProtect-Client: 1'
    )
    if [[ $method == POST ]]; then
        curl_args+=(
            -X POST
            -H 'Content-Type: application/json'
            -H "Origin: $site_url"
            -H 'Sec-Fetch-Site: same-origin'
            --data "$body_payload"
        )
    fi

    if ! status=$(curl "${curl_args[@]}" "$url"); then
        echo "[FAIL] $method $path: curl could not connect" >&2
        failures=$((failures + 1))
        return
    fi

    if [[ $mode != locked ]]; then
        if [[ $status == 444 ]] || grep -Eiq '^HTTP/[0-9.]+[[:space:]]+444([[:space:]]|$)' "$headers"; then
            echo "[FAIL] $method $path: CDNfly returned HTTP 444" >&2
            failures=$((failures + 1))
            return
        fi
    fi
    if [[ $mode != locked ]] && grep -Eiq '(^|/)_guard/auto\.js|cdnfly|human[[:space:]-]*verification|javascript[[:space:]-]*challenge' "$body"; then
        echo "[FAIL] $method $path: CDNfly guard content reached the client" >&2
        failures=$((failures + 1))
        return
    fi
    if ! contains_status "$allowed" "$status"; then
        echo "[FAIL] $method $path: unexpected HTTP $status (allowed: $allowed)" >&2
        failures=$((failures + 1))
        return
    fi

    echo "[ OK ] $method $path -> HTTP $status"
}

# The site is static now: there is no health endpoint, no admin login and no
# upload API to probe. What the edge still must not do is interrupt the pages,
# the release feed, or the assets a page needs to render.
check_response home / GET '200'
check_response download /download GET '200'
check_response changelog /client-updates GET '200'
check_response sdk /sdk GET '200'
check_response release_feed /data/releases.json GET '200'
check_response stylesheet /css/site.css GET '200'
check_response script /js/site.js GET '200'
check_response image /assets/novaprotect.png GET '200'
check_response favicon /favicon.ico GET '200'
# A page that does not exist must reach the origin's 404 document; a CDNfly
# challenge page here would mean the edge rewrites unknown paths into its guard.
check_response not_found /this-path-must-not-exist-np GET '404'

if (( failures > 0 )); then
    echo "CDNFLY-PREFLIGHT-FAILED ($failures failure(s), $warnings warning(s))" >&2
    echo "Apply deploy/cdnfly-edge-policy.json in CDNfly, purge the site cache, then rerun this script." >&2
    exit 1
fi
if (( warnings > 0 )); then
    echo "CDNFLY-PREFLIGHT-OK-WITH-WARNINGS ($warnings warning(s))"
else
    echo "CDNFLY-PREFLIGHT-OK"
fi
