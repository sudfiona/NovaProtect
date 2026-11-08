#!/usr/bin/env bash
# NovaProtect static site installer.
#
# What changed from the PHP era: no PHP, no PHP-FPM socket, no admin password,
# no install token, no data directory, no upgrade executor. This script only
# puts files on disk, points the vhost's root at them, and proves the pages are
# served. Everything the old installer did for the application runtime is gone
# because there is no application runtime.
#
# Layout under /www/wwwroot/<domain>:
#   releases/<version>-<stamp>/public/...   immutable deploy slots
#   current -> releases/<version>-<stamp>   active slot
#   previous -> releases/<version>-<stamp>  slot to roll back to
#
# TLS is not invented here: the listen/ssl_* directives are lifted from the
# vhost BaoTa already manages, so an existing certificate keeps working and a
# fresh install stays plain HTTP until the operator adds TLS in the panel.
set -Eeuo pipefail
umask 022

if [[ $# -gt 0 && $1 != --check-package ]]; then
    echo '用法：bash install.sh [--check-package]' >&2
    exit 2
fi
check_only=0
[[ ${1:-} == --check-package ]] && check_only=1

# This script sits in deploy/, but every path below is relative to the package
# root one level up. Resolve that properly instead of trusting the working
# directory, so both `bash install.sh` (root wrapper) and `bash deploy/install.sh`
# (direct) find the same files.
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -f $here/../VERSION && -d $here/../public ]]; then
    bundle=$(cd -- "$here/.." && pwd)
else
    bundle=$here
fi
domain=${NOVAPROTECT_DOMAIN:-nova.fbi.plus}
[[ $domain =~ ^[A-Za-z0-9.-]+$ ]] || { echo "域名不合法：$domain" >&2; exit 2; }

base=/www/wwwroot/$domain
state=/www/server/$domain
nginx_vhost=/www/server/panel/vhost/nginx/$domain.conf
nginx_bin=/www/server/nginx/sbin/nginx

note() { printf '%s\n' "$*"; }
fail() { printf '%s\n' "$*" >&2; exit 1; }

# --- package verification (read-only, no root required) -------------------
verify_bundle() {
    [[ -f $bundle/SHA256SUMS ]] || fail "包内缺少 SHA256SUMS：$bundle"
    local version_line
    version_line=$(tr -d '\r\n' < "$bundle/VERSION")
    [[ $version_line =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "包内 VERSION 不合法：$version_line"
    version=$version_line

    for required in VERSION SHA256SUMS release.json package.json public/index.html public/download.html \
        public/client-updates.html public/404.html public/css/site.css public/js/site.js \
        public/data/releases.json public/favicon.ico deploy/nginx-location.conf; do
        [[ -f $bundle/$required ]] || fail "包内缺少文件：$required"
    done

    # Every listed file must exist with a matching digest, and every payload
    # file must be listed: a manifest that misses a file protects nothing.
    local listed=0 bad=0
    while read -r digest path; do
        [[ -z ${digest:-} || -z ${path:-} ]] && continue
        listed=$((listed + 1))
        local target=$bundle/$path
        if [[ ! -f $target ]]; then
            note "  SHA256SUMS 列出的文件不存在：$path"
            bad=$((bad + 1)); continue
        fi
        local actual
        actual=$(sha256sum -- "$target" | awk '{print $1}')
        if [[ ${digest,,} != "$actual" ]]; then
            note "  SHA-256 不匹配：$path"
            bad=$((bad + 1))
        fi
    done < "$bundle/SHA256SUMS"
    [[ $listed -gt 0 ]] || fail 'SHA256SUMS 为空。'
    [[ $bad -eq 0 ]] || fail "包校验失败：$bad 项不一致。"

    local payload listing
    # SHA256SUMS is the one entry a manifest cannot list (a file cannot hold its
    # own digest), so it is excluded from the payload side of this comparison.
    # The archive-level .sha256 that ships next to the ZIP is likewise not part
    # of the bundle; if a caller copies it in, it must not be mistaken for a
    # packaging defect.
    payload=$(cd -- "$bundle" && find . -type f ! -name SHA256SUMS ! -name '*.zip.sha256' \
        | sed 's|^\./||' | LC_ALL=C sort)
    listing=$(awk 'NF>=2 { $1=""; sub(/^[[:space:]]+/,""); print }' "$bundle/SHA256SUMS" | LC_ALL=C sort)
    if [[ "$payload" != "$listing" ]]; then
        # Name the offenders instead of leaving the operator to guess which file
        # was added after packaging or left out of the manifest. Both sides are
        # byte-collated first: sort under the ambient locale and comm under C
        # disagree about ordering, which silently yields wrong results.
        local uncovered extra
        uncovered=$(LC_ALL=C comm -23 \
            <(printf '%s\n' "$payload") <(printf '%s\n' "$listing"))
        extra=$(LC_ALL=C comm -13 \
            <(printf '%s\n' "$payload") <(printf '%s\n' "$listing"))
        if [[ -n $uncovered ]]; then
            echo '包内文件未列入 SHA256SUMS：' >&2
            printf '  %s\n' $uncovered >&2
        fi
        if [[ -n $extra ]]; then
            echo 'SHA256SUMS 列出但包内不存在：' >&2
            printf '  %s\n' $extra >&2
        fi
        fail 'SHA256SUMS 未完整覆盖包内文件（有文件未列入清单）。'
    fi
    note "包校验通过：$version（$listed 个文件）"
}

verify_bundle
if [[ $check_only -eq 1 ]]; then
    note 'CHECKS-OK（只读校验，未改动系统）'
    exit 0
fi

# --- root-only install ----------------------------------------------------
[[ ${EUID} -eq 0 ]] || fail "请使用 root 运行：sudo bash install.sh"
command -v curl >/dev/null 2>&1 || fail '缺少 curl。'
command -v sha256sum >/dev/null 2>&1 || fail '缺少 sha256sum。'

if [[ ! -x $nginx_bin ]]; then
    nginx_bin=$(command -v nginx 2>/dev/null || true)
fi
[[ -n ${nginx_bin:-} && -x $nginx_bin ]] || fail '未找到 Nginx（宝塔路径 /www/server/nginx/sbin/nginx）。'

mkdir -p -- "$base/releases" "$state"
exec 9>"$state/deploy.lock"
flock -n 9 || fail '另一安装进程正在运行。'

stamp=$(date -u +%Y%m%dT%H%M%SZ)
slot=$base/releases/$version-$stamp
backup=$state/backups/$stamp

cleanup_partial() {
    if [[ -n ${slot:-} && -d $slot && $slot == "$base/releases/"* ]]; then
        rm -rf -- "$slot"
    fi
}
trap 'cleanup_partial' ERR

# --- backup the things a rollback needs ----------------------------------
mkdir -p -- "$backup"
readlink -f -- "$base/current" 2>/dev/null > "$backup/old-current" || : > "$backup/old-current"
readlink -f -- "$base/previous" 2>/dev/null > "$backup/old-previous" || : > "$backup/old-previous"
if [[ -f $nginx_vhost ]]; then
    install -m 0644 -- "$nginx_vhost" "$backup/vhost.conf"
else
    printf 'missing\n' > "$backup/vhost-missing"
fi
ln -sfn -- "$backup" "$state/last-backup"
note "已备份到：$backup"

# --- lay down the slot ----------------------------------------------------
mkdir -p -- "$slot"
# The package's public/ is the document root; deploy/ and the manifests stay
# beside it so a later upgrade can verify itself in place.
cp -a -- "$bundle/public" "$slot/public"
for f in VERSION release.json package.json SHA256SUMS; do
    [[ -f $bundle/$f ]] && cp -a -- "$bundle/$f" "$slot/$f"
done
chmod -R a+rX -- "$slot"

# --- vhost ----------------------------------------------------------------
# Reuse the TLS posture the panel already configured instead of assuming one.
tls_lines=''
if [[ -f $nginx_vhost ]]; then
    tls_lines=$(grep -E '^[[:space:]]*(listen[[:space:]]+[^;]*ssl|ssl_certificate|ssl_certificate_key|ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers|ssl_session_cache|ssl_session_timeout|ssl_session_tickets|ssl_stapling|ssl_trusted_certificate|ssl_dhparam|ssl_early_data)[[:space:]]' "$nginx_vhost" | sed 's/^[[:space:]]*//' || true)
fi

has_tls=0
if [[ -n $tls_lines ]] && grep -q '^ssl_certificate ' <<<"$tls_lines"; then
    has_tls=1
fi

mkdir -p -- "$(dirname -- "$nginx_vhost")"
tmp_vhost=$(mktemp)
{
    echo '# Generated by NovaProtect install.sh -- static site, no PHP.'
    echo 'server {'
    if [[ $has_tls -eq 1 ]]; then
        printf '%s\n' "$tls_lines"
    else
        echo '    listen 80;'
        echo '    listen [::]:80;'
    fi
    echo "    server_name $domain;"
    echo
    echo "    root $base/current/public;"
    echo '    index index.html;'
    echo
    sed "s|@@DOCUMENT_ROOT@@|$base/current/public|" "$bundle/deploy/nginx-location.conf"
    echo '}'
} > "$tmp_vhost"
install -m 0644 -- "$tmp_vhost" "$nginx_vhost"
rm -f -- "$tmp_vhost"

# --- switch the slots -----------------------------------------------------
if [[ -d $base/current ]]; then
    # First install: there is no previous slot to preserve.
    :
fi
old_current=$(readlink -f -- "$base/current" 2>/dev/null || true)
if [[ -n $old_current && $old_current == "$base/releases/"* ]]; then
    ln -sfn -- "$old_current" "$base/previous.new"
    mv -Tf -- "$base/previous.new" "$base/previous"
fi
ln -sfn -- "$slot" "$base/current.new"
mv -Tf -- "$base/current.new" "$base/current"

"$nginx_bin" -t || fail 'Nginx 配置校验失败，未重载。用 deploy/rollback.sh 回滚。'
"$nginx_bin" -s reload
trap - ERR

# --- prove it serves ------------------------------------------------------
sleep 1
if bash "$bundle/deploy/health-check.sh" "$version" "$state/diagnostics" >/dev/null 2>&1; then
    note "健康检查通过：$domain 正在提供 $version。"
else
    echo '健康检查未通过。诊断输出在：' "$state/diagnostics" >&2
    bash "$bundle/deploy/health-check.sh" "$version" "$state/diagnostics" || true
    fail '安装未通过健康检查，请运行 deploy/rollback.sh 回滚。'
fi

note ''
note "网站已安装：https://$domain/  版本 $version"
note "发布槽位：$base/current -> $slot"
if [[ $has_tls -eq 0 ]]; then
    note '未检测到 TLS 配置：当前仅监听 80。请在宝塔面板为该站点申请证书。'
fi
note '本包没有后台、没有数据库、没有 PHP。更新内容请重新部署新版本包。'
