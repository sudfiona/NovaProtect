#!/usr/bin/env bash
# Roll the static site back to the slot that was active before the last install.
#
# Simplified along with the site: there is no application service to restart
# and no shared application state to preserve, because there is no application.
# It restores the slot symlinks and the vhost, then proves the pages serve.
set -Eeuo pipefail
umask 022
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 运行 bash deploy/rollback.sh' >&2; exit 1; }

domain=${NOVAPROTECT_DOMAIN:-nova.fbi.plus}
base=/www/wwwroot/$domain
state=/www/server/$domain
nginx_vhost=/www/server/panel/vhost/nginx/$domain.conf
nginx_bin=/www/server/nginx/sbin/nginx

[[ -d $state/backups ]] || { echo '没有可用的安装备份目录。' >&2; exit 1; }
if [[ ! -x $nginx_bin ]]; then nginx_bin=$(command -v nginx 2>/dev/null || true); fi
[[ -n ${nginx_bin:-} && -x $nginx_bin ]] || { echo '未找到 Nginx。' >&2; exit 1; }

exec 9>"$state/deploy.lock"
flock -n 9 || { echo '另一安装/回滚进程正在运行。' >&2; exit 1; }

backup=$(readlink -f "$state/last-backup" 2>/dev/null || true)
[[ $backup == "$state/backups/"* && -d $backup ]] || { echo '没有可用的安装备份。' >&2; exit 1; }

read_slot() { tr -d '\r\n' < "$1" 2>/dev/null || true; }

validate_target() {
    local target=$1
    [[ -z $target ]] && return 0
    [[ $target == "$base/releases/"* ]] || { echo "备份中的发布目标不在允许目录：$target" >&2; exit 1; }
    [[ -d $target ]] || { echo "备份中的发布目录不存在：$target" >&2; exit 1; }
    # A static release is recognised by its document root, not by an entry script.
    [[ -f $target/public/index.html ]] || {
        echo "备份中的发布目录不是可识别的 NovaProtect 静态发布物：$target" >&2
        exit 1
    }
}

old_current=$(read_slot "$backup/old-current")
old_previous=$(read_slot "$backup/old-previous")
validate_target "$old_current"
validate_target "$old_previous"

restore_link() {
    local slot=$1 target=$2
    if [[ -n $target ]]; then
        ln -sfn -- "$target" "$slot.rollback"
        mv -Tf -- "$slot.rollback" "$slot"
    else
        rm -f -- "$slot"
    fi
}

restore_link "$base/current" "$old_current"
restore_link "$base/previous" "$old_previous"

if [[ -f $backup/vhost.conf ]]; then
    install -m 0644 -- "$backup/vhost.conf" "$nginx_vhost"
elif [[ -f $backup/vhost-missing ]]; then
    rm -f -- "$nginx_vhost"
else
    echo '备份缺少原站点 Nginx 配置，拒绝继续。' >&2
    exit 1
fi

"$nginx_bin" -t
"$nginx_bin" -s reload

version=''
if [[ -n $old_current && -f $old_current/VERSION ]]; then
    version=$(tr -d '\r\n' < "$old_current/VERSION")
fi
if [[ -n $version ]] && bash "$(dirname -- "${BASH_SOURCE[0]}")/health-check.sh" "$version" "$state/diagnostics" >/dev/null 2>&1; then
    echo "已回滚到 $version，健康检查通过。备份：$backup"
else
    echo "已恢复原槽位与 Nginx 配置，但健康检查未通过。诊断：$state/diagnostics" >&2
    echo "备份：$backup" >&2
    exit 1
fi
