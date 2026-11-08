#!/usr/bin/env bash
# Diagnose "403 Forbidden" on a plain static site dropped into a webroot.
#
# The package itself is flat: index.html sits at the archive root, so a 403 is
# almost never a packaging problem. It is one of four things, in descending order
# of how often they actually happen on BaoTa/aaPanel:
#
#   1. the site's 运行目录 (document root) points somewhere that is not where you
#      unzipped, very often /public left over from a previous PHP deployment;
#   2. the files are owned by root or lack the execute bit on directories, so the
#      nginx worker user cannot traverse into them;
#   3. the archive was extracted one level too deep, so the document root contains
#      a single folder instead of index.html;
#   4. an index file is missing or misnamed.
#
# Usage:
#   bash diagnose-static-403.sh --root /www/wwwroot/example.com --domain example.com
#   bash diagnose-static-403.sh --root /www/wwwroot/example.com --domain example.com --fix
#
# --fix only changes permissions and ownership; it never deletes or moves files.

set -u

root=''
domain=''
do_fix=0

usage() {
    cat <<'EOF'
Diagnose "403 Forbidden" on a plain static site dropped into a webroot.

Usage:
  bash diagnose-static-403.sh                      # auto-detect the site
  bash diagnose-static-403.sh --fix                # auto-detect, then fix perms
  bash diagnose-static-403.sh --root /www/wwwroot/example.com --domain example.com

Options:
  --root PATH       document root; defaults to the current directory when it
                    holds an index.html, else the only site under /www/wwwroot
  --domain NAME     site name used to find the panel config and error log;
                    inferred from the vhost whose root matches
  --fix             set ownership to the nginx worker user and modes to 755/644
  -h, --help        this text

Nothing is deleted or moved; --fix only touches ownership and permission bits.
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --root) root=${2:-}; shift 2 ;;
        --domain) domain=${2:-}; shift 2 ;;
        --fix) do_fix=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; echo >&2; usage >&2; exit 2 ;;
    esac
done

# --- auto-detection -------------------------------------------------------
# Running with no arguments is the common case: the operator is standing in the
# site directory or has exactly one site on the box. Resolve both instead of
# printing usage and making them look up a path.
if [[ -z $root ]]; then
    if [[ -f ./index.html ]]; then
        root=$PWD
    elif [[ -d /www/wwwroot ]]; then
        found=()
        for candidate in /www/wwwroot/*/; do
            [[ -d $candidate ]] || continue
            # A directory with index.html is a site; panel boilerplate dirs are not.
            [[ -f ${candidate}index.html ]] && found+=("${candidate%/}")
        done
        if [[ ${#found[@]} -eq 1 ]]; then
            root=${found[0]}
            printf 'auto-detected document root: %s\n' "$root"
        elif [[ ${#found[@]} -eq 0 ]]; then
            printf 'no site with an index.html under /www/wwwroot\n' >&2
            printf 'pass the directory explicitly: --root /www/wwwroot/<site>\n' >&2
            exit 2
        else
            printf 'several sites found; pick one with --root:\n' >&2
            printf '  %s\n' "${found[@]}" >&2
            exit 2
        fi
    else
        usage >&2
        exit 2
    fi
fi

# Only consider directories that really look like this site, so a stray
# index.html elsewhere does not silently get treated as the webroot.
if [[ ! -d $root ]]; then
    printf 'not a directory: %s\n' "$root" >&2
    exit 2
fi
root=$(cd -- "$root" && pwd)

if [[ -z $domain ]] && [[ -d /www/server/panel/vhost/nginx ]]; then
    # First try: the vhost whose `root` is exactly this directory.
    for conf in /www/server/panel/vhost/nginx/*.conf; do
        [[ -f $conf ]] || continue
        conf_root=$(awk '/^[[:space:]]*root[[:space:]]/ {print $2; exit}' -- "$conf" 2>/dev/null | tr -d ';"')
        conf_root=${conf_root%/}
        [[ -z $conf_root ]] && continue
        if [[ $(cd -- "$conf_root" 2>/dev/null && pwd) == "$root" ]]; then
            domain=$(basename -- "$conf" .conf)
            printf 'auto-detected domain from vhost root: %s\n' "$domain"
            break
        fi
    done

    # Second try: same name as the directory. This is the case that matters when
    # the vhost root is NOT this directory -- typically /public left over from a
    # PHP deployment, which is itself the reason for the 403.
    if [[ -z $domain ]]; then
        base=$(basename -- "$root")
        if [[ -f /www/server/panel/vhost/nginx/$base.conf ]]; then
            domain=$base
            printf 'auto-detected domain from directory name: %s\n' "$domain"
        fi
    fi
fi

# Last resort: the site directory name is almost always the domain, and the log
# path follows it. Better to show a log than to skip the whole section.
if [[ -z $domain ]]; then
    domain=$(basename -- "$root")
    [[ $domain == *.* ]] && printf 'assuming domain from directory name: %s\n' "$domain"
fi

say() { printf '\n=== %s ===\n' "$1"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '  !! %s\n' "$*"; }

# --- 1. document root ------------------------------------------------------
say 'document root'
if [[ ! -d $root ]]; then
    warn "not a directory: $root"
    note 'the site root in the panel does not exist; check 网站 -> 设置 -> 网站目录'
    exit 1
fi
note "resolved: $(cd -- "$root" && pwd)"
ls -la -- "$root" | sed 's/^/  /'

say 'index files'
found_index=0
for candidate in index.html index.htm; do
    if [[ -f $root/$candidate ]]; then
        note "found $candidate ($(stat -c '%s bytes mode=%a owner=%U:%G' -- "$root/$candidate"))"
        found_index=1
    fi
done
if [[ $found_index -eq 0 ]]; then
    warn 'no index.html at the document root -- nginx answers 403 for a directory it cannot index'
    # A single nested folder is the classic "extracted one level too deep" case.
    shopt -s nullglob
    entries=("$root"/*)
    shopt -u nullglob
    if [[ ${#entries[@]} -eq 1 && -d ${entries[0]} ]]; then
        warn "the root holds exactly one directory: ${entries[0]}"
        note 'likely extracted one level too deep; move its contents up:'
        note "  mv -- \"${entries[0]}\"/* \"$root\"/ && rmdir -- \"${entries[0]}\""
    fi
    # Case accidents happen when a Windows tool renames files.
    shopt -s nullglob nocaseglob
    odd=("$root"/*ndex*)
    shopt -u nullglob nocaseglob
    for item in "${odd[@]:-}"; do
        [[ -n ${item:-} ]] && warn "case-variant present: $item (Linux is case-sensitive; rename it to index.html)"
    done
fi

# --- 2. nginx worker user and readability ---------------------------------
say 'nginx worker user'
nginx_user=''
if command -v nginx >/dev/null 2>&1; then
    nginx_user=$(nginx -T 2>/dev/null | awk '/^[[:space:]]*user[[:space:]]/ {print $2; exit}')
fi
if [[ -z $nginx_user ]] && [[ -r /etc/nginx/nginx.conf ]]; then
    nginx_user=$(awk '/^[[:space:]]*user[[:space:]]/ {print $2; exit}' /etc/nginx/nginx.conf)
fi
[[ -z $nginx_user ]] && nginx_user='www'
note "worker user: $nginx_user"

if id "$nginx_user" >/dev/null 2>&1; then
    if [[ $found_index -eq 1 ]]; then
        if su -s /bin/sh "$nginx_user" -c "test -r '$root/index.html'" 2>/dev/null; then
            note "index.html IS readable by $nginx_user"
        else
            warn "index.html is NOT readable by $nginx_user -- this alone produces 403"
        fi
    fi
    if su -s /bin/sh "$nginx_user" -c "test -x '$root'" 2>/dev/null; then
        note "document root IS traversable by $nginx_user"
    else
        warn "document root is NOT traversable by $nginx_user (missing execute bit or wrong owner)"
    fi
else
    note "user $nginx_user does not exist on this host; skipped the readability probe"
fi

say 'ownership / permissions'
bad_dirs=$(find "$root" -type d ! -perm -o+rx 2>/dev/null | head -10)
bad_files=$(find "$root" -type f ! -perm -o+r 2>/dev/null | head -10)
if [[ -n $bad_dirs ]]; then
    warn 'directories missing o+rx:'
    printf '  %s\n' $bad_dirs
fi
if [[ -n $bad_files ]]; then
    warn 'files missing o+r:'
    printf '  %s\n' $bad_files
fi
[[ -z $bad_dirs && -z $bad_files ]] && note 'every entry is world-readable/traversable'

# --- 3. what the panel thinks the root is --------------------------------
say 'panel / nginx site config'
conf=""
for candidate in "/www/server/panel/vhost/nginx/${domain}.conf" "/etc/nginx/conf.d/${domain}.conf"; do
    [[ -f $candidate ]] && { conf=$candidate; break; }
done

if [[ -z $conf ]]; then
    note "no vhost found for ${domain:-<unknown>}"
    note 'looked in /www/server/panel/vhost/nginx and /etc/nginx/conf.d'
else
    note "config: $conf"
    conf_root=$(awk '/^[[:space:]]*root[[:space:]]/ {print $2, $3; exit}' -- "$conf" 2>/dev/null | tr -d ';' | awk '{print $1}')
    conf_index=$(awk '/^[[:space:]]*index[[:space:]]/ {print; exit}' -- "$conf" 2>/dev/null | sed 's/^[[:space:]]*//')
    note "configured root : ${conf_root:-<none, inherits>}"
    note "configured index: ${conf_index:-<none, inherits nginx default index.html>}"

    # This is the single most common cause once permissions are ruled out: the
    # panel still points the site at a subdirectory (classically /public) that
    # does not exist in a flat static upload.
    if [[ -n $conf_root ]]; then
        conf_root_norm=${conf_root%/}
        if [[ $conf_root_norm != "$root" ]]; then
            warn "configured root is NOT this directory"
            if [[ ! -d $conf_root_norm ]]; then
                warn "  $conf_root_norm does not exist at all -- nginx cannot serve it"
            fi
            note 'fix it in the panel: 网站 -> 设置 -> 网站目录 -> 运行目录 = /'
            note "  or edit $conf and set: root $root;"
        else
            note 'configured root matches this directory'
        fi
    fi

    # Anything that can turn a valid request into 403 on a static site.
    say 'directives that can cause 403'
    hits=$(grep -nE '^[[:space:]]*(try_files|auth_basic|deny|allow|autoindex)|location[[:space:]]' -- "$conf" 2>/dev/null)
    if [[ -n $hits ]]; then
        printf '%s\n' "$hits" | sed 's/^/  /'
    else
        note 'none found in this file; it may include others (include /www/server/panel/vhost/rewrite/*.conf)'
    fi
    for rewrite in "/www/server/panel/vhost/rewrite/${domain}.conf"; do
        if [[ -f $rewrite ]]; then
            note "伪静态 file present: $rewrite"
            grep -nE 'try_files|deny|location' -- "$rewrite" 2>/dev/null | sed 's/^/  /'
        fi
    done
fi

# --- 4. error log --------------------------------------------------------
say 'recent error log'
shown_log=0
for log in "/www/wwwlogs/${domain}.error.log" "/var/log/nginx/${domain}.error.log" "/var/log/nginx/error.log"; do
    if [[ -n $domain && -f $log ]]; then
        note "log: $log"
        tail -n 10 -- "$log" | sed 's/^/  /'
        shown_log=1
        break
    fi
done
[[ $shown_log -eq 0 ]] && note 'no readable log found for this site'

# --- 5. local request ----------------------------------------------------
# The distinction that matters: if a concrete file is served but a directory is
# not, the 403 is index resolution and the answer is in the vhost. If even a
# concrete file is refused, the request never reaches the static handler (a WAF,
# an auth rule, or a deny directive).
say 'local request'
if [[ -n $domain ]] && command -v curl >/dev/null 2>&1; then
    probe() {
        local path=$1 label=$2
        local status
        status=$(curl -sS -o /dev/null -w '%{http_code}' -m 5 -H "Host: $domain" "http://127.0.0.1$path" 2>/dev/null)
        printf '  %-24s %s\n' "$path" "$status"
        [[ -n $label ]] && printf '  %-24s %s\n' '' "$label"
    }
    probe '/' 'directory, relies on the index directive'
    probe '/index.html' 'concrete file at the document root'
    probe '/favicon.ico' 'concrete binary file'
    probe '/css/site.css' 'file inside a subdirectory'
    probe '/download/' 'directory with an index.html inside'

    say 'response headers for /'
    curl -sS -o /dev/null -D - -m 5 -H "Host: $domain" http://127.0.0.1/ 2>&1 | head -10 | sed 's/^/  /'

    # Cookies or cache-busting headers on a 403 are not nginx behaviour: that is
    # a WAF or panel module rewriting the response, and then the file permissions
    # and index directive are beside the point.
    set_cookie=$(curl -sS -o /dev/null -D - -m 5 -H "Host: $domain" http://127.0.0.1/ 2>/dev/null | grep -ci '^set-cookie')
    if [[ ${set_cookie:-0} -gt 0 ]]; then
        warn 'the 403 response carries a Set-Cookie header'
        note 'nginx alone does not do that; a WAF or panel module is answering'
        note 'check 宝塔 -> 网站防火墙 / 免费 WAF, and any CDN in front of the domain'
    fi
else
    note 'skipped (need a domain and curl)'
fi

# --- 6. effective configuration -----------------------------------------
# include directives can add an index override or a deny rule that the site file
# itself does not show, so dump what nginx actually loaded for this server.
say 'effective server block'
if [[ -n $domain ]] && command -v nginx >/dev/null 2>&1; then
    block=$(nginx -T 2>/dev/null | awk -v d="$domain" '
        $1 == "server" { inblock = 1; buf = ""; hit = 0 }
        inblock { buf = buf $0 "\n" }
        inblock && /server_name/ && index($0, d) { hit = 1 }
        inblock && /^}/ { if (hit) { printf "%s", buf; exit } inblock = 0 }
    ')
    if [[ -n $block ]]; then
        printf '%s\n' "$block" | grep -nE 'listen|server_name|root|index|try_files|include|deny|auth_basic|location' | sed 's/^/  /'
        if printf '%s\n' "$block" | grep -qE '^[[:space:]]*index[[:space:]]'; then
            idx=$(printf '%s\n' "$block" | awk '/^[[:space:]]*index[[:space:]]/ {print; exit}' | sed 's/^[[:space:]]*//')
            note "effective index: $idx"
            case $idx in
                *index.html*) note 'index.html is listed, so the 403 is NOT index resolution' ;;
                *) warn 'index.html is NOT in the index list -- that produces exactly this 403' ;;
            esac
        else
            note 'no index directive in the server block; nginx default is index.html'
        fi
    else
        note "could not isolate a server block for $domain from nginx -T"
        note 'run: nginx -T | less  and search for server_name'
    fi
else
    note 'skipped (need a domain and the nginx binary)'
fi

# --- fix -----------------------------------------------------------------
if [[ $do_fix -eq 1 ]]; then
    say 'applying fix'
    chown -R "$nginx_user:$nginx_user" -- "$root" && note "ownership -> $nginx_user:$nginx_user"
    find "$root" -type d -exec chmod 755 {} + && note 'directories -> 755'
    find "$root" -type f -exec chmod 644 {} + && note 'files -> 644'
    note 'done; retry the request (nginx does not need a restart for this)'
else
    say 'next'
    note 'rerun with --fix to set ownership and modes, or do it by hand:'
    note "  chown -R $nginx_user:$nginx_user $root"
    note "  find $root -type d -exec chmod 755 {} +"
    note "  find $root -type f -exec chmod 644 {} +"
fi
