#!/usr/bin/env bash
# Package entry point. The real work lives in deploy/install.sh; this wrapper
# resolves the package root from its own location so the caller's working
# directory never matters.
set -Eeuo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec bash "$here/deploy/install.sh" "$@"
