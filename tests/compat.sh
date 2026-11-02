#!/bin/sh
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: sh tests/compat.sh apout [all|write|files|arithmetic|exec]" >&2
    exit 2
fi
tests=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec "$tests/fixtures/run" "$1" "$tests/fixtures" "${2:-all}"
