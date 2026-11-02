#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
    echo "Usage: sh tests/smoke.sh apout" >&2
    exit 2
fi
tests=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec "$tests/fixtures/run" "$1" "$tests/fixtures" smoke
