#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: sh tests/smoke.sh /absolute/path/to/apout /path/to/PDP11" >&2
    exit 2
fi
apout=$1
fixtures=$2
work=$(mktemp -d "${TMPDIR:-/tmp}/apout-tests.XXXXXX")
trap 'rm -f "$work/output" "$work/expected" "$work/apout.dbg"; rmdir "$work"' EXIT HUP INT TERM
cd "$work"
count=0

for root in v6root v7root bsdroot; do
    binary="$fixtures/$root/bin/echo"
    if [ ! -f "$binary" ]; then
        echo "Missing fixture: $binary" >&2
        exit 1
    fi
    APOUT_ROOT="$fixtures/$root" "$apout" "$binary" apout regression > output
    printf 'apout regression\n' > expected
    cmp expected output
    count=$((count + 1))
done

APOUT_ROOT="$fixtures/v7root" "$apout" "$fixtures/v7root/bin/expr" 6 '*' 7 > output
printf '42\n' > expected
cmp expected output
count=$((count + 1))

APOUT_ROOT="$fixtures/v7root" "$apout" "$fixtures/v7root/bin/cal" 1 1970 > output
grep '1970' output > /dev/null
grep '1  2  3' output > /dev/null
count=$((count + 1))

printf 'alpha\nbeta\n' > expected
APOUT_ROOT="$fixtures/v7root" "$apout" "$fixtures/v7root/bin/cat" expected > output
cmp expected output
count=$((count + 1))
echo "Historical binaries: $count checks, 0 failures"
