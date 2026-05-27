#!/usr/bin/env bash
# One-time helper to regenerate the bundled snapshot fixtures from the
# upstream insta snapshots at $JA4_UPSTREAM (defaults to ../../ja4 relative to
# this repo). The fixtures live in tests/testdata/snapshots/ and ARE committed
# to this repo — you only need to run this if upstream changes.
#
# Source files are named `ja4__insta@<pcap-name>.snap` and start with an insta
# header like:
#
#     ---
#     source: ja4/src/lib.rs
#     expression: output
#     ---
#
# We strip the header (everything up to and including the second `---` line)
# and write the remainder as `<pcap-name>.yaml`.
#
# Skips `ja4__insta@gtp-iphone.pcap.snap` — the corresponding pcap is not
# distributed in the upstream `pcap/` directory.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
UPSTREAM="${JA4_UPSTREAM:-${HERE}/../../ja4}"
SRC_DIR="${UPSTREAM}/rust/ja4/src/snapshots"
DST_DIR="${HERE}/testdata/snapshots"

if [ ! -d "${SRC_DIR}" ]; then
    echo "snapshot source dir not found: ${SRC_DIR}" >&2
    echo "set JA4_UPSTREAM to the path of a FoxIO-LLC/ja4 checkout" >&2
    exit 1
fi

mkdir -p "${DST_DIR}"

shopt -s nullglob
count=0
for src in "${SRC_DIR}"/ja4__insta@*.snap; do
    base=$(basename "${src}")
    name=${base#ja4__insta@}     # strip prefix
    name=${name%.snap}           # strip suffix

    if [ "${name}" = "gtp-iphone.pcap" ]; then
        # pcap not bundled upstream — skip
        continue
    fi

    dst="${DST_DIR}/${name}.yaml"
    awk '
        BEGIN { hdr = 0 }
        /^---$/ { hdr++; if (hdr <= 2) next }
        hdr >= 2 { print }
    ' "${src}" > "${dst}"
    count=$((count + 1))
done

echo "imported ${count} snapshots into ${DST_DIR}"
