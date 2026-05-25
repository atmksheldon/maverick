#!/usr/bin/env bash
# Manual one-shot MAVERICK scan.
# Usage: ./scan-once.sh <targets-file> [--skip-masscan]
#
# Reads target IPs/CIDRs from <targets-file>, runs masscan + HTTP probe
# against the v0 Unitree fingerprint, writes JSONL to
# /var/lib/maverick/observations/YYYY-MM-DDTHHMMSSZ.jsonl.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <targets-file> [--skip-masscan]" >&2
  exit 2
fi

TARGETS="$1"; shift || true
EXTRA_ARGS=("$@")

if [ ! -r "$TARGETS" ]; then
  echo "cannot read targets file: $TARGETS" >&2
  exit 1
fi

DATESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
OUT_DIR=/var/lib/maverick/observations
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/$DATESTAMP.jsonl"

echo "MAVERICK scan-once" >&2
echo "  targets : $TARGETS ($(grep -cve '^\s*$\|^\s*#' "$TARGETS") entries)" >&2
echo "  output  : $OUT" >&2
echo "  started : $(date -u)" >&2

/opt/maverick-bin/probe --targets "$TARGETS" --out "$OUT" "${EXTRA_ARGS[@]}"

MATCHES=$(grep -c '"matched":true' "$OUT" || true)
TOTAL=$(wc -l < "$OUT")
echo "  ended   : $(date -u)" >&2
echo "  results : $TOTAL observation(s), $MATCHES matched" >&2
echo "  file    : $OUT" >&2
