#!/usr/bin/env bash
# SC-002: no private-key or credential material in any captured output. The
# integration suite marks every stored secret (LCM-MARKER-SECRET-*) and never
# expects a PEM private key, ACME/DNS credential or webhook signing secret in a
# listing, credential-free export, event, webhook body or captured log.
set -euo pipefail
ART="${ARTIFACTS:-.artifacts}"; export FREYA_CAPTURE_DIR="$ART/capture"; mkdir -p "$FREYA_CAPTURE_DIR"
go test -count=1 -tags integration ./tests/integration/... -run 'Test' -v > "$ART/integration.log" 2>&1 || { tail -50 "$ART/integration.log"; exit 1; }
cp "$ART/integration.log" "$FREYA_CAPTURE_DIR/suite.log"
n=0; for pat in 'LCM-MARKER-SECRET-' '-----BEGIN [A-Z ]*PRIVATE KEY-----' 'LCM-MARKER-DNS-' 'LCM-MARKER-ACME-'; do
  c=$({ grep -rc -- "$pat" "$FREYA_CAPTURE_DIR" || true; } | awk -F: '{s+=$2} END {print s+0}'); echo "redaction-scan: '$pat': $c"; n=$((n+c)); done
[[ "$n" -eq 0 ]] || { echo "redaction-scan: FAIL ($n matches)" >&2; exit 1; }; echo "redaction-scan: 0 matches"
