#!/bin/sh
# Capture one gateway handshake with tcpdump, then verify it automatically.
#
#   sudo capture/capture.sh hybrid 8884      # profile, host port of MQTT/TLS
#
# Needs: tcpdump, python3. Run `docker compose up -d` first. Open the resulting
# capture/<profile>.pcap in Wireshark for the screenshot (see WIRESHARK.md).
set -e
PROFILE="${1:?usage: capture.sh <classical|hybrid|pqc> <port>}"
PORT="${2:?usage: capture.sh <classical|hybrid|pqc> <port>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/capture/$PROFILE.pcap"

# 'any' sees docker's published-port traffic on lo/docker0 alike
tcpdump -i any -s 0 -U -w "$OUT" "tcp port $PORT" &
TD=$!
sleep 1

python3 "$ROOT/edge/edge_node.py" --profile "$PROFILE" --port "$PORT" \
    --ca "$ROOT/certs/ca.crt" --count 3

sleep 1
kill "$TD" 2>/dev/null || true
wait "$TD" 2>/dev/null || true
echo "---- analysis of $OUT"
python3 "$ROOT/analysis/pcap_clienthello.py" "$OUT"
