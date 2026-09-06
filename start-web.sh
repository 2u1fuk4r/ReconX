#!/usr/bin/env bash
# Start the ReconX web control panel and keep it running in the background.
#   ./start-web.sh            → http://127.0.0.1:8711  (as current user)
#   sudo ./start-web.sh       → same, with root (SYN nmap scans)
#   PORT=9000 ./start-web.sh  → custom port
cd "$(dirname "$0")"
PORT="${PORT:-8711}"
HOSTBIND="${HOSTBIND:-127.0.0.1}"

pkill -f "reconx_web.py --port ${PORT}" 2>/dev/null && sleep 1

nohup python3 reconx_web.py --host "$HOSTBIND" --port "$PORT" \
      > reconx_web.log 2>&1 &
sleep 2

if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/"; then
  echo "ReconX web panel  →  http://${HOSTBIND}:${PORT}"
  echo "log: $(pwd)/reconx_web.log   ·   stop: pkill -f reconx_web.py"
else
  echo "failed to start — check reconx_web.log"
  tail -20 reconx_web.log
  exit 1
fi
