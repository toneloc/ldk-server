#!/usr/bin/env bash
set -euo pipefail
DATA="${MPC_DATA_DIR:-/tmp/ldk-server-mpc-signet/mpc}"
for p in party-a party-b; do
  if [ -f "$DATA/$p.pid" ]; then
    kill "$(cat "$DATA/$p.pid")" 2>/dev/null || true
    rm -f "$DATA/$p.pid"
    echo "stopped $p"
  fi
done
