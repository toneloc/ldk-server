#!/usr/bin/env bash
# Starts the two Coinbase cb-mpc parties on this machine as separate processes with
# separate key-share directories. Party B (P2) listens for Party A; Party A (P1) listens
# for LDK Server and holds the only client-facing endpoint.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${MPC_PARTY_BIN:-$ROOT/target/release/ldk-server-mpc-party}"
DATA="${MPC_DATA_DIR:-/tmp/ldk-server-mpc-signet/mpc}"
P1_ADDR="${MPC_P1_ADDR:-127.0.0.1:7701}"
P2_ADDR="${MPC_P2_ADDR:-127.0.0.1:7702}"

mkdir -p "$DATA/party-a" "$DATA/party-b"

"$BIN" --role p2 --listen "$P2_ADDR" --keystore "$DATA/party-b" \
  > "$DATA/party-b.log" 2>&1 &
echo $! > "$DATA/party-b.pid"
sleep 0.5
"$BIN" --role p1 --listen "$P1_ADDR" --peer "$P2_ADDR" --keystore "$DATA/party-a" \
  > "$DATA/party-a.log" 2>&1 &
echo $! > "$DATA/party-a.pid"

echo "MPC party B (P2) pid $(cat "$DATA/party-b.pid") listening on $P2_ADDR, shares in $DATA/party-b"
echo "MPC party A (P1) pid $(cat "$DATA/party-a.pid") listening on $P1_ADDR, shares in $DATA/party-a"
echo "Logs: $DATA/party-{a,b}.log"
