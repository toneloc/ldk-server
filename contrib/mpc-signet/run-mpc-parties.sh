#!/usr/bin/env bash
# Starts four Coinbase cb-mpc parties on this machine as separate processes with separate
# key-share directories. Any three of them must agree to sign. Each takes LDK Server's
# requests on 770N and the other parties on 771N.
#
# On one machine the parties are process boundaries, not trust boundaries: this is for a demo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${MPC_PARTY_BIN:-$ROOT/target/release/ldk-server-mpc-party}"
DATA="${MPC_DATA_DIR:-/tmp/ldk-server-mpc-signet/mpc}"
THRESHOLD="${MPC_THRESHOLD:-3}"
PARTIES=(a b c d)

ROSTER=()
for i in "${!PARTIES[@]}"; do
  p="${PARTIES[$i]}"
  mkdir -p "$DATA/party-$p"
  id="$("$BIN" --keystore "$DATA/party-$p" --share-key-file "$DATA/share-$p.key" --print-identity)"
  ROSTER+=(--party "$p=127.0.0.1:$((7711 + i))=$id")
done

for i in "${!PARTIES[@]}"; do
  p="${PARTIES[$i]}"
  "$BIN" --name "$p" --threshold "$THRESHOLD" --listen "127.0.0.1:$((7701 + i))" \
    --network "${MPC_NETWORK:-signet}" \
    --keystore "$DATA/party-$p" --share-key-file "$DATA/share-$p.key" \
    --auth-key-file "$DATA/client.psk" "${ROSTER[@]}" "$@" \
    > "$DATA/party-$p.log" 2>&1 &
  echo $! > "$DATA/party-$p.pid"
  echo "MPC party $p pid $! clients on 127.0.0.1:$((7701 + i)), shares in $DATA/party-$p"
done

echo "Logs: $DATA/party-{a,b,c,d}.log. LDK Server's auth_key_path is $DATA/client.psk."
echo "Full coverage needs channel kits: once $DATA/party-a/tdh2.pub exists, run"
echo "ldk-server-mpc-ceremony (new-seed, then new-kits) and copy the .kit files to"
echo "$DATA/party-{a,b,c,d}/kits. See ldk-server-mpc/README.md."
