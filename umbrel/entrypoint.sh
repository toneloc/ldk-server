#!/bin/bash
set -e

CONFIG_FILE="/data/config.toml"

# Generate config if it doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
    mkdir -p /data

    cat > "$CONFIG_FILE" << 'EOFCONFIG'
[node]
EOFCONFIG

    echo "network = \"${LDK_NETWORK:-signet}\"" >> "$CONFIG_FILE"
    echo "alias = \"${LDK_ALIAS:-umbrel-ldk}\"" >> "$CONFIG_FILE"
    echo "listening_addresses = [\"${LDK_LISTENING_ADDRESS:-0.0.0.0:3001}\"]" >> "$CONFIG_FILE"

    # Only add announcement_addresses if set
    if [ -n "${LDK_ANNOUNCEMENT_ADDRESS:-}" ]; then
        echo "announcement_addresses = [\"${LDK_ANNOUNCEMENT_ADDRESS}\"]" >> "$CONFIG_FILE"
    fi

    echo "rest_service_address = \"${LDK_REST_ADDRESS:-0.0.0.0:3002}\"" >> "$CONFIG_FILE"

    cat >> "$CONFIG_FILE" << 'EOFCONFIG'

[storage.disk]
dir_path = "/data/ldk"

[log]
level = "Info"
file_path = "/data/ldk-server.log"

[tls]
hosts = ["localhost", "server", "ldk-server"]

EOFCONFIG

    echo "[esplora]" >> "$CONFIG_FILE"
    echo "server_url = \"${LDK_ESPLORA_URL:-https://mutinynet.com/api}\"" >> "$CONFIG_FILE"

    echo "Generated config at $CONFIG_FILE"
    cat "$CONFIG_FILE"
fi

exec /usr/local/bin/ldk-server "$CONFIG_FILE"
