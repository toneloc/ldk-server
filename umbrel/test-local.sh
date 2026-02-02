#!/bin/bash
set -e

cd "$(dirname "$0")"

# Build WASM GUI if dist doesn't exist or is outdated
if [ ! -d "../ldk-server-gui/dist" ] || [ "../ldk-server-gui/src" -nt "../ldk-server-gui/dist" ]; then
    echo "Building WASM GUI..."
    cd ../ldk-server-gui
    trunk build --release
    cd ../umbrel
fi

export APP_DATA_DIR="$(pwd)/data"
export APP_LDK_SERVER_IP=172.20.0.2
export APP_LDK_WEB_IP=172.20.0.3

echo "Starting LDK Server..."
echo "GUI will be available at http://localhost:8080"
echo ""

docker compose up --build "$@"
