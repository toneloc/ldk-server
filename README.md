# LDK Server + Stable Channels

**LDK Server** is a fully-functional Lightning node in daemon form, built on top of
[LDK Node](https://github.com/lightningdevkit/ldk-node). This fork integrates
[Stable Channels](https://github.com/toneloc/stable-channels) — dollar-denominated
Lightning channels that automatically rebalance to maintain a target USD value.

The server exposes a Protobuf API over HTTPS with HMAC authentication, including
all upstream LDK Server endpoints plus three Stable Channels endpoints.

### Features

- All upstream LDK Server APIs (25+ endpoints): on-chain, BOLT11, BOLT12, splicing, channel management, etc.
- Stable Channels: automatic stability payments that keep channel balances pegged to a USD amount
- HMAC authentication and auto-generated TLS
- Background BTC price fetching (Kraken, Bitstamp, Coinbase)
- LSPS2 liquidity provider support (optional)
- CLI, client library, and GUI

## Deployment

### 1. Clone and build

```bash
git clone https://github.com/toneloc/ldk-server.git
cd ldk-server
git checkout server-redo
cargo build --release
```

The `stable-channels` crate is expected at `../../Drive/2026/stable-channels` relative to the
`ldk-server/` directory. Adjust the path in `ldk-server/Cargo.toml` if your layout differs.

### 2. Create a config file

The default config path on each platform:

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/ldk-server/config.toml` |
| Linux | `~/.ldk-server/config.toml` |
| Windows | `%APPDATA%\ldk-server\config.toml` |

Copy the reference config and edit it:

```bash
# macOS example
mkdir -p ~/Library/Application\ Support/ldk-server/
cp ldk-server/ldk-server-config.toml ~/Library/Application\ Support/ldk-server/config.toml
```

Key settings:

| Field | Description | Example |
|---|---|---|
| `network` | Bitcoin network | `"regtest"`, `"signet"`, or `"bitcoin"` |
| `rest_service_address` | HTTPS API bind address | `"127.0.0.1:3002"` |
| `listening_addresses` | Lightning P2P port | `["0.0.0.0:9735"]` |
| `dir_path` | LDK data storage directory | `"/tmp/ldk-server/"` |
| `[esplora]` or `[bitcoind]` | Chain source (pick one) | see config file |
| `[tls] hosts` | TLS hostnames (auto-generates certs if paths omitted) | `["localhost"]` |

### 3. Run

```bash
# Uses default config path:
./target/release/ldk-server

# Or specify a config path:
./target/release/ldk-server /path/to/config.toml
```

On first start the server will:
- Generate an API key at `<data_dir>/<network>/api_key`
- Generate self-signed TLS certificates (if none configured)
- Start the LDK Lightning node and begin chain sync
- Start background BTC price fetching (every 30s)
- Start the stability check timer
- Listen for HTTPS connections on `rest_service_address`

### 4. Get your API key

The API key is stored as 32 raw bytes. To display it as hex:

```bash
xxd -p ~/Library/Application\ Support/ldk-server/regtest/api_key | tr -d '\n'
```

### 5. Interact via CLI

```bash
cargo run --release --bin ldk-server-cli -- \
  -b localhost:3002 \
  --api-key <hex-api-key> \
  --tls-cert <data_dir>/tls_cert.pem \
  help
```

Common commands:
```bash
ldk-server-cli ... onchain-receive    # Generate a funding address
ldk-server-cli ... get-balances       # Show on-chain + Lightning balances
ldk-server-cli ... list-channels      # List all channels
ldk-server-cli ... get-node-info      # Node ID, sync status, etc.
```

### 6. Stable Channels API

Three additional endpoints beyond the upstream LDK Server API:

| Endpoint | Description |
|---|---|
| `GetPrice` | Returns the current cached BTC/USD price |
| `ListStableChannels` | Lists all stable channels with expected USD, backing sats, price |
| `EditStableChannel` | Updates the target USD amount or note for a stable channel |

These use the same HMAC-authenticated Protobuf format as all other endpoints.

### 7. LSPS2 (optional)

To run as a liquidity provider with JIT channel opening:

```bash
cargo build --release --features experimental-lsps2-support
```

And configure `[liquidity.lsps2_service]` in your config.toml.

### 8. Migrating from the old LSP backend

If you were running `lsp_backend` from the stable-channels repo, point `dir_path` at your
existing LDK data directory. The `StableChannelManager` reads `stablechannels.json` and
`stablechannels.db` from the network subdirectory, same as before.

## Architecture

```
ldk-server/
├── ldk-server/              # Main daemon
│   ├── src/main.rs          # Event loop with stability timer
│   ├── src/service.rs       # HTTP route dispatch (28 endpoints)
│   ├── src/stable_manager.rs# Stable channel lifecycle + trade messages
│   └── src/api/             # Request handlers
├── ldk-server-protos/       # Protobuf definitions (including stable.proto)
├── ldk-server-client/       # Rust HTTP client library
├── ldk-server-cli/          # Command-line interface
└── ldk-server-gui/          # egui desktop frontend
```

### Shell Completions

```bash
# Bash (add to ~/.bashrc)
eval "$(ldk-server-cli completions bash)"

# Zsh (add to ~/.zshrc)
eval "$(ldk-server-cli completions zsh)"

# Fish (add to ~/.config/fish/config.fish)
ldk-server-cli completions fish | source
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on building, testing, code style, and development workflow.
