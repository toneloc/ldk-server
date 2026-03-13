# Configuration

LDK Server is configured from three sources, merged with a fixed precedence:

1. **TOML file** — base layer
2. **Environment variables** — override TOML
3. **CLI arguments** — override environment variables

All three sources are optional. The server fails to start only if a required
field is missing from *every* layer, or if the final merged config is invalid
(for example, zero or multiple chain sources configured).

## Config file location

The first positional argument to `ldk-server` is the path to the config
file. If omitted, the server looks for `config.toml` in the default data
directory:

- macOS: `~/Library/Application Support/ldk-server/config.toml`
- Windows: `%APPDATA%\ldk-server\config.toml`
- Other (Linux, BSDs, etc.): `~/.ldk-server/config.toml`

If that path does not exist, the server continues without a file and relies
on env vars + CLI args alone.

## Running with each source

```bash
# 1. Config file
cargo run --bin ldk-server ./ldk-server/ldk-server-config.toml

# 2. Environment variables only
export LDK_SERVER_NODE_NETWORK=regtest
export LDK_SERVER_NODE_REST_SERVICE_ADDRESS=127.0.0.1:3002
export LDK_SERVER_BITCOIND_RPC_ADDRESS=127.0.0.1:18443
export LDK_SERVER_BITCOIND_RPC_USER=user
export LDK_SERVER_BITCOIND_RPC_PASSWORD=pass
cargo run --bin ldk-server

# 3. CLI arguments (override both)
cargo run --bin ldk-server -- \
  --node-network regtest \
  --node-rest-service-address 127.0.0.1:3002 \
  --bitcoind-rpc-address 127.0.0.1:18443 \
  --bitcoind-rpc-user user \
  --bitcoind-rpc-password pass
```

## TOML reference

A working template lives at
[`ldk-server/ldk-server-config.toml`](../ldk-server/ldk-server-config.toml).

### `[node]`

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `network` | `"bitcoin"` / `"testnet"` / `"testnet4"` / `"signet"` / `"regtest"` | yes | Bitcoin network the node operates on. |
| `rest_service_address` | `"ip:port"` | yes | Address the REST API binds to. Parsed as `std::net::SocketAddr` — hostnames are not accepted. |
| `listening_addresses` | `["host:port", ...]` | no | Lightning P2P listen addresses. |
| `announcement_addresses` | `["host:port", ...]` | no | Addresses advertised in channel/node announcements. Only needed if you announce publicly. |
| `alias` | string (≤ 32 bytes) | no | Node alias used in announcements. Longer values fail with `node.alias must be at most 32 bytes long.` |

### `[storage.disk]`

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `dir_path` | string | no | Directory used by LDK and BDK for persistence. Also the base path for generated auth/TLS material (`<storage_dir>/<network>/api_key`, `<storage_dir>/tls.crt`). |

### `[log]`

| Key | Type | Required | Default | Description |
| --- | ---- | -------- | ------- | ----------- |
| `level` | `"Off"` / `"Error"` / `"Warn"` / `"Info"` / `"Debug"` / `"Trace"` | no | `Debug` | Maximum log level. Parsed via `log::LevelFilter::from_str`. |
| `file` | string | no | `<storage_dir>/<network>/ldk-server.log` | Log file path. If omitted, the server writes logs to this default path. |

### `[tls]`

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `cert_path` | string | no | Path to a PEM certificate. If omitted, a self-signed cert is generated at `<storage_dir>/tls.crt`. |
| `key_path` | string | no | Path to the matching private key. |
| `hosts` | `[string, ...]` | no | SANs baked into the auto-generated self-signed cert. |

### Chain source (exactly one required)

The server fails to start with
`Must set a single chain source, multiple were configured` if zero or more
than one of these blocks are present (across all layers combined).

#### `[bitcoind]`

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `rpc_address` | `"host:port"` | yes (if block present) | bitcoind RPC endpoint. |
| `rpc_user` | string | yes | RPC username. |
| `rpc_password` | string | yes | RPC password. |

#### `[electrum]`

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `server_url` | string | yes | Electrum server URL (e.g. `ssl://electrum.blockstream.info:50002`). |

#### `[esplora]`

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `server_url` | string | yes | Esplora HTTP base URL (e.g. `https://mempool.space/api`). |

### `[rabbitmq]` — (optional)

Required when the server is built with the `events-rabbitmq` feature;
ignored otherwise. Both fields must be present **and non-empty**, or
startup fails with:

> Both `rabbitmq.connection_string` and `rabbitmq.exchange_name` must be
> configured if enabling `events-rabbitmq` feature.

| Key | Type | Description |
| --- | ---- | ----------- |
| `connection_string` | string | AMQP connection URI. |
| `exchange_name` | string | Exchange events are published to. |

### `[liquidity.lsps2_service]` — (optional)

Required when built with `experimental-lsps2-support`; ignored otherwise.
Missing block fails with:

> `liquidity.lsps2_service` must be defined in config if enabling
> `experimental-lsps2-support` feature.

| Key | Type | Description |
| --- | ---- | ----------- |
| `advertise_service` | bool | Whether to advertise the LSP service. |
| `channel_opening_fee_ppm` | u32 | Per-million fee charged for opening a channel. |
| `channel_over_provisioning_ppm` | u32 | Extra capacity provisioned, per-million. |
| `min_channel_opening_fee_msat` | u64 | Minimum absolute opening fee (msat). |
| `min_channel_lifetime` | u32 | Minimum channel lifetime in blocks. |
| `max_client_to_self_delay` | u32 | Maximum `to_self_delay` accepted from the client. |
| `min_payment_size_msat` | u64 | Minimum JIT-channel payment size. |
| `max_payment_size_msat` | u64 | Maximum JIT-channel payment size. |
| `client_trusts_lsp` | bool | Whether the client must trust the LSP. |
| `require_token` | string | Optional token required to use the service. |

## Environment variables & CLI arguments

Every env var has a matching CLI flag, and vice versa. These nine fields are
the only ones overridable outside the TOML file; optional blocks
(`[rabbitmq]`, `[liquidity.lsps2_service]`) and TLS/log settings are
TOML-only.

| CLI flag | Environment variable | TOML equivalent |
| -------- | -------------------- | --------------- |
| `--node-network` | `LDK_SERVER_NODE_NETWORK` | `node.network` |
| `--node-listening-addresses` | `LDK_SERVER_NODE_LISTENING_ADDRESSES` | `node.listening_addresses` |
| `--node-announcement-addresses` | `LDK_SERVER_NODE_ANNOUNCEMENT_ADDRESSES` | `node.announcement_addresses` |
| `--node-rest-service-address` | `LDK_SERVER_NODE_REST_SERVICE_ADDRESS` | `node.rest_service_address` |
| `--node-alias` | `LDK_SERVER_NODE_ALIAS` | `node.alias` |
| `--bitcoind-rpc-address` | `LDK_SERVER_BITCOIND_RPC_ADDRESS` | `bitcoind.rpc_address` |
| `--bitcoind-rpc-user` | `LDK_SERVER_BITCOIND_RPC_USER` | `bitcoind.rpc_user` |
| `--bitcoind-rpc-password` | `LDK_SERVER_BITCOIND_RPC_PASSWORD` | `bitcoind.rpc_password` |
| `--storage-dir-path` | `LDK_SERVER_STORAGE_DIR_PATH` | `storage.disk.dir_path` |

### Precedence in practice

Given the same field set in two layers, the higher-priority layer wins
outright — values are replaced, not merged. For example, a
`listening_addresses = ["127.0.0.1:3001"]` in TOML is fully replaced (not
appended to) by `--node-listening-addresses 0.0.0.0:9735`.

One consequence: setting `--bitcoind-rpc-address` on the CLI does **not**
implicitly switch the chain source. If your TOML has `[esplora]`, the CLI
`bitcoind` arg adds a second chain source and startup fails with the
"multiple were configured" error. Remove the `[esplora]` block from TOML,
or pick a single source across all layers.

## Feature flags that change required config

Features are enabled at build time (`cargo build --features ...`) and change
which TOML blocks become mandatory:

| Feature | Effect |
| ------- | ------ |
| `events-rabbitmq` | `[rabbitmq]` becomes required with non-empty fields. |
| `experimental-lsps2-support` | `[liquidity.lsps2_service]` becomes required. |

Without these features, the corresponding blocks are silently ignored if
present.

## Minimal examples

### Regtest with local bitcoind

```toml
[node]
network = "regtest"
rest_service_address = "127.0.0.1:3002"

[storage.disk]
dir_path = "/tmp/ldk-server"

[bitcoind]
rpc_address = "127.0.0.1:18443"
rpc_user = "user"
rpc_password = "pass"
```

## See also

- [`ldk-server/ldk-server-config.toml`](../ldk-server/ldk-server-config.toml) — annotated template
- [`ldk-server/src/util/config.rs`](../ldk-server/src/util/config.rs) — source of truth for parsing, merging, and validation
