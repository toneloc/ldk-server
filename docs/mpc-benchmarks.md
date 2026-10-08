# cb-mpc 2-of-2 signing benchmarks (ldk-server-mpc)

Measured 2026-10-07 with `ldk-server-mpc-bench` (release build).

- Hardware: Apple M4, 24 GB RAM, macOS 26.2.
- cb-mpc: commit `0b71670` ("fix: harden refresh and backup integration guidance (#137)"),
  Release build, custom static OpenSSL 3.6.4, AppleClang 21.
- Both MPC parties and the client on the same machine, TCP over loopback.
- "full path" = `MpcClient` → P1 service → cb-mpc protocol with P2 service (one fresh TCP
  connection per request, as LDK Server does). "inproc" = both cb-mpc roles on two threads
  with an in-memory transport (pure protocol cost, no service overhead).

## Distributed key generation (ECDSA-2P DKG, secp256k1)

| path      | n  | mean   | p50    | p95    | p99    | min    | max    |
|-----------|----|--------|--------|--------|--------|--------|--------|
| inproc    | 10 | 144 ms | 128 ms | 239 ms | 239 ms | 122 ms | 239 ms |
| full path | 5  | 203 ms | 151 ms | 400 ms | 400 ms | 138 ms | 400 ms |

DKG time varies with the Paillier key generation (prime search) on P1.

## ECDSA signing (one signature over a 32-byte digest)

| path                       | n   | mean    | p50     | p95     | p99     | min     | max     | throughput |
|----------------------------|-----|---------|---------|---------|---------|---------|---------|------------|
| inproc                     | 200 | 38.7 ms | 38.1 ms | 40.5 ms | 51.6 ms | 37.8 ms | 68.0 ms | 25.8 /s    |
| full path, concurrency 1   | 200 | 42.8 ms | 42.6 ms | 43.6 ms | 45.3 ms | 42.2 ms | 60.3 ms | 23.4 /s    |
| full path, concurrency 4   | 400 | 46.5 ms | 46.0 ms | 52.1 ms | 56.6 ms | 43.8 ms | 59.0 ms | 85.5 /s    |

Service/transport overhead over the raw protocol is about 4 ms per signature. Signatures on
different keys run in parallel; signatures on the same key are serialized (per-key lock).

## CPU and memory (party processes, sampled with `top` during signing)

| load                      | P1 CPU      | P2 CPU      | RSS per party |
|---------------------------|-------------|-------------|---------------|
| idle                      | 0 %         | 0 %         | ~3.4 MB       |
| signing, concurrency 1    | 34–52 %     | 31–47 %     | ~3.4 MB       |
| signing, concurrency 4    | 150–209 %   | 142–202 %   | ~3.4 MB       |

(Percent of one core; the M4 has 10 cores.)

## Impact on Lightning operations (regtest e2e, `e2e-tests/tests/mpc.rs`)

From the ldk-server debug log (`MPC signed <op> ... in <t>`), measured inside the
`ExternalFundingSigner` call, i.e. including client connect, request, protocol and
verification:

| operation                              | observed latency        |
|----------------------------------------|-------------------------|
| `CounterpartyCommitment`               | 42–52 ms (typ. ~46 ms)  |
| `HolderCommitment` (force close)       | ~56 ms                  |
| `ClosingTransaction`                   | ~42 ms                  |
| `ChannelAnnouncement`                  | 43–62 ms                |
| `EnsureKey` on first use (DKG)         | ~380 ms (server A log: funding pubkey available 3.0 s after open-channel request incl. channel setup) |

A BOLT11 payment over a direct channel involves two `sign_counterparty_commitment` calls on
the MPC side (add HTLC, settle), so MPC adds roughly 90–100 ms to a payment's critical path
with both parties on the same machine. Non-funding signatures (HTLC, revocation) are
unaffected.

Signet (real network, `contrib/mpc-signet`): `CounterpartyCommitment` for the channel open
with a remote LND peer took 67.6 ms.

## How to reproduce

```bash
cargo build --release -p ldk-server-mpc
target/release/ldk-server-mpc-bench --mode inproc --signs 200 --dkgs 10
# full path: start two parties, then
target/release/ldk-server-mpc-party --role p2 --listen 127.0.0.1:7802 --keystore /tmp/b &
target/release/ldk-server-mpc-party --role p1 --listen 127.0.0.1:7801 --peer 127.0.0.1:7802 --keystore /tmp/a &
target/release/ldk-server-mpc-bench --mode remote --party-a 127.0.0.1:7801 --signs 200 --dkgs 5 --concurrency 1
target/release/ldk-server-mpc-bench --mode remote --party-a 127.0.0.1:7801 --signs 400 --dkgs 4 --concurrency 4
```
