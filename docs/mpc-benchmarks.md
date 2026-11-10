# cb-mpc signing benchmarks (ldk-server-mpc)

## Threshold signing, three of four (branch `mpc`, 2026-11-09)

Measured with `ldk-server-mpc-bench --mode inproc` (debug build of the Rust code, Release
build of cb-mpc `0b71670` plus the derivation patch) on a two-core x86-64 Linux container.
All parties run as threads of one process over an in-memory transport, so the three signing
parties share two cores; parties on machines of their own would each have a core, but add
network round trips.

| operation                       | parties       | n  | mean   | p50    | p95    | min    | max    |
|---------------------------------|---------------|----|--------|--------|--------|--------|--------|
| key generation                  | 4 (3 needed)  | 5  | 25 ms  | 24 ms  | 28 ms  | 23 ms  | 28 ms  |
| signature                       | 3 of 4        | 40 | 388 ms | 382 ms | 427 ms | 355 ms | 472 ms |
| key generation                  | 2 (2 needed)  | 5  | 7 ms   | 7 ms   | 9 ms   | 5 ms   | 9 ms   |
| signature                       | 2 of 2        | 40 | 188 ms | 186 ms | 210 ms | 172 ms | 221 ms |

In the regtest end-to-end test, on the same machine with four party processes, LDK Server
logged 380 to 410 ms for one holder-commitment signature.

### Where the time goes (2026-11-10)

`ldk-server-mpc-bench --mode profile` (release build) counts CPU time and traffic per party.

| per signature                    | 2 of 2  | 3 of 4  |
|----------------------------------|---------|---------|
| wall time, this machine          | 180 ms  | 405 ms  |
| CPU time per party               | 105 ms  | 200 ms  |
| messages sent per party          | 7       | 14      |
| bytes sent per party             | 122 KiB | 244 KiB |
| rounds                           | 8       | 8       |

For scale: the old two-party protocol (ECDSA-2P, below) takes 93 ms on this container and
39 ms on the M4, a factor of 2.4 between the machines. Three-of-four signing is therefore
about four times slower than two-party signing was, and should land near 165 ms on the M4.
That last figure is an estimate, not a measurement.

A CPU profile puts about 60% of a party's time in the base oblivious transfers (256 per pair
of parties, redone for every signature) and about 22% in zero-knowledge proofs. Nearly all of
it is constant-time secp256k1 point multiplication. The network is not the bottleneck: eight
rounds at 1 ms between parties is 8 ms.

### What was tuned

| change                                              | before  | after   |
|-----------------------------------------------------|---------|---------|
| request with 3 signatures, four party processes     | 1302 ms | 951 ms  |
| one signature, 2 of 2, `--ot-threads 2`             | 180 ms  | 143 ms  |
| one signature, 3 of 4, `--ot-threads 2` (in-process)| 405 ms  | 353 ms  |

- **Signatures of one request run side by side**, each in its own session (up to eight at a
  time). A commitment with HTLCs used to take one signing round per signature, one after the
  other. Three parties on two cores are CPU-bound here; with a core or more per party the
  request should take about as long as one signature.
- **`--ot-threads N`** on the party (patch `cb-mpc-base-ot-threads.patch`, off by default)
  spreads the base OTs of a signature over N threads. Messages and results are unchanged.
  This container cannot show the full effect: its two cores are already shared by the
  parties, and through four party processes `--ot-threads 2` made no measurable difference.
  On a party with four idle cores the base-OT share of the time should fall to about a
  quarter. Measure it on real hardware before relying on it.
- **A party that did not answer is skipped for 15 seconds**, and connecting to a party times
  out after 3 seconds, so one dead party costs a single slow request rather than every one.
- Key generation now returns only after every party has stored its share (this was a race:
  a signature right after a channel open could reach a party that had not written its share
  yet).

### What was not done

The largest lever left is to stop redoing the base OTs for every signature: run them once per
pair of parties and extend them. That is a change to the signing protocol itself, cb-mpc does
not offer it, and its specification could not be consulted from here. It could remove about
half of the CPU cost, and it needs a cryptographer's review before anyone writes it.

The rest of this page is the earlier two-party (ECDSA-2P) measurement, kept for comparison.

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
`ExternalChannelSigner` call (funding-only build), i.e. including client connect, request, protocol and
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

## Full key coverage (regtest e2e, `coverage = "all"`, measured 2026-10-08)

Latency inside `ExternalChannelSigner::sign` (policy on both parties, parallel sessions to
Party B, signature verification), from the ldk-server log of `e2e-tests/tests/mpc.rs`:

| batch                                             | n | min     | p50     | max     |
|---------------------------------------------------|---|---------|---------|---------|
| `[CounterpartyCommitment]`                        | 7 | 51.2 ms | 53.1 ms | 65.0 ms |
| `[CounterpartyCommitment, CounterpartyCommitmentHtlc]` (1 HTLC) | 6 | 60.0 ms | 64.0 ms | 88.9 ms |
| `[HolderCommitment]` (force close)                | 1 | 69.3 ms | 69.3 ms | 69.3 ms |
| `[ClosingTransaction]`                            | 2 | 46.5 ms | 46.6 ms | 46.6 ms |
| `[ChannelAnnouncement]`                           | 4 | 47.1 ms | 59.1 ms | 74.0 ms |
| five DKGs at channel open (parallel)              | 1 | 431 ms wall |     |         |

HTLC signatures run as parallel sessions, so a commitment with *k* HTLCs costs roughly
one session plus a few ms per extra HTLC rather than *k* sequential sessions.

## Signet (funding-only coverage, 2026-10-08)

Real-network timings from `contrib/mpc-signet` against a third-party LND node (Blink staging)
and a second LDK Server, both parties on the same machine as the node:

- `CounterpartyCommitment`: 40–66 ms; `ClosingTransaction`: 39.6 ms; `HolderCommitment`
  (force close): 44.4 / 73.2 ms.
- A 20,000 sat BOLT11 receive was recorded (`PAYMENT_RECEIVED`) 164 ms after the sender's
  `bolt11-send` command returned, including network round trips to the peer.

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
