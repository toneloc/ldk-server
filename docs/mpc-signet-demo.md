# Signet demonstration: MPC-backed LDK Server channels

Run on 2026-10-08 (UTC) with the `coverage = "funding"` build (the full-coverage build was
verified on regtest afterwards; see `e2e-tests/tests/mpc.rs`). Both MPC parties and LDK
Server ran on one machine; the counterparties were a third-party LND node and a second,
plain LDK Server.

| Item | Value |
|---|---|
| MPC node id | `030453875a7881fa49ee7e0f4eabdab01a5c5eab7cfa7893d3e514e664d845ff98` |
| Chain source | Esplora (blockstream.info, then mempool.space after rate limiting) |
| Funding | alt signet faucet, 95,912 sat, tx `51a36e1aff58dfa11b6a2d6168b46a9b7a1047b235638a9f1a05cb0cff825d12` |
| Peer 1 | Blink staging LND `024e679c1a77143029b806f396f935fa6cd0744970f412667adfc75edbbab54d7a@34.138.165.14:9735` |
| Peer 2 | second LDK Server (no MPC) `03348044546fb58290326615b96325bfc4f8430105e5de56823fc5169fd84c65c3` |

## Sequence

1. Started Party B, then Party A, then LDK Server (`contrib/mpc-signet`).
2. Channel 1, outbound 50,000 sat to Blink, announced. First-use DKG produced funding key
   `0244b03d3ee3173800438f04da301a01f159a1436566731085668a23029f8b88b4`; the opening
   commitment was MPC-signed in 67.6 ms. Funding tx
   `8a4cb61f6a721ddf939858f895cca880a650c0b4152fde9ad458430e430f1cc0`, confirmed in block
   325441. (A first attempt against a Zap node was rejected for being under its 0.01 BTC
   minimum; that DKG'd key was never used.)
3. Channel 2, inbound 100,000 sat from the second LDK Server. The MPC node acted as
   acceptor: DKG produced `03b03ae5f2e4449319713ca63a97b09fb120ae7fb7bccfdb23c30e86a84db4521a`,
   commitment signed in 41.4 ms. Funding tx
   `bc1d0ff795906253f055b8333b381054f18f545cd01bf5c998ab0334b2b3bff1`.
4. Send: 1,000 sat keysend to Blink, succeeded (two MPC-signed commitment updates, 41 and
   58 ms).
5. Receive: 20,000 sat BOLT11 from the second server, `PAYMENT_RECEIVED` 164 ms after the
   send command. Send: 7,000 sat BOLT11 to the second server, succeeded. Commitment
   signatures 40 to 66 ms.
6. Restarted both MPC parties (3 shares reloaded each) and LDK Server (both channel signers
   re-derived through `EnsureKey`); a further 3,000 sat receive succeeded.
7. Cooperative close of channel 2, initiated by the MPC node: closing tx
   `b2fc2d867ca2cb2e4e31661922aa24a7a2f078af87ef94691c5a7ded34ecaea2`, MPC
   `ClosingTransaction` signature in 39.6 ms. Its 2-of-2 witness script contains the DKG'd
   key `03b03ae5…`.
8. Unilateral close of channel 1 (holder force-close): commitment tx
   `bbc875ad6725ef77891e56555edb960ce3ebb21fc3688e5a9451485e6a449341`, MPC
   `HolderCommitment` signatures in 44.4 and 73.2 ms. Its witness script contains the DKG'd
   key `0244b03d…`.
9. Both closing transactions confirmed at 05:04 UTC; the node reported no pending
   closure balances and the channel funds back in the on-chain wallet / awaiting the
   force-close delay.

## Not demonstrated on signet

- The full-coverage mode (`coverage = "all"`) and Party B's policy: verified on regtest
  only (two LDK Servers, five DKGs per channel, payments, restarts, cooperative and force
  close, PSK links, encrypted shares, payout allow-list).
- Splicing.
- Party B on a separate machine.
