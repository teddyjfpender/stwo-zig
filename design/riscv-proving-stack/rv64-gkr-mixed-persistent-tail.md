# Mixed-oracle persistent GKR tail

This optional path fuses the last four or fewer rounds of one mixed-height
sumcheck into a single 256-thread CTA. It keeps the existing shared batch
transcript, weights, sleeping-oracle corrections, round records and terminal
masks. It does not use the independent-transcript single-oracle tail API.

`batch_transition.cuh` is the common round-transition authority for the existing
one-round kernel and the new persistent kernel. Each warp sums and folds one
oracle at a time; the CTA joins before and after the shared challenge draw.
The first fold writes an exclusively owned bank. Subsequent folds reuse that
bank in place: output row i reads only input rows i and i+half, so its stores
cannot overwrite another output row's inputs. Original input fractions remain
read-only. The final masks are written directly from the terminal fractions.

The host admits every original input, both fold banks and the shared workspace
before any mutation. The native entry point independently checks its complete
ranges, rejects overlapping writable/read-only spans, bounds the oracle count
to 64 and remaining rounds to 4, and requires the same original oracle heights
as the shared state. The kernel's shared state is bounded; it
allocates no device memory and transfers no round polynomial or challenge to
the host.

The runtime symbol is optional. Old images use the existing route. New images
also retain that route by default: `STWO_RV64_GKR_BATCH_TAIL` must be explicitly
present, and batched oracles and the new native symbol must both be available.
The producer logs the selected flag. No protocol or security-profile change
is introduced.

Qualification uses the existing connected native GKR traversal fixtures, with
an opt-in harness mode. It compares all native round records, transcript
checkpoints, terminal masks and closure artifacts, including the existing
poison cases. The harness also tries invalid heights and record/state aliases
before the valid enqueue. Host tests cover immediate and delayed mixed-height
tails, sleeping constant oracles, preflight and failure poisoning. Full-block
proof parity and controlled timings are still required before adoption or any
performance claim.
