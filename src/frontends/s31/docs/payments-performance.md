# Blinded payment proving performance

The payment prover preserves the full eleven-component circuit protocol,
80 fresh-random blinding rounds, 70 queries, blowup 1, interaction PoW 20,
FRI PoW 26 and fold step 1. The source, canonical relation, verification key
and fixed commitment are identical before and after the execution changes.

The prover now reuses the checked topology's existing commitment and parsed
AIR for native self-verification. It does not accept an expected root from the
proof. The BLAKE2s/M31 nonce search uses the existing prepared 40-byte kernel
and computes only the first digest word needed by its PoW predicate. M31
reduction, canonical minimum-nonce order, scalar selection and worker-failure
completion remain unchanged. The full-hash verifier remains independent.

Evaluations-only storage was measured and discarded: reducing coefficient
storage increased out-of-domain sampling time on this workload. The retained
path keeps the existing coefficient storage policy. No witness cache or
deterministic blinding seed was added.

## Recorded results

The [bound measurement](../../../../design/s31/measurements/payments/tongo-proving-audit-v1-2026-10-09.json)
compares baseline `aaecd597374b0cbffe060182c86cedd5a600df8a` with the optimized
runtime on an AMD EPYC 9V74 host, with an eight-core container quota and eight
workers. Zig 0.15.2 builds both lanes in ReleaseFast. All 44 quiet timing samples
per lane (12 initial plus 32 additional), four warmups per lane and their proof
hashes are recorded; every proof passes both separately compiled native
verifiers. Compilation and the two extra profiled proofs are excluded.

| Metric | Baseline | Optimized |
| --- | ---: | ---: |
| CLI latency, median | 2.078 s | 1.950 s |
| CLI latency, observed range | 1.820–3.570 s | 1.752–2.292 s |
| Post-proving interval, median | 160 ms | 21 ms |
| Separate native verification, median | 170 ms | 174 ms |
| Prover peak RSS, median | 1,041,840 KiB | 1,042,274 KiB |
| Proof bytes, median | 468,801 | 468,952 |

The observed median latency reduction is **6.2%**. The distributions overlap:
the initial 12-pair run showed only 1.1%, and the next 32 pairs showed 5.8%.
This is a local execution improvement, not a latency guarantee or a comparison
with deployed Tongo. The post-proving interval is derived from the native
timers and includes serialization, self-verification, cleanup and output. Its
reduction isolates the benefit of avoiding a second fixed-table commitment;
it is not verifier-only timing. Memory remains approximately 1 GiB.

A separate fixed-transcript canonical nonce diagnostic, using a pinned Rust
known-answer nonce, measured 108.1 ms versus 96.9 ms median over ten samples
per lane (10.4% faster). Its source, binary hashes and samples are in the same
measurement file. This kernel result is not the payment latency improvement.
The earlier run made under competing build load and the discarded storage
experiment are explicitly excluded from the headline comparison.

## Reproduce a matched comparison

Build both revisions with Zig 0.15.2 on PATH. Use an unused worktree/package
destination; the builders and benchmark refuse to overwrite existing evidence.
The witness below is deliberately public synthetic test data.

```sh
git worktree add --detach /tmp/stwo-zig-payment-before aaecd597374b0cbffe060182c86cedd5a600df8a
python3 /tmp/stwo-zig-payment-before/src/frontends/s31/python/s31.py build \
  /tmp/stwo-zig-payment-before/src/frontends/s31/examples/payments/tongo_transfer.s31 \
  --out /tmp/s31-payment-before --lowering gate
python3 src/frontends/s31/python/s31.py build \
  src/frontends/s31/examples/payments/tongo_transfer.s31 \
  --out zig-out/s31/payment-performance/candidate --lowering gate
python3 src/frontends/s31/tests/acceptance/benchmark_tongo.py \
  --baseline /tmp/s31-payment-before \
  --candidate zig-out/s31/payment-performance/candidate \
  --output zig-out/s31/payment-performance/comparison.json \
  --warmups 2 --samples 12 --workers 8 --profile
```

Choose workers for the host; eight is the recorded container's CPU quota.
Finish builds and other tests before timing. Each lane uses fresh CLI processes
and includes witness/topology construction, random blinding, setup, proving,
serialization, native self-verification and file output. Compilation is
excluded. Warmups warm executable/filesystem pages; these are **cold setup per
request**, not resident-session or sustained-service measurements.

The driver requires identical keys and sources, alternates lane order, verifies
every proof using both installed native verifiers, checks the fixed commitment
and fresh trace commitments, and records medians/ranges, peak RSS, binary and
compiler fingerprints, CPU/quota and proof receipts. Proof-of-work is stochastic
because every proof uses fresh entropy; report the distribution, not a best run.

## Stage interpretation and limits

`STWO_CIRCUIT_STAGE_PROFILE=1` enables existing `CIRCUIT_STAGE` timings and
new bounded `S31_PHASE` intervals. An interval covers time since the previous
transcript callback: `mix_circuit_hash` includes base-witness generation,
`commit_base_trace` includes its commitment, `mix_interaction_claim` includes
interaction-witness generation, and `prove_ex` contains the composition/OODS/FRI
stage tree. Do not add those nested stage times to the encompassing interval.
Normal proving does not sample these clocks or print private values/digests.
Extra profiled proofs are verified but excluded from the headline distribution.

The full profile's 5,295,488 fixed preprocessed cells remain a structural cost.
Further large gains require a prepared proving service and/or a separately
designed hash-focused AIR with its own soundness and privacy review. Existing
sparse-profile numbers are not a matched confidential-payment comparison.

The [audit contract](../../../../design/s31/language/PROVING_AUDIT.md) records
security boundaries and validation. Native verification and pinned nonce/proof
fixtures do not establish general zero knowledge. Complete new-package pinned
Rust acceptance and a reviewed privacy argument remain release gates.
