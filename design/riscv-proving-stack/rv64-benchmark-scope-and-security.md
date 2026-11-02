# RV64 benchmark scope and security labels

Recorded2026-11-02. These distinctions apply to the retained block24628607 and
the explicitly experimental OM31 services/GKR lane in PR309.

## Execution scope

The earlier approximately8.6-second figure covered one CPU batch of roughly
4,194,303 instructions. A complete retained block executes104,253,913 instructions
and produces25 CPU proofs plus service truth proofs. Current complete-block
proving is approximately227seconds under the K18 benchmark-control policy; the
complete producer process takes245.92seconds including capture, setup and output.
These are different workload scopes, rather than an8.6-to227-second regression
on the same batch. Multiplying8.57 by25 gives214.25seconds as a rough scale
illustration only; service work and per-proof/concurrent worker settings differ.

K18/K17/K16 label the maximum Keccak truth-component log height, not the CPU
instruction count or security. CPU batches remain at most4,194,303 retirements
with log22 CPU traces. Independently sizing Keccak changes the truth roster:
K18 has5 total truth proofs, K17 has7, and K16 has11. Those include Keccak plus
three secp truths. None of the complete-block times below includes recursion.
Fresh independent reception is a separate process, outside proving time.

## Security scope

| Complete-block observation | Proving | Parameter profile | Whole-protocol128 qualified? |
| --- | ---: | --- | --- |
| K18/source80/deferred |227.20s|Benchmark q70/P26/fold4, nominal96-bit PCS|No|
| K17/source80/deferred |225.72s|Same benchmark control|No|
| K16/checkpoint68/deferred |238.91s|Same benchmark control|No|
| K18/source80/deferred candidate |305.85s|Engineering beta2/q256/P0/fold4|No|

OM31 widens algebraic challenges relative to QM31. It does not by itself qualify
the composed STARK/FRI/lookup/GKR/transcript protocol at128bits. The engineering
candidate strengthens parameters but is not an independently reviewed128-bit
certificate. Its software acceptance and proof-byte parity do not supply that
certificate. Receiver security promotion deliberately remains fail-closed.

A matched-field CPU0 control previously measured classic LogUp7.95seconds versus
GKR8.46seconds for source plus proving. The expected net GKR-over-LogUp CPU speedup
is not established. Storage/geometry improvements and a bad scalar-to-packed
implementation speedup must not be reported as that missing algorithm comparison.
Historical QM31 timings also change field width and cannot isolate GKR cost.

The current OM/GKR profile has no qualified accepting recursive root. Earlier
QM31 wrap/fold results are a different lane. Consequently neither these timing
rows nor the provisional candidate establish a like-for-like comparison against
a competitor's qualified128-bit end-to-end proof. GPU execution qualification
remains deferred by request.

Authoritative receipts are under
`vectors/reports/rv64-deferred-local-binding-20261102/`, with full reports,
resources, frozen binary hashes, process usage and fresh receiver outputs.
`rv64-deferred-local-binding.md` explains the memory/time/proof-volume tradeoffs.
`rv64-whole-protocol-security-policy.md` records the independent security gate.
