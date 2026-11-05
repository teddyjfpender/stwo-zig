# M7 device scheduling: measured first slice

This slice is proof-neutral. It orders composition ingress, auxiliary columns,
LDE, quotient roles, final interpolation and commitment on native lane 0. The
old lane-1 implementation required host joins between those stages. Per-role
CUDA events are now distinct and resolved after the existing root readback,
so timing collection does not require a per-role host wait. Role scratch is
retired with the existing stream-ordered arena fences; the non-arena free
implementation still joins before reuse. Error cleanup keeps a conservative
completion join. `STWO_RV64_COMPOSITION_ENQUEUE=0` selects the old ordering for
same-binary comparison; `=1` selects the enqueue path.

Each recursion lane also gets its own trace-commit and composition metadata
context. This slice still shares the native owner session across lanes, so it
does **not** establish asynchronous device overlap between two proofs.

## Evidence

Both selectors ran in the production resident prover on both development
blocks, three requests per block. Every native proof, bundle, ordered recursive
proof and tree is byte-identical to the M6 default c1 receipts. Fresh,
cache-disabled M6 CPU receivers accepted both blocks for both selectors. The
receiver configuration and binary hashes are retained in the daemon receipts.

Single loaded-session observations [M], median of two warm requests:

| block | selector | request s | native s | recursion s | root B |
|---|---|---:|---:|---:|---:|
| 26235156 | 0 | 13.370 | 3.213 | 8.015 | 750136 |
| 26235156 | 1 | 13.247 | 3.033 | 8.200 | 750136 |
| 24628607 | 0 | 18.324 | 4.459 | 11.428 | 708696 |
| 24628607 | 1 | 18.967 | 4.606 | 11.822 | 708696 |

The selector-0 daemon load was 14.94 to 17.58 [M], and selector-1 was 24.45 to
18.66 [M]. These runs do not demonstrate a request-time improvement. The native
stage also slowed on the latter run. Reversed-order trace measurements and a
composed integration measurement are required before a latency claim or default
decision. RSS was 34.340/33.904 GiB [M]; both used the automatic arena and had a
sampled whole-device peak of 31.503 GB [M]. These do not meet the M7 memory gates.

The build receipt records the base commit; source-v1.json additionally binds the
two modified source files by SHA-256. The measured binary was built from that
explicit dirty source snapshot. Performance rows state this provenance.

The first two-lane run on k4 failed cleanly with `InvalidRecursionAdmission`
before recursion. The harness supplied 17 pending-authority slots, while the
existing k4 queue requires 21 for four lanes (12 carry slots + 8 lane slots +
1). This is an admission/configuration failure, not a new proof result and not
an OOM result. A correct 21-slot run is still owed.

## Remaining M7 work

This is not the completed device-graph stream. The device transcript, captured
per-class CUDA graph, independent lane native owners, two-proof physical-memory
gate, <=10 blocking calls/node, <=500 launches/node and >=70% recursion-window
kernel-busy gates remain open. The trace-window tool now counts the actual
recursive tree's nodes instead of applying a binary-tree formula to k4 proofs.
