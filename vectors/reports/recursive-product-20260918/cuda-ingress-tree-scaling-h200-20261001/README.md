# H200 CUDA ingress and recursive-tree scaling, 1 October 2026

This is one isolated RunPod H200 SXM session (143,771 MiB device memory),
ReleaseFast, production circuit registry, and canonical 70-query/26-bit-PoW
Cairo and circuit security. The end-to-end request here starts with **already
adapted** contiguous mainnet PIE inputs `15627902-15627904` (1,224,007 steps)
and `15627905-15627907` (785,807 steps) and ends at one verified recursive
root. PIE execution, Rust adaptation, queueing, and compilation are outside
the timed request. Leaf proofs, leaf inputs, and canonical root proof/output
bytes are checked against the pinned Rust-qualified
[reference receipt](../cuda-resident-pipeline-h100-20261001/receipt.json).

| Adapted transport and root | Trial A | Trial B | Cairo | Wraps | Fold | Process overhead |
|---|---:|---:|---:|---:|---:|---:|
| JSON, canonical root | 13.348 s | 13.458 s | 6.81–6.87 s | 3.16–3.23 s | 2.19–2.20 s | 0.94–1.03 s |
| Rust-produced STWZCPI, canonical root | **12.464 s** | **12.507 s** | 5.71–5.75 s | 3.24–3.26 s | 2.24–2.25 s | 1.07–1.13 s |
| Final compact capture with post-parse source check | 13.132 s | **12.659 s** | 5.91–6.00 s | 3.26–3.29 s | 2.28–2.30 s | 1.08–1.31 s |

Both transports produce the **same proof bytes** for each leaf and the root.
The table's Cairo phase includes input ingress, static assets, proof execution,
and publication; the two resident Cairo proof executions themselves take only
about 0.8 s combined.
The compact transport changes only the adapted-input file digest, so that
digest is not compared to the JSON reference; the normalized input and every
proof digest are compared. The one-time JSON-to-compact conversion of old
artifacts is outside these trials; the Rust adapter can emit compact bytes
directly for new inputs. Direct use of immutable adapted inputs also removes a
large per-request copy from the benchmark driver. A separate compact-terminal
root trial took 12.541 s with JSON inputs but changed root proof bytes, so it
is **not** included in the canonical comparison.
The final compact capture verifies that the source path still hashes to the
same bytes after parsing. Both final trials retain byte-identical leaf and
root proofs against the Rust-qualified reference; the table keeps earlier
trials visible so the cost of that last source check is not hidden.

The first fixed-coefficient load takes about 2.45 s; the second leaf restores
the verified GPU image. Its profiled 2.1 GB load comprises 1.846 s in the
read/SHA-256 pass, 0.180 s validation, 0.282 s SIMD-coefficient transposition,
and 0.127 s upload. A plain read of the same local file takes 0.27 s and
`sha256sum` 1.64 s, so the authentication hash dominates the cold load. An
experimental switch to Zig's BLAKE3 implementation preserved all proof bytes
but regressed the pass to ~3.02 s and the pipeline to 13.675–14.101 s. That
switch was rejected; the retained code keeps SHA-256 for this artifact.

The canonical two-leaf fold divides into ~0.97 s one-time setup and topology
construction, ~1.24 s for its reduction, and ~0.002 s output rendering. The
resident GPU proof is ~0.50 s of that reduction. The remaining per-node cost
is dominated by rebuilding the multiverifier witness and circuit values.

## Tree scaling

The scaling harness takes the two **verified** leaf artifacts from the
`compact-input-b` pipeline receipt: the circuit leaves for
`15627902-15627904` and `15627905-15627907`. For a 1,024-leaf run it places
512 copies of each artifact in alternating order; it does not fetch or prove
1,024 distinct PIEs. It exercises actual canonical multiverifier proofs and
root publication, but the repeated sequence is **not a contiguous Starknet
chain**. It isolates the recursion-tree cost and must not be reported as
end-to-end block proving.
Repeated inputs may also benefit CPU page-cache locality; distinct PIE proofs
still need a real-chain qualification.
All tree runs use one H200 process per size and a serial CUDA reduction source.

| Leaves | Reductions | Wall | Reduction stage | Peak GPU | Peak host RSS |
|---:|---:|---:|---:|---:|---:|
| 16 | 15 | 22.109 s | 20.251 s | 28.772 GB | 2.348 GB |
| 64 | 63 | 83.862 s | 81.914 s | 28.772 GB | 2.475 GB |
| 256 | 255 | 332.393 s | 329.196 s | 29.323 GB | 2.978 GB |
| 1,024 | 1,023 | 1,341.938 s | 1,334.811 s | 29.323 GB | 5.005 GB |

At 1,024 leaves, per-node logging attributes 727.1 s to multiverifier
construction and 572.6 s to proving across all ten levels. The first two
levels account for 1,013.6 s of the reduction time. GPU memory remains near
one reduction's arena; host memory rises with the retained leaf proofs.
The harness is [benchmark_circuit_cuda_fold_scaling.py](../../../../scripts/benchmark_circuit_cuda_fold_scaling.py).

The current CUDA tree driver uses one reduction source and deliberately runs
sibling reductions serially. A fresh 1,024-leaf root requires 1,023 proofs
across ten levels; memory is bounded, but work is nearly linear in leaf count.
For a continuing chain, an append-only frontier of **internal** circuit proofs
could retain completed subtrees and reprove only the new carries plus a terminal
root checkpoint. The terminal `.root` proof cannot itself be used as a child.
Independent siblings can then be scheduled across bounded GPU workers without
changing the canonical tree order or public outputs. This is an architecture
proposal, not a qualified performance result. It requires proof-byte and
packed-output parity at each checkpoint.

The original 32.308 s H100 receipt is a different GPU/session: 9.494 s Cairo,
12.579 s wrapping, 9.021 s folding, and 1.214 s overhead. The best final-code
H200 result here is 2.55× faster than that baseline, **not** the 10× target.
The initial same-host JSON-to-compact improvement was ~0.9 s; the final source
check retains most of it. A production-scale tree
requires a compiled/reusable multiverifier witness program and bounded
parallel reductions; faster CUDA proving alone cannot eliminate the ~0.71 s
per-node witness construction cost measured here.

The machine-readable [same-host matrix](same-host.json),
[tree-scaling receipt](tree-scaling.json), and individual
[pipeline receipts](receipts/) retain stage times, memory, proof digests, and
reference-parity results.

## Larger PIE admission

The requested `15553620_15553629` is reported as ~180M steps; its ZIP and
authoritative metadata require a bearer key. The
[Lord of the Pies API](https://15-237-92-219.sslip.io/v1/docs) describes a
new ~30M-step range budget and allows individual heavy blocks to exceed it.
The [existing H200 SN PIE suite](../../../../src/integrations/cairo_cuda/README.md)
provides the first, smaller scale points (individual adapted input to Cairo
proof publication; these exclude recursion):

| PIE | Cairo steps | Publication time | Peak GPU memory |
|---|---:|---:|---:|
| SN PIE 2 | 7.707M | 4.706 s | 61.318 GB |
| SN PIE 4 | 14.058M | 5.248 s | 79.740 GB |
| SN PIE 3 | 14.075M | 5.570 s | 99.268 GB |
| SN PIE 1 | 14.645M | 5.737 s | 100.443 GB |

At similar step counts, memory differs substantially, so extrapolating the
180M case from steps alone would be misleading.
For a larger cohort, record `os_steps`, holes, builtins, largest component log,
ingress, proof time, host RSS, and GPU peak. Preflight the 180M-step input's
geometry and memory before allocating a full prover arena. The current adapted
input decoder also has a **2 GiB file-size cap**, which the 180M-step case may
hit before GPU admission; that cap must be measured rather than silently
raised. If the planned prover footprint exceeds H200 capacity, the range needs
new contiguous SNOS PIE boundaries (or
an independently qualified trace-partitioning protocol); cutting an existing
ZIP into files would not preserve its proof semantics.

The API downloader is [fetch_starknet_pies.py](../../../../scripts/fetch_starknet_pies.py).
It can select ready PIEs near requested step counts or resolve an actual
contiguous block interval. Start with `--meta-only` and the explicit
`15553620_15553629` name before downloading the large ZIP. It records
metadata and ZIP hashes, checks range contiguity, and does not forward the
bearer token to the redirected storage host.
