# Cairo PIE construction for the CUDA prover

The PIE-producing service chooses contiguous Starknet OS block ranges. The
prover can only inspect an OS PIE **after it has been baked and adapted**; it
cannot infer the exact AIR from a sum of block step counts. This document
records the 512-leaf H200 evidence, identifies the dominant geometry, and
specifies the Zig admission and partition tool. The service remains
responsible for authenticating OS inputs and state roots and for obtaining
proofs; the planner does not create an OS execution or qualify a proof.

## What the 300 one-block PIEs cost

The [complete campaign receipt](https://github.com/starknet-innovation/proving-service/tree/main/data/h200-api-128-512/h200-api-512-001)
contains 512 ordered PIEs, of which 300 span one block. Joining its per-PIE
timers to the [later API metadata export](https://github.com/starknet-innovation/proving-service/blob/main/data/h200-api-128-512/pie_metadata.csv)
gives:

| Measured per-PIE timer | One-block sum | One-block median | One-block p95 | Share of all 512 reported timer values |
| --- | ---: | ---: | ---: | ---: |
| Input ingress | 323.465 s | 0.943 s | 1.757 s | 60.5% |
| Cairo proof | **365.593 s** | **1.209 s** | **1.274 s** | **69.2%** |
| Circuit leaf wrap | **308.275 s** | **0.987 s** | **1.156 s** | **56.9%** |
| Cairo proof + wrap | **673.867 s** | **2.210 s** | **2.466 s** | **63.0%** |

These sums describe reported work, **not 674 seconds of separable campaign
wall time**. Input lookahead and publication windows overlap work; the 300
items were mixed with other PIEs in sixteen 32-item worker commands. The
accepted-to-root wall clock for all 512 was 2,103.459 s. The one-block
population had 73.1% of OS steps, 80.8% of API-reported EC-op uses, and
78.6% of API-reported Pedersen uses, but builtin counts alone do not apportion
the measured time.

**Individual memory for these 300 was not sampled.** The saved GPU peak is a
whole-device maximum for each 32-PIE command, repeated in its member rows.
Those sixteen command peaks ranged from **93.194 to 123.259 decimal GB**;
assigning any of those values to a specific PIE would be false precision.
The separately verified [PIE scale study](../vectors/reports/recursive-product-20260918/pie-scale-study-20261001/README.md)
has 478 individually proved PIEs under several earlier builds. Its 136
one-block cases had a 101.389 GB median sampled GPU peak, but they are **not
the campaign's 300** and cannot answer their memory distribution.

## The dominant memory cliff is Pedersen's downstream EC multiplication

An exact local geometry replay on the separately verified one-block PIE
`15590913_15590913` gives a useful component-level example. This PIE had
22.673 million OS steps and 217,608 reported Pedersen uses; its source
metadata reports no EC-op uses. Nevertheless its H200 proof peaked at
**105.201 GB**, close to its **103.367 GB** planned resident arena, and its
proof execution took 1.567 s. The inspector counted **193,076 distinct
Pedersen keys**. Crossing 131,072 keys pads the aggregator to 2^18 rows;
the 28-to-one downstream `partial_ec_mul_window_bits_18` feed then pads to
**2^23 rows**.

| Exact resident geometry for this raw PIE | Bytes or rows |
| --- | ---: |
| `partial_ec_mul_window_bits_18` main coefficients | 9.966 GB |
| Its interaction coefficients | 8.724 GB |
| Its main + interaction LDE evaluations, at 2× coefficient height | 37.380 GB |
| **Those four arrays' logical storage** | **56.070 GB** |
| Its retained lookup-input slab | 16.744 GB |
| All writer lookup inputs | 29.929 GB |
| Resident live maximum, at constraint evaluation | 102.324 GB |

The logical component figures **cannot be added to the resident peak**:
the planner aliases non-overlapping lifetimes. The lookup-input slab ends at
trace commitment's first phase, while the largest recorded live set occurs
later at constraint evaluation. Eliminating that lookup slab alone therefore
does not imply a proportional reduction in whole-proof peak. The direct
`ec_op_builtin` trace in this example is only 273 main and 36 interaction
columns at 2^8 rows; it is not the source of the 56 GB expansion. Pedersen's
partial-EC multiplication is the key target.

The separately tested `15591789_15591789` is a useful cross-check: its API
reports **960 EC-op uses**, yet the current standalone canonical geometry
allocates only **1.266 MB of direct EC-op coefficients** (main and
interaction combined), versus **56.069 GB of coefficients and evaluations
for Pedersen's partial-EC component**. Its exact standalone arena is
114.412 GB. This is a geometry comparison, **not a new H200 measurement or
the production circuit-leaf lane**. It shows that EC-op counts are a weak
explanation of the memory cliff even for an EC-heavy PIE.

The [earlier geometry diagnosis](../vectors/reports/recursive-product-20260918/pie-scale-study-20261001/README.md)
compares two PIEs near 24 million steps: one had 131,623 distinct Pedersen
keys and the other 129,868. Crossing the padding boundary added **4.983 GB
to the partial-EC main coefficient trace alone**. The old `u32` trace-offset
failure was fixed; the padded storage jump remains. This demonstrates why a
step cap, raw Pedersen-call cap, or transactions-per-PIE cap is not a safe
device-memory rule. The separately measured 35 final-build stress cases had
sampled GPU usage 1.821–2.124 GB above their exact allocated plans (median
1.841 GB); a reserve is still required because this is a selected cohort.

The backend has **already** recovered a large lookup/evaluation lifetime
overlap. Fifteen former near-capacity cases peaked at trace commitment with
roughly 33.7–42.8 GB of writer lookup outputs; seven retested cases had
planned allocations reduced by as much as **33.6 GB** after the planner
separated the lookup read from the interaction-evaluation write and improved
arena placement. That was proof-format-preserving and Rust-verified. The
remaining target is the current live set, not reintroducing the same
lifetime fix. In the `15590913` example it peaks at constraint evaluation;
other, larger geometries can still peak at trace commitment or OODS.

## Optimization priorities and proof obligations

1. **Make exact geometry part of upstream boundary search.** The enhanced
   `cairo-trace-geometry` accepts the same circuit registry as the leaf prover
   and emits a content-bound JSONL receipt. The PIE producer should first
   screen plausible contiguous ranges using cheap source statistics, then
   bake and adapt the surviving ranges and use this exact receipt. In
   particular it should test partitions on both sides of each Pedersen
   power-of-two boundary. This can reduce proof count while avoiding a large
   memory cliff. A one-block PIE already over the limit needs a backend
   improvement; block-boundary selection cannot split it further.
2. **Attack the simultaneous coefficient/evaluation live set.** The largest
   example peaks at constraint evaluation, when main and interaction trace
   representations coexist for later OODS/quotient/decommit work. Candidate
   architectures are tiled LDE/commitment with a compact query-retention
   scheme, deterministic witness or LDE replay after commitment, and bounded
   host spill only where transfer cost is acceptable. The Merkle root and
   queried values must remain transcript-identical; any new lifetime must be
   checked against decommitment. A mere allocator switch or asynchronous
   transfer does not remove simultaneously live words.
3. **Profile time before rewriting arithmetic.** The native `ec_op_builtin`
   writer already uses projective arithmetic and reuses dead partial-input
   columns as scratch. The Pedersen partial-EC component and its generic AOT
   witness, commitment, interaction and FRI costs need an idle-H200 timeline
   with kernel/activity attribution. A specialized writer or changed AIR may
   be valuable, but component counts do not prove that EC arithmetic itself
   is the critical path. An AIR change additionally requires a new verifier
   contract and end-to-end security/parity qualification.
4. **Test memory ideas at the real peak.** Replaying retained lookup inputs
   could shrink trace-generation/commit memory, but the later
   constraint-evaluation peak must be recomputed before claiming a smaller
   H200 requirement. Tiling or spilling needs proof-byte equivalence or an
   explicitly versioned proof change, independent verification, stage timings,
   and sampled whole-device memory on low/high Pedersen-key controls.

NVIDIA's [CUDA allocator documentation](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/stream-ordered-memory-allocation.html)
supports stream-ordered reuse of freed allocations; it does not claim to
compress live data. Its [best-practices guide](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html)
recommends measuring effective bandwidth and coalescing before tuning a
kernel. These are hypotheses to test on this prover, not measured speedups.

## Zig construction tool and service boundary

Build both tools with `zig build cairo-trace-geometry
cairo-pie-construction-plan -Doptimize=ReleaseFast`.

1. The PIE service bakes candidate complete-block ranges. For each it retains
   the input CPI SHA-256, first/last block, boundary state roots, and any
   *calibrated* input-ingress-plus-Cairo-proof estimate. It also supplies a trusted ordered
   per-block root chain.
2. Run `cairo-trace-geometry --circuit-registry REGISTRY.json --jsonl
   CANDIDATE.cpi ... > geometry.jsonl`. One invocation reuses immutable source
   assets; `--artifact-dir` or `STWO_CAIRO_CUDA_ARTIFACT_DIR` points it at the
   worker's authenticated asset directory when running outside the source
   checkout. Each line binds the CPI SHA-256, exact registry SHA-256 and asset
   hashes to the
   actual variant, allocated/peak-live bytes, Pedersen distinct keys, padding,
   and major component sizes. Missing registry produces a diagnostic receipt,
   which the partition planner refuses.
3. Run `cairo-pie-construction-plan --candidates candidates.json --geometry
   geometry.jsonl --circuit-registry REGISTRY.json --device-bytes DEVICE
   --reserve-bytes RESERVE --objective leaves`. The tool rejects geometry
   hashes, duplicate candidates, discontinuous blocks, invalid candidate
   roots and inconsistent source hashes. It excludes oversized candidates
   and finds the **minimum-leaf contiguous partition among the supplied
   candidates** in linear time in blocks plus candidates. Ties prefer lower
   modeled cost, then lower maximum allocation.
4. For `--objective estimated-time`, every admitted candidate must carry
   `estimated_ingress_and_cairo_ms`; supply explicit `--leaf-wrap-ms` and
   `--fold-ms`.
   The planner then minimizes that declared additive model, not actual
   unmeasured latency. It marks the output `proof_qualified=false`. The
   service must still prove every selected PIE, independently verify the
   leaf and root, and record measured time and whole-device memory.

The candidate file uses this JSON shape; the hash below is illustrative and
must be replaced by the adapted input's actual SHA-256. `pie` must equal the
stem printed in the matching geometry line.

```json
{
  "schema": "stwo.cairo-pie-candidates.v1",
  "blocks": [
    {"number": 15653264, "initial_root": "0x1", "final_root": "0x2"}
  ],
  "candidates": [
    {
      "pie": "15653264_15653264",
      "first_block": 15653264,
      "last_block": 15653264,
      "initial_root": "0x1",
      "final_root": "0x2",
      "input_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "estimated_ingress_and_cairo_ms": 2100
    }
  ]
}
```

For a real campaign, the service supplies many overlapping candidate ranges
in the same file. The planner considers only complete contiguous partitions
of the ordered `blocks` array; it does not search across missing candidates.

This tool formally checks **continuity, identity binding, capacity against a
declared reserve, and optimality over the candidates/model supplied**. It
cannot certify that a candidate OS execution is valid merely from its JSON
fields, that an unbaked range would fit, or that modeled time equals actual
time. Those are explicit service/prover obligations rather than hidden
assumptions in the partition result.
