# Generic CUDA System Architecture

## Verdict

Commit `a49a389de5cf9c40305b521b9f18747bdb999887` is a
performance-qualified architecture checkpoint, not a `core_cuda` promotion.
Against frozen predecessor
`f66f7d82ec4128770ad78770a92d754729fbb92b`, the equal-weight
structural-class verified-request ratio is `0.433310` (2.308x speedup), with a
95% round-bootstrap interval of `[0.432620, 0.433954]`.

This verdict covers latency, narrow/deep, non-target wide, and extreme
wide-Fibonacci geometry. It does not establish end-to-end performance for the
Native Blake, Poseidon, Plonk, state-machine, or XOR AIRs, and it does not
cover RISC-V, Cairo, or a sustained mixed-shape service. The CUDA board remains
disabled and promotion-ineligible.

## Architecture

The candidate changes reusable CUDA backend mechanisms:

- process-owned strict-AOT runtime, persistent sessions, and fixed-address
  shape arenas;
- authenticated function and graph caches keyed by complete plan identity;
- explicit graph/direct execution with exact byte-parity gates;
- fused basis-transform and composition intervals selected only by direction
  and domain log;
- stack-free transform schedules selected only by transform structure;
- one-pass contiguous-slab Blake2s leaves with a progressive segmented
  fallback;
- one terminal D2H operation, zero CPU fallbacks, and truthful per-stage CUDA
  event telemetry;
- separate proof-semantic and executable program identities.

No path selects a kernel from an AIR name, benchmark identifier, input digest,
or target width.

## Formal ABBA Result

The same RTX 4090 ran seven counterbalanced A-B-B-A rounds per workload. Each
process used ten warmups and five verified samples. Ratios are paired
candidate/predecessor estimates.

| workload | predecessor | candidate | ratio | 95% CI |
| --- | ---: | ---: | ---: | ---: |
| latency `log14 x 32` | 2.609 ms | 2.190 ms | 0.8397 | [0.8382, 0.8409] |
| narrow/deep `log22 x 3` | 59.16 ms | 22.37 ms | 0.3782 | [0.3779, 0.3782] |
| wide `log18 x 37` | 8.53 ms | 5.03 ms | 0.5887 | [0.5788, 0.5986] |
| wide `log18 x 73` | 14.69 ms | 6.33 ms | 0.4309 | [0.4307, 0.4312] |
| wide `log18 x 128` | 23.53 ms | 8.50 ms | 0.3614 | [0.3612, 0.3616] |
| extreme `log22 x 100` | 322.91 ms | 79.47 ms | 0.2462 | [0.2460, 0.2464] |

The extreme row is 52.8 row-MHz and approximately 5.28 billion committed
cells/s at the verified-request boundary.

Every row remains below the 1.05 regression ceiling. The worst steady row is
the small latency case at 0.8397. Cold-process time is a separate boundary:
the small row regressed from about 299.4 ms to 317.9 ms, while the extreme row
improved from about 882.2 ms to 623.4 ms. Cold small-proof startup therefore
remains open work.

## Correctness And Resources

- Canonical proof bytes are identical across predecessor, graph, and forced
  direct execution for every measured shape.
- Independent Zig verification and the pinned Rust Stwo oracle pass.
- Twelve SM89 device differentials pass, including direct/progressive
  commitment widths `1, 15, 16, 17, 31, 32, 33, 37, 64, 73, 100, 128, 257`.
- CPU fallback attempts and completions are zero.
- Exactly one terminal proof read is reported.
- Graph cache provenance, request allocation release, persistent arena bounds,
  AOT identity, and repeated proof determinism are enforced by report schema
  v6.
- The focused `native_cuda_device` CI/oracle lane passes on the RTX 4090.

## Rejected Experiment

A retained four-level Merkle kernel reduced launch count by 31-39%, but
regressed real proofs at small, wide, and extreme shapes. Its shared-memory
and live-state cost plus underfilled upper levels outweighed launch savings.
The experiment was removed rather than retained as benchmark-specific code.

## Coverage Blockers

`core_cuda` remains disabled because only four of nine required structural
classes have end-to-end workloads. Missing classes are:

- hash-heavy Native Blake and Poseidon;
- lookup-heavy Native Plonk/LogUp;
- irregular state-machine geometry;
- RISC-V VM workloads;
- sustained mixed-shape proving.

The next delivery is a generic uniform-log Native executor followed by XOR as
the first non-wide AIR. XOR forces nonempty preprocessed-tree handling without
copying the wide-Fibonacci executor. Blake and Poseidon then exercise the same
generic commitment and transform paths at much larger widths.

## Evidence Identity

- Candidate binary SHA-256:
  `b7115a64c116c21f70b8f48e4d038ed658441b56babed3819c24b5e27f222d51`
- Predecessor binary SHA-256:
  `c7ebcdcdf6692cd21edf8411c1c253c7341e67550f37f267cbda61e09bb35e73`
- Full raw judge report SHA-256:
  `e796fa27e01d636c06bc2c0f1e43cbba5bffac9b32872ac1bba90549a61e5ebd`
- GPU: NVIDIA GeForce RTX 4090, SM89, driver `580.126.09`
- Zig: `0.15.2`, `ReleaseFast`
