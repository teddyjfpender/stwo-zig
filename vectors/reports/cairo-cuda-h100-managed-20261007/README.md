# Cairo CUDA H100 capacity trials, 2026-10-07

These are **single cold-command trials**, not ranked benchmark scores. The
source is `c1a94c01e` on `codex/cairo-cuda-managed-arena`; input and proof
identities are in each `report.json` and independent
`official-verdict.json`. The H100 SXM has 80 GiB of HBM. The fixed asset
was the canonical preprocessed image. Whole-device peak was sampled with
`nvidia-smi` every 250 ms, so it is an observed lower bound on a transient
peak. Host RSS does not reliably count all UVM-backed pages.

| PIE | Arena plan | Mode | Full command | Adapted input to publication | Ingress | Proof + decode | Observed GPU peak | Observed process RSS peak | Official verifier |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 15582797_15582797 | 88.627 GB | managed | 16.831 s | 15.171 s | 4.248 s | 10.863 s | 79.177 GiB | 3.726 GiB | accepted |
| 15590913_15590913 | 103.367 GB | managed | 39.072 s | 37.282 s | 4.542 s | 32.680 s | 79.177 GiB | 3.798 GiB | accepted |
| 15590913_15590913 | 103.367 GB | managed + stage prefetch | 37.007 s | 34.802 s | 4.723 s | 30.016 s | 79.177 GiB | 77.021 GiB | accepted |

The proof SHA-256 values are `fcc457fee3bcaca85efd97d308daa1a16e849c633b4571144417543158eb1eeb`
and `23ef11f1f7bbf0b31d6ede197bd67d2548975b951283c4cedc0fb6148e443af9`,
respectively. The dense PIE's managed and prefetched proofs are byte
identical. The latter hash also matches the pinned H200 expected proof.
The ordinary H100 device-pool path rejected the first 88.627 GB plan at
admission with `InsufficientDeviceMemory`; managed memory only makes the
out-of-core proof possible, and does not lower the plan's size.

The dense PIE's device-stage timings show why managed memory is not the final
design. In stage order ingress, trace generation, trace commit, constraint
evaluation, OODS, quotient, FRI commit, PoW, decommit, assembly:

| Mode | Trace commit | Constraint | OODS | Quotient | Decommit |
| --- | ---: | ---: | ---: | ---: | ---: |
| Managed | 10.086 s | 5.770 s | 4.058 s | 3.756 s | 4.248 s |
| Managed + prefetch | 9.717 s | 5.947 s | 7.418 s | 2.743 s | 0.023 s |

Prefetch trades OODS time and host memory for faster quotient/decommit. One
paired trial is insufficient to call its 2.48 s publication gain repeatable.
The proof identity and verifier result do establish correctness for this
input. The stage memory inventory is in `geometry-dense.txt`; the proposed
bounded-memory pipeline is in
[`design/cairo-cuda-bounded-memory-pipeline.md`](../../../design/cairo-cuda-bounded-memory-pipeline.md).

## Host-placement follow-up

The following are additional single cold-command diagnostics on an 80 GiB
H100 SXM. They use the same canonical inputs and independent Rust verifier.
`throughput` and `capacity` are the opt-in values of
`STWO_CUDA_MANAGED_PLACEMENT` in the updated source. The `final-baseline` and
`final-capacity` receipt directories hold a sequential same-pod pair from
before evaluation placement moved to the pre-commit boundary. Every
successful follow-up proof had the exact expected SHA-256
listed above.

| PIE | Placement | Adapted input to publication | Observed GPU peak | Observed process RSS peak | Independent verifier |
| --- | --- | ---: | ---: | ---: | --- |
| 15590913_15590913 | managed only (`final-baseline`) | 35.725 s | 79.177 GiB | 3.763 GiB | accepted |
| 15590913_15590913 | post-commit placement (`final-capacity`) | 34.618 s | 69.614 GiB | 3.764 GiB | accepted |
| 15590913_15590913 | pre-commit capacity (`early-evaluations`) | 34.310 s | 56.487 GiB | 3.764 GiB | accepted |
| 15590913_15590913 | throughput (`host-evaluations`) | 22.835 s | 79.177 GiB | 3.770 GiB | accepted |
| 15582797_15582797 | post-commit placement (`final-capacity-second`) | 24.408 s | 59.614 GiB | 3.693 GiB | accepted |
| 15582797_15582797 | pre-commit capacity (`early-evaluations-second`) | 29.651 s | 48.362 GiB | 3.694 GiB | accepted |

The capacity policy moves the lookup slab before trace writers execute and
places both evaluation trees on the host before their commitments. The dense
PIE saves 22.690 GiB (28.7%) of observed device memory versus the same-pod
managed-only run; the second saves 30.815 GiB (38.9%) against its earlier
managed-only reference. The planned
arena sizes remain 103.367 GB and 88.627 GB; this is HBM placement, not a
smaller logical proof plan. Publication time varied by several seconds across
single runs, so there is no qualified speedup claim.
Host RSS is not a reliable measure of all UVM-backed pages.
The 48.362 GiB result does not establish that this PIE fits a nominal 48 GB
card; the advertised capacity may be decimal and the device needs reserve.

The discarded experiments are summarized in
`host-placement/experiment-comparison.tsv`: late lookup
placement did not lower the peak; whole-component lookup retirement was fast
but left the 15.59 GiB `partial_ec_mul_window_bits_18` output on the GPU until
its writer finished; moving only that large component before its writer was
slower and still reached the H100 limit. Host-placing interaction coefficients
before commitment also left the peak unchanged while adding substantial time.
These observations motivate row-level
lookup chunking and bounded LDE evaluation storage.
