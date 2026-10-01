# H200 recursive-pipeline phase split and owned witness, 2026-10-01

Eight ABBA-order trials prove the same two continuous adapted mainnet PIEs,
`15627902-15627904` and `15627905-15627907`, through two CUDA leaf wraps and
one canonical CUDA fold. The security settings are 70 FRI queries and 26 PoW
bits for both Cairo and circuit proofs. Every leaf and root proof, root output,
and packed-root digest matches the pinned Rust-qualified reference. The raw
trial data are in [measurements.json](measurements.json); the mutually
exclusive timing columns for every trial are in
[phase-breakdown.csv](phase-breakdown.csv). All times below are seconds.

| Phase, median of four trials per binary | Baseline | Owned witness |
| --- | ---: | ---: |
| Already-adapted input to verified root | 15.842 | 17.662 |
| Fixed preprocessed asset load | 3.838 | 3.776 |
| Other Cairo ingress and preparation | 4.039 | 4.751 |
| Cairo GPU proof execution | 0.852 | 0.858 |
| Cairo verification plus publication | 0.138 | 0.178 |
| Circuit host preparation, including witness build | 4.112 | 5.137 |
| Circuit resident plan and ingress | 0.630 | 0.712 |
| Circuit resident proof schedule and finish | 0.859 | 0.862 |
| Circuit local verification | 0.011 | 0.018 |

The medians of individual columns do not sum to the median total. Each CSV
row does sum to its corresponding wall clock: it also records arena release,
resident decode/other, conversion, process overhead, and driver overhead.
`fixed_asset_load_s` is **inside** the original `cairo_prove_s` timer; the CSV
subtracts it from Cairo ingress before showing other preparation. Adaptation
and a separately timed adapted-file disk read are zero in these trials because
the inputs were prepared earlier and the collector does not isolate file I/O
from source preparation. `cairo_verify_and_publish_s` is a combined timer;
the Cairo verifier part cannot be reported separately from these receipts.
`circuit_local_verify_s` separately times all three in-process circuit proof
checks. The Rust reference comparison here checks exact digests after the run;
it is not an independently timed Rust verifier call.

The change preallocates the known value count for authenticated circuit
topologies and transfers the fold's completed value table to the prover,
avoiding another full-table copy. An isolated M5 replay of the exact same
padded 44.5-million-variable witness fell from **199.0 ms to 102.4 ms**;
the full padded value-table SHA-256 was identical. The H200 median root
witness build fell from **606.5 ms to 541.5 ms**, and host peak RSS from
about **3.14 GB to 2.99 GB**. Whole-device sampled peak stayed **54.88 GB**.

These changes **did not establish an end-to-end speedup**. The raw H200 median
is 11.5% slower for the changed binary. Trial-to-trial host performance is
bimodal across both binaries: baseline trial 4 had a 5.60 s circuit-host
preparation stage, while the three slow owned trials were 5.11–5.17 s; the
fast owned trial was 3.15 s. The CUDA proof schedule/finish remained roughly
0.86 s for both. The evidence supports a narrower reduction in fold witness
allocation/copy cost and host memory, while full-pipeline latency needs more
same-host controlled work. The original 32.308 s H100 receipt and its 3.231 s
10× target are [documented separately](../cuda-resident-pipeline-h200-20261001/README.md).

The phase split is now emitted by
[`circuit_pipeline.py`](../../../../tools/starknet-block-collector/circuit_pipeline.py)
as `detailed_phase_breakdown_s` for future resident CUDA runs. This keeps
loading, preparation, proof execution, verification, and publication visible
without double counting nested timers.
