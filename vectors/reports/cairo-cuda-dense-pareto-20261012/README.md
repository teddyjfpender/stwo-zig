# Dense single-block Cairo PIEs on smaller GPUs

This experiment asks whether the largest *ready, single-block* PIE in the live
catalogue can be proved on a lower-rental-cost GPU while preserving the exact
canonical proof. On 12 October 2026, the ready catalogue contained 51,015 PIEs,
including 19,856 single-block PIEs. Its highest-step single-block entry was
`16011167_16011167`: **25,942,361 OS steps**, eight transactions, 172,116
Pedersen calls, and 591 EC-op calls. The dated catalogue snapshot and API
metadata are in [`catalogue-summary.json`](catalogue-summary.json) and
[`source-metadata/`](source-metadata/).

## Result

The highest-step PIE fits and proves on a 96 GB RTX PRO 6000 Blackwell Server
Edition. Two independent proofs had identical SHA-256
`a556b6afed7bdcb237710653489d11d110d5b0d992608587cea5aeeadaff6658`;
the pinned official Rust verifier accepted the proof. The source is an adapted
canonical `.cpi`, so these timings exclude SNOS execution and PIE adaptation.

| PIE | GPU | OS steps | Proof stage | Adapted input to publication | Whole-device peak |
| --- | --- | ---: | ---: | ---: | ---: |
| `16011167_16011167` | RTX PRO 6000, run 1 | 25.94M | 0.952 s | 3.073 s | 78.74 GiB |
| `16011167_16011167` | RTX PRO 6000, run 2 | 25.94M | 0.952 s | 3.113 s | 78.74 GiB |
| `16011167_16011167` | H200, run 1 | 25.94M | 1.160 s | 5.096 s | 78.61 GiB |
| `16011167_16011167` | H200, run 2 | 25.94M | 1.161 s | 5.130 s | 78.61 GiB |
| `15656867_15656867` | RTX PRO 6000 | 24.97M | 0.826 s | 3.005 s | 76.12 GiB |
| `15582797_15582797` | RTX PRO 6000 | 20.85M | 0.911 s | 2.843 s | 83.80 GiB |
| `15582797_15582797` | H200 | 20.85M | 1.245 s | 7.433 s | 83.67 GiB |
| `15591789_15591789` | H200 | 25.38M | 1.655 s | 6.018 s | 107.67 GiB |
| `15591789_15591789` | RTX PRO 6000, best tested placement | 25.38M | 31.221 s | 33.520 s | 88.13 GiB |

These are observed runs, not a prediction of all one-block PIEs. The complete
table, including failed policies and A100 experiments, is
[`results.tsv`](results.tsv); regenerate it from the raw receipts with
`python3 make_results.py`. The full proof for the highest-step PIE is stored
compressed in [`proofs/`](proofs/), with the Rust-verifier verdict in
[`receipts/pro6000/highest-rust-verdict.json`](receipts/pro6000/highest-rust-verdict.json).

The lower-cost GPU wins on the exact-input highest-step pair: $2.49/hour
divided by $5.29/hour for the H200, multiplied by the observed proof-time ratio
of 0.952/1.160, gives **0.39 times the H200 proof-stage rental cost**. The
PRO 6000 is also 18% faster in proof execution on that input. On the resident
20.85M-step case, the proof-stage rental-cost ratio is **0.34**. The
cross-host adapted-input timings are less controlled because input paths and
host storage differ (`/tmp` on both hosts, with different local storage and
CPU characteristics); use matched-host service runs before making a
production request-cost claim. No build, queue, or idle-time cost is included
in these per-proof ratios.

For the highest-step PRO 6000 run, the 2.087-second ingress divides into
0.540 seconds of source preparation, 0.660 seconds of static setup,
0.284 seconds of CUDA runtime startup, 0.236 seconds of writer preparation,
and 0.367 seconds of other work. Thus the proof itself is already under one
second on this GPU, while startup and ingress determine most of the
adapted-input-to-publication latency. The receipt has the precise nested
timings; these rounded categories are for diagnosis, not a separate clock.

The near-top but geometrically denser `15591789_15591789` is the counterexample
to step-count-only routing. It has **25,379,487** OS steps, 191,100 Pedersen
calls and 960 EC-op calls. Its planned arena is 106.55 GiB, so it does not fit
in the PRO 6000's 96 GB physical memory. Managed placement made it provable,
but the best tested policy took 31.221 seconds of proof execution versus
1.655 seconds resident on H200. At the observed rental rates, that is about
**8.9 times the H200 proof-stage cost**. Whole-device peaks below 96 GB in
those trials do not mean all hot pages were resident; the slow evaluation
stage is consistent with managed-memory migration. The largest overlapping
plan slots include 63.18 GiB of trace evaluations, 31.54 GiB of lookup writer
inputs, 31.34 GiB of trace coefficients, and 13.81 GiB of writer scratch.

## Qualification and method

The source PIE metadata came from the dated `/v1/pies` catalogue snapshot.
The adapted input for the highest-step case has SHA-256
`f0b1189f14af78195c2b5151679d62da79c909f1c9af281eae8a4e2432ec9956`.
Proofs use the canonical Blake2s channel, 70 queries, and 26 proof-of-work
bits. The same highest-case proof bytes were produced twice, and the pinned
Rust verifier at `stwo-cairo@82f21252a68ec006d73e299f5bf1ce6d4db0ee78`
accepted them. Trial receipts record executable SHA, policy environment,
proving and ingress stages, full command time, planned arena, and sampled
whole-device peak. The full-command timer includes process startup and
teardown; the adapted-input-to-publication timer covers the in-command proof
request. Preflights checked CUDA context, managed advice, prefetch, a kernel,
and synchronization on each experimental host.

This branch also contains an opt-in, bounded prefetch policy for capacity
experiments. On A100, a balanced placement with this policy reduced the
20.85M-step proof stage from 26.470 to 14.280–14.369 seconds with identical
proof bytes, but that remains materially slower and more expensive than a
resident H200 or PRO 6000 proof. The policy rejects transfers that cannot
leave a four-GiB device reserve. It is research-only and disabled by default.

The next architectural target is the dense geometry tail: determine which
large temporary slots can be streamed or recomputed across their true lifetime
instead of relying on fault-driven managed-memory migration. A routing rule
should use the planned arena and component geometry, not OS steps alone, to
choose a GPU. The highest-step success shows that 25M-step single-block PIEs
can be inexpensive on the 96 GB GPU; it does **not** establish that every
25M-step PIE fits there or that a 32 GB RTX 5090 is competitive.
