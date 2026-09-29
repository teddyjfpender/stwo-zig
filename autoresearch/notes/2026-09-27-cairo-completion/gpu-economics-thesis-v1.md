# PIE proving economics: single RTX 5090 hypothesis

Discussion checkpoint, 2026-09-28. No NVIDIA performance claim or GPU qualification is made here. CPU/Metal optimization work will pause after v92 qualification at the user's request.

The objective is minimum fully loaded cost per accepted proof, subject to end-to-end latency well under 5 seconds, canonical security, and memory headroom. The user clarified the aspirational target: beat the reported 1.5-second H100 result at $3/hour. Isolated kernel speed and minimum allocation size are intermediate metrics.

## Known measurements and boundaries

Canonical SN PIE 3, v91 same-binary three alternating pairs, Apple M5 Max:

| Metal storage | Median isolated proving | Maximum process physical footprint |
| --- | ---: | ---: |
| Ordinary | 15.193823 s | 50.848074 GB |
| Compact, experimental | 33.221000 s | 41.302899 GB |

The compact policy saves 18.77% of measured peak footprint but takes 2.187 times as long. All six initial trials are retained, officially verified, byte identical, and have zero CPU fallbacks. This is evidence about this implementation on Metal; it is not a prediction of the CUDA reconstruction penalty.

NVIDIA specifies 32 GB GDDR7 and 1,792 GB/s memory bandwidth for the RTX 5090: [official specifications](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/). Advertised bandwidth is a ceiling, not measured prover throughput.

Apple's process physical footprint includes CPU and Metal allocations sharing unified memory. It is not CUDA device peak memory. A discrete implementation can keep cold data in host memory; it can also introduce host/device duplicates absent on Apple. Therefore neither the 50.85 GB ordinary nor the 41.30 GB compact figure establishes a 5090 fit result. CUDA allocator high-water telemetry must include persistent arenas, caches, FFT/FRI scratch, commitments, queries, and staging allocations. Host physical/RSS and pinned-memory peaks must be measured separately with explicit byte units.

The historical approximately 1.5-second H100 result is user-recalled and tentatively attributed to SN PIE 2; witness inclusion and receipt are not yet established. Do not use it to calibrate speedups or production cost.

## Candidate policies to compare

| Policy | Memory mechanism | Expected cost to measure |
| --- | --- | --- |
| Lifetime reduction and buffer reuse | Remove duplicates, retire feeds/columns at last joined consumer, reuse disjoint stage scratch | Can save memory without additional arithmetic or transfers; prove dependency and ownership safety |
| Bounded component/column streaming | Process independent native-size batches through a bounded arena | Smaller batches may lose occupancy or add submissions; transcript barriers restrict overlap |
| Selective retention/reconstruction | Retain native coefficients and required commitments; reconstruct bounded AIR/query data | Extra FFTs and repeated reads may increase time; latest compact Metal result quantifies a substantial current penalty |
| Explicit host backing | Keep cold data in host RAM; prefetch bounded pinned buffers; overlap transfer with independent computation | PCIe traffic, synchronization and CPU supply may dominate; provision host RAM separately |
| More than one GPU / higher-memory GPU | Distribute independent work or fit larger resident working sets | Additional hardware, transfers, host resources, reduction/aggregation and scheduling costs; capacity is not automatically one pooled arena |

NVIDIA recommends minimizing host/device transfers and describes pinned asynchronous transfers and overlap in its [CUDA Best Practices Guide](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-c-best-practices-guide/). The proposed streaming policy applies that guidance; it is not implemented or qualified by this checkpoint.

A starting engineering target would leave several GB of the 5090's advertised capacity unused (roughly a 24-28 GB device working-set budget), with the exact budget established from CUDA's reported usable bytes and production safety margin. Fitting narrowly at the hard limit is insufficient for a service. This is a proposed budget, not a measured fit.

Choose the policy per workload: SN PIE 2 is smaller than SN PIE 1/3 in the current suite; it need not pay the same reconstruction cost. A bounded scheduler should select the largest safe resident batch for each authenticated geometry. Reducing host witness storage alone will not fix a later GPU commitment/opening peak.

## Cost model and experiment

For a steady service:

    cost per accepted proof = total provisioned system cost per hour / accepted proofs per hour

Total system cost includes GPU rental or amortization, CPU, RAM, electricity/cooling as applicable, idle capacity, and retries. Measure accepted throughput directly under the intended arrival rate and concurrency; do not divide by isolated proof latency if overlapping jobs or queueing change throughput.

For a serial, fully occupied illustrative comparison, if a 5090 system takes 2.2 times as long as a larger GPU system, it breaks even only below about 45.5% of the larger system's hourly cost. At lower utilization, include the idle allocation cost. A cheaper proof is still inadmissible if p99 latency misses the deadline.

When NVIDIA access becomes available, compare ordinary resident, bounded streaming, and compact reconstruction on all four pinned PIEs. Hold workload, witness inclusion, security, verifier acceptance and cold/warm cache policy fixed. Record:

- Isolated proof time and end-to-end time (PIE decode, execution/witness, proof, serialization and verification reported separately).
- CUDA device peak, host physical/RSS peak, pinned peak, transferred bytes, transfer time, reconstruction time, and fallback counts.
- Warm steady accepted proofs/hour, failure/retry rate, queue-inclusive p95/p99 latency, and fully loaded cost/proof.
- One request and controlled concurrency, with a persistent service where supported and bounded caches.

There is no numerical 5090 latency forecast at this checkpoint. The initial hypothesis is that lifetime reduction plus bounded streaming can make a single 5090 economical; compact reconstruction is a fallback whose measured compute penalty must be justified against system cost and latency.

## User-calibrated production target (2026-09-28)

The user specifies latency well under 5 seconds, including witness generation
and queueing, and wants to beat the historical 1.5-second H100 reference at
$3/hour. Treat sub-1.5-second comparable end-to-end latency as the aspirational
target, not merely fitting on a cheaper GPU. The archive, security, timing
scope, and official acceptance must match before claiming the reference beaten.
The recalled reference is tentatively SN PIE 2; its timing scope is still
unconfirmed. Its $3/hour rate is user-provided, not a current market quotation;
host-resource inclusion is unconfirmed.

At serial full utilization, ignoring additional unbundled costs, the reference
is 2,400 accepted proofs/hour and $0.00125/proof (0.125 US cents). For a
candidate taking T seconds at R dollars/hour, cost parity requires R*T = 4.5.

| Candidate serial latency | Hourly cost ceiling for reference cost parity |
| --- | ---: |
| 1.0 s | $4.50/hour |
| 1.5 s | $3.00/hour |
| 2.0 s | $2.25/hour |
| 3.0 s | $1.50/hour |
| 4.0 s | $1.125/hour |

A lower rate beats reference cost; a latency below 1.5 seconds beats reference
latency. A slower single-5090 proof can win on cost while losing on latency;
label that result explicitly rather than claiming it beats both. These are
arithmetic thresholds, not device performance predictions or rental quotes.
Compare fully loaded provisioned system costs on both sides. In production,
replace serial latency-derived throughput with measured accepted proofs/hour
and separately enforce queue-inclusive tail latency. Low arrival rates and
idle provisioned capacity invalidate the full-utilization cost estimate.

The CPU/Metal optimization goal remains paused. This target clarification
updates the GPU discussion thesis only; no new optimization or GPU run begins.
