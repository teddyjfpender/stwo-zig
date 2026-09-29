# Cairo CUDA qualification and GPU economics — 28 September 2026

This session uses an authorized Runpod H100 SXM 80GB rental to assess the current Zig CUDA product. It does not promote the staged diagnostic route to production, and failed runs are not proving-performance results.

## Target and comparison basis

The user target is end-to-end PIE latency well under 5 seconds, including witness generation and queueing, and beating a historical approximately 1.5-second H100 result at $3/hour (PIE identity and timing boundary unconfirmed). That reference is $0.00125 per proof at full serial utilization. The actual current pod rate is $3.503/hour including storage: parity requires an accepted serial average below 1.285 seconds. Idle time, retries, setup, utilization and billed transfer time increase cost per accepted proof.

Runpod quoted an RTX 5090 at $0.99/hour but availability has not been established. Rate parity would allow approximately 4.545 seconds excluding storage, still subject to the full end-to-end latency target. Neither an Apple process footprint nor a failed GPU run establishes card fit or accepted-proof economics.

## Configuration and reproducibility

- H100 SXM 80GB; CUDA 12.8.93; NVIDIA driver 580.126.09; Zig 0.15.2; ReleaseFast; SM90 only.
- 8 vCPUs, 251GB host RAM. Shared/rented CPU capacity matters for witness and adaptation timing.
- Diagnostic SN PIE 2: 70 queries, 26-bit main PoW, 24-bit interaction PoW, blowup log 1, FRI fold step 3, channel salt 7. CPU/Metal recent default measurements use fold step 1 and salt 0, so timing comparisons must disclose that configuration difference.
- Freshly adapted current SN PIE 2 input SHA-256 matches the historical CUDA fixture exactly: `fe78e1549f66c2c175d075fad5e0c1ea174df29f9331684e654ef9e9c8821704` (162,102,548 bytes).
- The new bounded preprocessed exporter reproduces all 161 historical fixed-column coefficients byte for byte: SHA-256 `4d4fda06dfa3bca19554510a158f6c50abad06a74d29c17885ed4cbb88ada34d` (2,172,407,516 bytes).
- Source snapshots and build arguments identify the dirty worktree actually transferred. No repository credentials or local caches were included.
- Proof driver records exit status, host RSS, child wall time, product hash and 100ms whole-device NVML samples. The sampled device peak is a lower bound and includes driver allocations; it is not a precisely measured per-process live-byte peak.

## Qualification sequence

1. Repair CUDA AOT build drift: import the shared deduction contract, match all current enum selectors, explicitly reject unsupported lowering and retain authenticated manifests.
2. Build the Linux CUDA product from the staged source snapshot.
3. Run the full diagnostic proof and preserve all failures.
4. Publish the compact envelope and backend report; verify independently using the Rust adapters and official verifier before timing claims.
5. Only accepted proof runs may inform throughput and unit-cost comparisons. The CLI currently creates independent runtime/ingress per repeat; this is not a warm persistent service benchmark. Its adapted-input timer excludes PIE execution/adaptation and queueing.

## First hardware finding

Qualification v4 failed with `TraceWriterBindingMismatch` at schedule authority validation, before proof execution. The child wall time was 5.66452 seconds, host maximum RSS 901,476,352 bytes, and highest sampled whole-device used memory 81,150,148,608 bytes. These are failure-diagnostic numbers, not proving results. They establish a concrete allocation concern for smaller cards, not an accepted-proof memory requirement.

## Budget lifecycle

The initial session is capped at $5 and 75 minutes, with a detached balance/deadline watchdog plus server termination requested at creation. The pod must be deleted after receipts are downloaded. Final spend and cleanup status are recorded separately; do not infer active rental state from this file.


## Final hardware outcome — 28 September 2026

**The diagnostic CUDA backend builds and executes on H100, but does not yet
produce an accepted SN PIE 2 proof.** Qualification v14 reaches the sole terminal
read and rejects a nonzero FRI degree verdict: terminal header word 15 is 1,
where acceptance requires 0. No envelope was published, and neither independent
Rust verifier could therefore be run on a full CUDA proof. Performance and
cost-per-accepted-proof remain unqualified. The historical 1.5-second H100 result
has not been reproduced or matched to this implementation.

| Measurement | Latest outcome | Scope |
| --- | --- | --- |
| Complete SN PIE 2 CUDA proof | Rejected: FRI degree verdict | 70 queries / 26-bit main PoW; diagnostic protocol above |
| Accepted proof time | Not available | No accepted proof emitted |
| Device arena reservation | 80,091,736,000 bytes (80.09 GB) | Entire planned arena, not just peak live contents |
| Highest sampled device memory | 81,720,573,952 bytes (81.72 GB) | Whole-device NVML, 100 ms sampling, includes driver allocations |
| Host maximum RSS | 1,018,310,656 bytes (1.02 GB) | CUDA proof child only; excludes PIE VM execution |
| Failed child wall time | 8.220 s | Debugging measurement, **not an accepted proof timing** |
| Rental balance decrease | $4.3114 | Setup, builds and qualification; observed account ledger difference |
| Remaining account credit | $16.3352 | Snapshot immediately after deletion |
| Rental cleanup | Pod deleted; pod list empty; settled spend $0/hour | See `cleanup-receipt.json` |

The final receipt is [qualification-v14/receipt.json](hardware/qualification-v14/receipt.json)
and the strict rejection is in [process.log](hardware/qualification-v14/process.log).
The receipt's original `started_utc` field was captured after the child finished;
it is a completion timestamp in these archived runs. Monotonic elapsed time and
exit status are unaffected. The reusable driver now records separate timestamps.

### Implemented and checked

- Repair current shared deduction contract imports and CUDA AOT enum drift.
- Correct composite witness scheduling: root-to-member internal dependencies
  belong to one launch, while ordering between distinct launches remains checked.
- Remove the artificial 510-power cap; a hardware check verifies all 1,325 powers.
- Retain quotient coordinates through decommit because the first FRI layer aliases
  them. Qualification then completes trace and FRI openings.
- Retain the terminal bundle from ingress through final assembly. Its header,
  roots, samples and nonce captures previously overlapped earlier allocations.
  Qualification then preserves the header and exposes the genuine degree failure.
- Add strict proof publication and diagnostic receipts with explicit scope,
  protocol, input/source/product identities and no production eligibility claim.
- Export the canonical fixed-column coefficient pack with bounded host memory;
  its SHA-256 matches the prior pack byte for byte.
- Add an opt-in content/toolchain/SM keyed CUDA archive cache. Validate archive
  and cubin hashes before reuse and publish the receipt last. Zig-only rebuilds
  take about one minute on this rental, versus four to five minutes rebuilding
  the complete native archive.

Seven hardware correctness checks pass: 1,325 challenge powers, 12 FFT/LDE
shapes, BLAKE2s commitments, all 279 pinned SN2 constraint placements, six quotient
paths, OODS, and FRI/PoW. These checks exercise isolated components and do not
establish correctness of the assembled proof. Receipts:
[component checks](hardware/cairo-component-smokes/receipt.json),
[PCS checks](hardware/cairo-pcs-smokes/receipt.json).
The constraint evaluator records 271 authenticated AOT loads, eight cache hits,
zero missing entries, zero runtime compilations and zero CPU fallbacks.

Focused Linux Zig checks pass for controller ownership (2/2) and the resident
inventory lifetime regressions (2/2, latest v14). Local Python source/build checks
pass (32), archive/builder checks pass (23), and build-cache checks pass (2 after
updating the fixture's shared-contract input). These overlapping groups are not
a count of unique tests. The full repository suite was not run.

### Next work, ordered by evidence

1. Isolate the assembled FRI degree failure. Compare real SN2 stage outputs
   against the Rust/CPU oracle in order: trace and interaction, composition,
   OODS samples, quotient, FRI folds and final polynomial. Existing small kernel
   checks cannot substitute for this comparison. Preserve the degree gate.
2. Emit a full compact envelope and obtain independent verifier acceptance;
   qualify the current Cairo revision and production input path rather than
   declaring the pinned SN2 diagnostic production-ready.
3. Reduce the allocation plan before renting a 5090. The 16.62 GB retained
   lookup allocation, 24.86 GB main/interaction evaluations, 12.43 GB corresponding
   coefficients, 6.44 GB progressive commitment workspace and full Merkle slabs
   are the largest opportunities. Port bounded Merkle retention, writer scratch
   reuse and the public cache policy from the CPU/Metal implementation, then
   measure the actual CUDA peak with accepted proofs.
4. Add persistent runtime/arena and preprocessing reuse, plus full witness-to-proof
   timing. Queueing, cold starts and failed retries belong in production economics.
5. Qualify device support before testing cheaper cards: the current product is
   SM90-specific and the builder's two-digit SM parser rejects SM120. A Blackwell
   compile and device run are required; an SM string change alone is insufficient.
6. Benchmark accepted throughput and occupancy on a card that fits, with a frozen
   input/security configuration. At $3.503/hour, a fully utilized H100 must average
   below 1.285 seconds per accepted serial proof to beat the user's $0.00125 target.
   A quoted $0.99/hour 5090 would have a 4.545-second threshold before storage,
   while still needing to meet end-to-end latency well under five seconds.

The concrete economic finding is that the current CUDA allocation policy rules
out a single 5090. There is no demonstrated GPU economic win yet. The remaining
credit is preserved for a further qualification once the degree failure is
localized, instead of spending it on failed repeated timings or a card that
cannot fit the current plan.
