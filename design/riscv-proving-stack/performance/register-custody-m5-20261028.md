# Register-local custody: complete-bundle comparison

The canonical experiment reduces memory commitment area **10.07×**, but only
reduces driver wall time **1.063×**. This is a useful memory-family improvement,
not the next order-of-magnitude end-to-end improvement. Recursion is now the
primary target for this fixture.

## Measured results

Same ELF, public input, oracle, cycles, segment count and initial/final RW roots
within each pair. The guest executes SHA, Keccak and a repeated register/RAM
load/store loop. Both variants publish every base proof and the old native
recursive forest; a fresh detached receiver verifies the complete bundle.

| Canonical q70/26, 307,214 cycles, two segments | Global registers / word-v4 | Local registers / RAM2 |
|---|---:|---:|
| Sorted memory events | 737,404 | 122,981 |
| Byte-range requests | 10,323,656 | 1,721,734 |
| Memory committed M31 cells | 112,197,632 | 11,141,120 |
| Memory proof instances | 1 | 1 |
| Collection | 3.218 s | 1.530 s |
| Proving, including native recursive leaves | 33.846 s | 30.423 s |
| Remaining forest | 52.935 s | 52.720 s |
| Fresh complete verification | 2.250 s | 2.069 s |
| Driver wall | **92.250 s** | **86.743 s** |
| Memory/range proving, within proving phase | 8.296 s | 1.750 s |
| Charged allocator peak | 7.568 GB | 7.568 GB |
| Base proof files | 10 | 10 |
| Base proof file bytes | 9,732,855 | 9,159,216 |

The diagnostic q8/PoW0 pair, 20,494 cycles, also passes: events
49,276 → 8,293, memory cells 7,012,352 → 1,392,640, driver wall
27.305 → 25.646 s, charged peak 2.179 GB in both arms. Do not pool this
diagnostic pair with canonical timings.

Single samples, eight CPU workers on the M5, ReleaseFast. Peak is the shared
driver allocator's charged live allocations, not process RSS or device RAM.
Driver wall excludes shared execution preflight and source initialization;
it includes the driver invocation's setup and destruction. Named driver phases
leave a small unpartitioned remainder. Family timers overlap other work and
must not be added to the wall phases. Native leaf callbacks in the canonical
mode1 log take 10.892 and 10.642 s and are already inside proving time.

The historical 10.14× block-area model compared against a 142-cell/event
baseline. This new experiment compares the current 107-cell/event word-v4
component against 170 cells per paired RAM2 row. The padded-area ratio happens
to be similar; it is not a measurement of the retained Ethereum block.

The 10.07× ratio is padding-sensitive. Both measured workloads match this
guest-specific census: mode0 events = `12 * iterations + 124`, mode1 events =
`2 * iterations + 101`. Applying the existing power-of-two row padding predicts
that 65,536 iterations would keep mode0 at 112,197,632 cells but double mode1
to 22,282,240 cells, reducing the ratio to 5.035×. That is a geometry projection,
not another timing run. A planner must include caller/terminal events and
component padding rather than assuming that round cycle counts are optimal.

## Correctness scope

Both runs pass all 12 selected tests. The complete receiver closes native,
register, memory, caller, ROM, lookup and endpoint equations using original
base proofs. Its native forest alone remains open: neither experiment produces
a standalone recursive block root.

Negative controls reject changed register endpoint clocks and omitted window
plans. A genuine fused proof with two physical register claims changed by +1
and −1, preserving their aggregate, is rejected with `OodsNotMatching`; an
untampered clone verifies. This is adversarial replay coverage, not a formal
soundness proof or a complete malicious-prover audit.

## Design decision

Eliminating the entire 1.750 s memory/range task cannot explain another 10×
improvement in an 86.743 s job. The 52.720 s forest and 21.534 s of sequential
foreground native leaf callbacks occupy about 85.6% of this driver's wall time.
Subtracting those intervals leaves about 12.49 s, above the 8.67 s target. This
holds remaining timings fixed; it is not a new measurement or a strict
scheduling lower bound. Independent base families run concurrently with native
callbacks, and removing callbacks changes contention and overlap. It motivates
reducing base/setup work as well as recursive work.

1. Replace compulsory individual wrappers and the old forest with bounded
   direct-native batches, preserving the exact global receive equations. The
   [problem-match brief](complete-batch-problem-match-20261028.md) defines the
   first complete receiver and its explicit remaining closure boundary.
2. Choose larger native partitions by **total** native plus recursive cost.
   The [same-execution experiment](native-tiling-m5-20261028.md) measured
   12–14× lower phase sums at larger sizes; it was ALU-only and still needs a
   mixed RAM/precompile comparison. Keep component domains independent.
3. Fuse compatible native, projection and caller AIRs under joint PCS groups
   to remove transcripts, openings and FRI checks upstream of recursion. The
   current fused companion proof does not yet fuse native execution itself.
4. Complete local proofs once and bridge their authenticated narrow event
   streams into the later global relation. This requires new transcript and
   receiver semantics; caching unauthenticated event summaries is insufficient.

These changes overlap. Their isolated ratios cannot be multiplied. The next
acceptance metric is a real complete-bundle wall-time reduction, followed by
recursive closure of every global family into one standalone root.

## Reproduce

The test and archived block implementation live on `codex/ethereum-block-fast-lab`.
Run from that checkout:

```sh
STWO_REGISTER_COMPARE_ITERATIONS=61440 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_register_custody_test_root.zig \
  -OReleaseFast --test-filter 'register custody complete comparison canonical' \
  > register-q70.log 2>&1
python3 design/riscv-proving-stack/performance/register-custody-results.py \
  register-q70.log
```

[JSON](block-v6-register-custody-m5-20261028.json) retains raw integer counters,
log hashes, profile and scope; [CSV](block-v6-register-custody-m5-20261028.csv)
has one row per arm. The parser rejects incomplete runs, changed endpoint
roots, missing hostile controls, mismatched census and incorrect scope flags.
