# Session 17: SN2 compact quotient and dual-PoW runtime

Date: 2026-07-25

## Scope

This increment closes two product-ABI gaps found while binding the complete
SN2 Cairo proof to the AIR-neutral resident CUDA stages:

1. variable-height quotient numerators must remain compact through the final
   quotient combine; and
2. Cairo's interaction PoW occurs during trace commitment, before the normal
   query PoW stage.

It does not claim a complete SN2 CUDA proof or proving throughput.

## Compact quotient combine

The existing CUDA numerator accumulator already accepted compact source
descriptors, but the final combine required every partial numerator to use the
largest group's fixed stride. SN2 has 19 quotient groups spanning logs 4
through 23, so padding all groups to log 23 is the wrong storage contract.

The resident quotient ABI now has a second, general combine entry point:

`stwo_combine_quotients_from_compact_numerators_on`

It consumes:

- one authenticated log per partial numerator;
- a monotone `u64` offset table with `group_count + 1` entries;
- four compact coordinate slabs with the exact summed word extent; and
- the unchanged sample points and first-linear-term accumulators.

The original fixed-stride entry point remains unchanged for uniform AIRs.
Host preparation validates every offset interval as exactly `2^log` words
before uploading the immutable table. The device kernel additionally bounds
each interval against the admitted compact slab.

The Cairo resident plan now owns:

- `quotient_source_descriptors`, with one 16-byte compact descriptor per
  logical trace column; and
- `quotient_partial_offsets`, with one `u64` boundary per quotient group plus
  the terminal boundary.

FRI layer zero now binds directly to `quotient_result_coordinates`. It no
longer allocates a second same-sized coordinate slab or requires a device copy
at the quotient-to-FRI boundary.

## Corrected resident geometry

The exact Rust-pinned SN2 plan now reports:

```text
slots=108
coefficient_cells=3717220288
lde_cells=7434440576
logical_bytes=66832193260
peak_live_bytes=58028559828
allocated_bytes=58028560620
terminal_words=2102610
decommit_words=878280
fits_h100_80gb=true
```

The prior session-14 inventory remains historical evidence. This inventory
supersedes it after adding the descriptor tables and removing the duplicate
FRI-zero allocation.

## Device evidence

The focused native quotient smoke was rebuilt with only the changed product
object replaced in the previously authenticated 4090 development archive. It
compared compact log-3/log-4 partials against the same independent CPU oracle
used by the fixed-stride path:

```text
Native CUDA quotient smoke passed: five resident stages match independent
CPU references and reject invalid ranges
```

This is a kernel parity gate, not an authenticated full-product archive or
proof benchmark. A clean authenticated AOT build remains required before the
H100 proof run.

## Dual PoW

The common runtime previously hard-coded both PoW search and transcript
absorption to `telemetry.Stage.pow`. That is correct for native AIR query PoW
but cannot represent Cairo's earlier interaction PoW.

The runtime now exposes stage-bound variants:

- `Fri.Native.grindPowAtStage`
- `Transcript.Native.absorbPowAtStage`

Only `.trace_commit` and `.pow` are admitted. Existing callers retain their
unchanged methods, which delegate to `.pow`. The checked wrapper contract test
executes search plus absorption inside `.trace_commit`, then continues through
the ordinary later proof stages.

## Remaining critical path

- bind all 39 authenticated SN2 transcript operations to resident slots;
- derive and upload the exact quotient source/group topology from the Cairo
  semantic bundle;
- execute the 57 trace launch owners and their auxiliary writer buffers;
- add mixed-height OODS and decommit opening topology;
- compact the final device proof into its exact 8,410,304-byte canonical
  payload;
- rebuild the complete authenticated AOT product;
- run the first exact SIMD/CUDA/Rust-verifier H100 proof gate.
