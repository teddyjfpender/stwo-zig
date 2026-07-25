# SN PIE 2 CUDA H100 Pause Handover

Date: 2026-07-25

Status: paused by request; architecture checkpoint only; not a CUDA or Cairo
promotion.

Tracking issue: [#114](https://github.com/teddyjfpender/stwo-zig/issues/114).

## Objective

The immediate objective was one honest, end-to-end proof of Starknet SN PIE 2
through the resident Cairo CUDA product on a single H100. The proof must:

- consume the canonical adapted PIE and preprocessed columns;
- execute every admitted Cairo witness, relation, PCS, quotient, FRI, and
  decommit stage on CUDA without a CPU fallback;
- emit canonical proof bytes and a structured report;
- pass the Zig verifier and the pinned Rust Stwo verifier;
- report setup, proof, and total wall time separately;
- report proof size and digest, host RSS, device peak memory, dispatches,
  transfers, synchronization, and fallback telemetry; and
- derive MHz from the 7,977,397 executed Cairo cycles and the verified proof
  time.

This checkpoint does **not** satisfy that objective yet. No valid SN PIE CUDA
proof, verifier verdict, or proving-speed number exists at this boundary.

## Last Confirmed Boundary

The latest completed H100 run used the canonical SN PIE 2 artifacts and reached:

1. runtime and one retained proof transaction;
2. the complete resident arena and slot provider;
3. static twiddle and canonical preprocessed-column initialization;
4. preparation of all recorded, fixed, memory, and native EC writers;
5. preparation of all gather and compact preactions;
6. the exact per-component relation source registry;
7. the complete CUDA relation plan;
8. statement and transcript binding;
9. proof-session validation;
10. ingress completion and the beginning of trace generation;
11. multiplicity-destination clearing;
12. recorded writer launches 0 through 20; and
13. the native EC composite launch at ordinal 21.

The first fixed-table launch, `range_check_6` at launch ordinal 22 and component
index 41, then failed with `InvalidDeviceAddress`.

The last completed diagnostic took approximately 4.74 seconds from cold
process start to that fail-closed boundary and used approximately 861 MiB peak
host RSS. That is diagnostic startup and ingress time, not proof time.

## Defects Found And Fixed

The short H100 loop found several correctness and ownership defects that
ordinary unit gates did not expose.

### Compact witness ABI ownership

The product now owns a compact-v2 witness overlay rather than modifying the
pinned vendor kernel. Its descriptor is:

```text
[stride_rows, real_rows, word_base, words_per_instance, instances, dst]
```

The AOT manifest, product closure, runtime binding, poisoned-padding tests, and
native smoke coverage use the v2 symbol. The pinned v1 vendor sources remain
byte-identical.

### Cairo memory address execution table

The memory base writer previously uploaded only `address_to_id[1..]` and reused
that view as EC execution table zero. Native EC indexes this table by the
original memory address and therefore requires the address-zero sentinel.

The execution table now owns the complete canonical
`address_to_id[0..len]`. The memory trace writer receives a zero-copy subview
starting at one. Resident sizing includes the sentinel word.

### Native EC multiplicity extents

Multiplicity feed destinations are padded slabs. Native EC requires the exact
active prefix. Address, large-value, small-value, and range-check-8 count
bindings now use the geometry-authenticated prefixes.

### Native EC launch identity

The EC composite catalog hashed the raw bytes of a Zig `Launch` struct. Padding
bytes after its `u8` enum were uninitialized, so otherwise identical
catalog-time and prepare-time plans could have different identities.

Launch identities are now hashed field by field in canonical little-endian
order. A poisoned-padding regression constructs equal launches in differently
filled storage and requires equal identities.

### Relation source partitioning

The relation binder formerly repartitioned the global writer lookup slab with
one cursor. This was incorrect for `verify_bitwise_xor_12`: its fixed writer
materializes an 83,886,080-word auxiliary lookup slab, while its relation uses
16 direct base columns through the dedicated `bitwise_xor_12` layout.

The exact surplus is both:

```text
80 columns * 2^20 rows
5 words * 2^24 logical relation rows
```

Relaxing the final cursor check would have left later components shifted.
Instead, lookup relations now bind the authenticated writer view for their own
component and require an exact extent. Non-lookup relations continue to bind
the exact committed base columns. The H100 run confirmed that all relation
sources and the complete relation plan prepare after this change.

## Paused Fix: Fixed-Table Pointer Alignment

The `range_check_6` failure was traced to internal fixed-table metadata layout,
not to a bad GPU pointer or shader.

Fixed-table buffers interleave 64-bit device-pointer tables with 32-bit
metadata. `range_check_6` has an odd trace-output count. The following pointer
table therefore began at a four-byte-aligned address, and the strict runtime
correctly rejected its cast to `u64`.

The local checkpoint now:

- aligns the cursor before every non-empty device-pointer table;
- makes resident sizing simulate the same padded sequence; and
- adds an odd trace-output sizing regression (`12` words rather than the
  invalid unpadded `11`).

Local formatting, diff checks, product closure, and CUDA runtime contract tests
passed after this change. The H100 build was intentionally stopped before the
corrected binary completed, because this work was paused. The alignment fix is
therefore locally gated but **not H100 execution-validated**.

The next session should add a second odd-entry regression or direct address
assertions so cross-entry padding cannot drift independently of sizing.

## Checkpoint Decomposition

The resident bring-up initially crossed the `CONTRIBUTING.md` 850-line ceiling.
The checkpoint was not committed with exceptions or a larger baseline.
Responsibility modules were extracted without changing the proof route:

| module | before | checkpoint | extracted responsibility |
| --- | ---: | ---: | --- |
| `runtime/stages/relation.zig` | 882 | 841 | resident-source validation |
| `executor/eval/controller.zig` | 859 | 826 | product resolution |
| `executor/ingress/writer_binding.zig` | 911 | 762 | writer-view construction |
| `executor/ingress/writer_preactions.zig` | 892 | 837 | resident range and row geometry |
| `executor/trace_commit.zig` | 1,042 | 816 | shared types, cohort geometry, and identity |
| `executor/trace_writer_controller.zig` | 879 | 791 | controller identity |
| `request_compiler.zig` | 974 | 849 | SN2-only test fixtures |

The 13-line `src/cairo_cuda.zig` package root is admitted explicitly as a
declarative facade and recorded in `conformance/decomposition-plan.md`. The
normal source-conformance gate reports no new violations. Preserve these narrow
public surfaces and continue extracting ownership before adding unrelated
behavior.

## Remaining Critical Path

Resume only this ordered path before any optimization work:

1. Build the `stwo-cairo-cuda` product for SM90 from this checkpoint.
2. Run one process under an exclusive lock and confirm that every fixed-table
   writer clears trace generation.
3. Continue the same fail-fast loop through memory writers, trace commitment,
   relation execution, interaction commitment, constraint evaluation,
   composition commitment, OODS, quotient, FRI, PoW, and decommit.
4. Fix only exact semantic, extent, ownership, synchronization, or ABI defects
   exposed by that run. Do not tune kernels during bring-up.
5. Wire the CLI's existing `--output`, `--report-out`, and `--repeat` options
   into the product. The current product parses these options but does not yet
   publish the terminal proof or report and performs only one execution.
6. Write the canonical proof envelope with statement and implementation
   identities, proof byte length, and digest.
7. Verify the proof independently. The Zig verifier is defense in depth; the
   pinned Rust Stwo implementation remains the final correctness oracle under
   `CONTRIBUTING.md`.
8. Require strict AOT, zero fallback attempts and completions, one terminal
   D2H proof read, no intermediate host reads, deterministic proof bytes, and
   complete stage telemetry.
9. Only after a verified proof exists, collect three warmed samples and report
   the median proof time and:

   ```text
   MHz = 7,977,397 cycles / proof_seconds / 1,000,000
   ```

10. Keep setup, proof, total wall, host RSS, device peak memory, and proof size
    separate. Do not call cold ingress time proving time.

## Restart Boundary

The canonical local artifacts used by the paused H100 session were:

```text
SN PIE input: sn2_cuda_mvp.stwzcpi
preprocessed pack entries: 161
preprocessed pack bytes: 2,172,407,516
preprocessed pack SHA-256:
4d4fda06dfa3bca19554510a158f6c50abad06a74d29c17885ed4cbb88ada34d
executed cycles: 7,977,397
```

The production invocation remains:

```sh
export STWO_CAIRO_CUDA_ARTIFACT_DIR=/absolute/path/to/sn2-artifacts
export STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS=/absolute/path/to/stwo-cairo-canonical-preprocessed.stwzppc

./zig-out/bin/stwo-cairo-cuda prove \
  --backend cuda \
  --input "$STWO_CAIRO_CUDA_ARTIFACT_DIR/sn2_cuda_mvp.stwzcpi" \
  --output "$STWO_CAIRO_CUDA_ARTIFACT_DIR/sn2.proof" \
  --report-out "$STWO_CAIRO_CUDA_ARTIFACT_DIR/sn2.report.json" \
  --repeat 1
```

Run only one proof process per device while completing bring-up.

## Evidence And Diagnostics

The preceding session notes in this directory record the resident architecture,
constraint parity, relation parity, PCS binding, quotient, FRI, and terminal
route decisions. The paused remote diagnostic filenames were:

```text
sn2-contract-canonical.out
sn2-relation-extent.out
sn2-relation-views.out
sn2-exec-boundary.out
sn2-launch-diagnostic.out
```

These logs are diagnostic and machine-local. They are not benchmark evidence.

## Explicit Non-Claims

At this checkpoint:

- SN PIE 2 has not completed a CUDA proof;
- no proof has been accepted by either verifier;
- no SN PIE CUDA MHz value is valid;
- the fixed-table alignment repair has not run on the H100;
- CLI proof/report publication is incomplete;
- repeated and streaming proofs are out of scope; and
- no CUDA board or autoresearch workload should be activated or promoted from
  this checkpoint.

The merged code must remain fail-closed and disabled for promotion until the
remaining acceptance gates are satisfied.
