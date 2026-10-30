# Bounded original groups

This inactive protocol combines independently sized execution cohorts into one
original STARK. It retains each cohort's exact 23-column endpoint main root for
the late global RAM bridge. It does not yet constitute a complete block proof.

The execution builder is
`src/frontends/riscv/prover/block_v8_endpoint_group_execution_v1.zig`.
`block_v8_endpoint_group_proof_v1.zig` proves and freshly verifies the group;
`block_v8_endpoint_group_statement_wire_v1.zig` transports public metadata.

## Work removed

A group has one ROM provider, one six-bus lookup provider and one endpoint
Range16 provider, instead of proving those providers for every cohort. The
cohorts still build their actual native witnesses once. Endpoint main trees
remain separate, so the late bridge can open their existing roots under its
independently bound global challenge without reconstructing wide native rows.

The original proof count falls from N to one within each group. This does not
imply an N-fold reduction in hash work: native main columns, per-cohort endpoint
columns and per-cohort interaction constraints still have to be committed and
proved. The first real-window experiment must measure the resulting tradeoff.

## Exact relation closure

All public members, independently derived layouts, frame and CPU boundaries,
ELF/security policy and first-round roots enter the group identity before the
common epoch draws. Range, lookup and ROM requests use shared challenges and
bounded positive census totals. Those provider residuals can be aggregated.

CPU state, registers and local RAM close separately for each member. An error
of delta in one member cannot cancel an error of minus delta in another. The
native and caller halt constraints remain per-access constraints, including a
write of one followed by a clearing write before the final endpoint. Endpoint
net changes alone are never the halt policy.

A source becomes eligible for the late bridge only after the receiver verifies
the actual group original once. The receiver exports all member endpoint roots
and the group's outer CPU boundary. Metadata decoding or an endpoint tree lease
is not a proof receipt. A coordinator must check all group boundaries and exact
source coverage, then close the bridge against the independent global RAM
proof. Recursive reduction must preserve those obligations.

## Geometry and ownership

For N native members and M caller-bearing members, the original has
`4*N + 3*M + 7` trace trees. N is bounded to eight; M is at most N. The fixed
roster and the native/endpoint/caller roots are explicit. The optional mixed
profile is designed into the layout but has not yet been runtime-qualified as
a Group.

The producer keeps at most eight native witnesses while building the shared
providers. It transfers each native owner out of its real runner segment and
releases the runner envelope. After the original is serialized, all native
witnesses, provider stages, original proof objects and initial public metadata
are destroyed. Fresh metadata admission and original verification use only
serialized bytes plus the independently pinned ELF/security policy. The
returned result owns only public metadata, bytes, verified sources and narrow
endpoint matrices/tree leases needed by the later bridge.

The Group protocol uses explicit tree indices for retained endpoint leases.
The historical Local protocol continues to use tree index two. Both routes
require exact root, 23-column width, raw/LDE geometry, coefficient retention,
owned backing and a hard retained-byte limit.

## Qualification

The genuine two-cohort canonical gate is:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v8_endpoint_group_proof_test_root.zig -OReleaseSafe
```

The 2026-10-30 run passed 461 tests, skipped one and failed none. The actual
continuous eight-cycle fixture produced one 401,832-byte original. Its 0.541 s
core / 0.598 s whole diagnostic timing is not a block-performance benchmark.
The gate freshly verifies once after producer destruction, checks all returned
sources, rejects compensated per-member register/RAM residuals, and exercises
wrong-index/root/resource-limit and retained-tree lifetime cases. Evidence is
under `vectors/reports/riscv-cpu-architecture-20261029/group-original-qualification/`.

The separate execution gate exercises the real session/witness builder and
bounded metadata transport. The opt-in benchmark uses `STWO_B8_GROUP_*`
variables with the same pins and input suffixes as the existing Local execution
benchmark. It saves `group.proof`, `group.json` and `report.json`. Its declared
scope remains a native-only nonterminal window with **global RAM open**, until
the bridge/global proof and recursive group receiver are integrated.

## First real window

The frozen ReleaseFast executable subsequently proved the retained 4,194,304
instruction window as one eight-member Group (524,288 cycles per cohort), with
39 trace trees. It produced a 5,587,460-byte original. The measured request path
was 20.941 s: 2.945 s preparation, 15.762 s original production (including
10.784 s core proving) and 1.996 s fresh byte verification. Charged peak storage
was 12,158,340,617 bytes. This deliberately trades higher simultaneous witness
storage for fewer originals and shared providers.

All eight endpoint roots, counts and frames match the previously qualified
separate-local bundle byte for byte. The source-only measurement still leaves
global RAM open. The independent Group/bridge/compact-global pipeline and its
file-only receiver are separate qualification work; a recursive Group root
must also be implemented before claiming a complete recursive block result.
Evidence: `vectors/reports/riscv-cpu-architecture-20261029/native-4194304-group-8x524288/`.

## Explicit wider native profile

The separately versioned `native_wide_v2` Group profile permits up to 32
native-only members. It has at most 135 trace trees and 67 component parts,
within the existing 256-tree/part dynamic placement limits. Mixed groups keep
the original V1 eight-member profile. Native cohort geometry is independent:
the first wide experiments still use 524,288 cycles per cohort.

The default `compact_v1` framing, keys, envelope and metadata schema remain
unchanged. V2 adds its own domain prefix (including the finite 32-member bound),
`B8G2P001`/`B8G2S001` envelope and explicit metadata schema. Relabeling either
profile's metadata cannot admit the other profile's original. Increasing a
resource limit never implicitly selects this protocol.

`block_v8_endpoint_group_pipeline_v1.zig` first generates one Group original
without a redundant self-verification. Its generation-only result has a void
verified field and cannot be used as a verified-source summary. It then proves
the same-root late bridge and compact global memory, serializes all five
artifacts, destroys every producer proof/scope/endpoint tree, and runs the
file-only receiver. That receiver verifies each Group once, exports all its
members, checks complete ordered CPU/frame coverage, and closes bridge/global
RAM. The returned theorem covers the declared nonterminal window; it is still
not a recursive single root or terminal block proof.

The opt-in complete-bundle benchmark and pinned launcher are:

```sh
python3 scripts/v8_real_endpoint_group_bundle.py --help
```

The same frozen benchmark executable supports V1 4M/eight-cohort closure and
explicit `--native-wide` 8M/16-cohort or 16M/32-cohort closure. The runner checks
binary/capture/ELF/snapshot pins, exact geometry and artifact hashes, records
stage timers and peak charged storage, and supports `--validate-only` to finish
publication checks without re-executing a successful expensive proof.

## Complete-bundle scaling: measured tradeoff

The canonical CPU file-only receiver has now accepted the complete three-original
bundle at 4M, 8M and 16M instructions. The respective inner bundle times are
24.934 s, 48.317 s and 90.324 s; charged host peaks are 12.192 GB, 24.024 GB
and 45.610 GB. Including input loading and publication gives 24.989 s,
48.353 s and 90.368 s. All use 524,288-cycle native cohorts; the 16/32-member
cases explicitly select the new V2 consolidation domain and wire format.

This is a proof-roster improvement, not yet a latency win. The retained sparse
Local pipeline with two concurrent source jobs completes 16M in 80.865 s,
compared with the new Group's 90.368 s at the same outer timing boundary.
Grouping reduces original count from 34 to three but consumes about 8.93x its
charged host peak. Its source core timer falls from a 66.350 s **sum of
potentially overlapping Local jobs** to 46.412 s in one Group; this does not
imply a wall-time speedup. The next required measurement is complete recursive
closure of the grouped sources, where fewer FRI/PCS instances may matter.

All source reports, exact comparison ratios and the unified CSV are under the
campaign's `group-complete-bundle-window-times.csv`,
`group-complete-bundle-comparison.json` and `MEASUREMENTS.md`. No new proving
run was used to create those records.
