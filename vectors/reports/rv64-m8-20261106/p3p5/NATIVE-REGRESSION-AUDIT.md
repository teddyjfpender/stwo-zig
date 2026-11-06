# Native regression audit

Status: read-only source/SQLite audit [M/D], not a new benchmark or causal
experiment. P3/P5 source is unchanged. No build, GPU job or prover was run.

The capture/native phase contains recursion in the candidate. Its increased
GPU union must not be called increased native work. The source audit finds no
native selection leak from composition-column packing or owned INTER reuse.
Earlier recursion overlap is positively observed; its contribution to native
critical-path delay remains a contention hypothesis, not isolated causal proof.

## Source boundaries

These guards also exist in frozen checkpoint `b68e02081`:

- `src/integrations/riscv_cuda/rv64/resident_composition.zig:290-310`
  (frozen lines): class planning passes `c.namespace == .outer`, and
  `selectedColumns` rejects `!outer`. Runtime selection independently requires
  `self.outer_workspace` at frozen line 1017. Native `evaluateAtBlowup` creates
  a `Job` whose `outer_workspace` defaults false; generic
  `evaluateRolesAtBlowup` explicitly passes false at frozen lines 475-477.
  Only the named outer entrypoints pass true. `outer_source_composition.zig:29`
  uses that explicit outer entrypoint. The chunk metadata assignment is in
  `outer_source.zig`'s outer artifact builder; native artifacts do not acquire
  chunk metadata merely because the process flag is set.
- A whole-`src` search finds only the definition and one production caller of
  `commitOwnedInter`: `trace_commit.zig:127` and `outer_source.zig`'s
  `Owner.interact` (frozen line 578). The normal trace-stage path supplies no
  owned-input argument. Reuse validates INTER tree index, no retirement hook,
  supported rate/capabilities, and owned lease/column identity before entry.
- This is not a claim that every candidate flag is outer-only.
  `pcs_native.zig:41-48` reads phase-retirement and compact-eager policy for the
  common PCS service; `trace_commit.zig:78-79` also selects compact eager from
  that policy. Those flags legitimately affect native as well as recursion.
  Arena size, idle cache, admission, sparse truth, sibling sessions and lane
  count also differ between the measured arms.
- `resident_ready.zig:49-79` retains host pools across native production and
  creates sibling services when recursion sessions are enabled. Each sibling
  has a distinct service/queue while sharing the physical GPU and admission.
  That permits physical overlap; it does not establish that overlap is free.

## Existing profile evidence

Raw evidence remains under `/workspace/m3/runs/m7-integrate/` on the existing
pod, with prefix
`daemon-24628607-r2-p1-inter-contributions-profile-20261106-01-` and suffixes
`06-baseline` and `07-fullstack`. All figures below use warm trial 1 [M], one
separate profiled pair, excluded from headline medians. Both profiles report
complete kernel accounting and no CUDA graph envelopes in request windows.

| Measure [M, seconds unless marked] | Baseline | Fullstack |
|---|---:|---:|
| Native prove wall from combined report | 4.599853270 | 5.354017017 |
| Capture + native interval wall | 6.791020798 | 7.655020090 |
| Whole-request kernel duration sum, GPU-s | 10.578837545 | 10.597261422 |
| Whole-request per-device kernel union, GPU-s | 10.578837545 | 10.311834358 |
| Capture/native interval kernel union, GPU-s | 4.373029420 | 5.110547081 |
| After-native interval kernel union, GPU-s | 6.205808125 | 5.191441581 |
| After-native interval wall | 5.795506390 | 5.521149312 |
| After-native busy, two-device denominator [D] | 53.53982644% | 47.01413861% |

`scripts/rv64_m7_native_ownership.py:45-51` selects only `rv64/` and `m7/pcs/`
labels, omitting the available `m7v2/domain/stage/request/ordinal/ticket`
semantic ranges. Its phase boundaries at lines 90-98 clip all device work in
that interval. Neither the phase union nor `rv64/owner/top_level_union` is
native-only. Its nested callback/controller/PCS rows are inclusive and cannot
be added; launch correlation, rather than kernel names or execution inside a
host range, assigns delayed kernels (lines 115-144).

Read-only SQLite attribution used the unique CUPTI runtime correlation and
enqueueing globalTid, then the enclosing `m7v2/` semantic range at API start.
Warm kernel correlations and semantic range matches had zero ambiguities [M].
Candidate recursion-node kernels already occupy 0.846298289 GPU-s [M, union]
before native end. Whole-request semantic recursion-node kernel duration sum
is 5.992008420 GPU-s [M], versus union 5.934047425 GPU-s [M]. Thus duration sum
and occupied union diverge under concurrent execution.

Candidate semantic native-packet and GKR-packet kernel unions are respectively
2.245139887 and 0.905592821 GPU-s [M]; 1.454520294 kernel-duration GPU-s [M]
remain unassigned by semantic ranges. These include setup/fixed activity and
must not all be assigned to native by subtraction. A separate stream audit
finds native/GKR labels exclusively on GPU streams 22-25 and recursion labels
exclusively on streams 26-33 [M, observed membership]. Assigning unmarked work
by this exclusive stream membership yields 4.456393131 native-stream GPU-s
[D, attribution inference], versus baseline's 4.373029420 pre-native GPU-s
[M, no recursion/controller ranges there]. That modest kernel increase is
much smaller than the native wall increase; it does not identify the shares
due to admission, sibling-session GPU contention, host scheduling, zero-idle
cache or the smaller arena. There is no measured node-peak result in this audit.

## Full recursion window, distinct from after-native

For the candidate, define the semantic recursion GPU-activity window as the
earliest start to latest end of kernel, memcpy or memset activity whose unique
runtime launch is enclosed by an `m7v2/recursion_node/` range. Warm Nsight-clock
endpoints are 56,069,037,660 and 62,847,122,699 ns [M]: duration
6.778085039 s [D]. Producer-relative positions are 6.215008361 through
12.993093400 s [D, inherits spool-ack UTC alignment]. Recursion activity starts
1.440011729 s before the recorded native end [D].

Over exactly this window:

- All-device kernel interval union is 6.929092411 GPU-s [M], giving
  **51.11393831% busy [D]**, denominator `2 * 6.778085039 s`. This includes
  concurrent native kernels; it is an occupancy measure, not recursion-only
  kernel cost.
- Semantic recursion-owned kernel interval union is 5.934047425 GPU-s [M],
  giving **43.77377527% busy [D]** with the same denominator. Unmarked setup
  work is excluded. Stream-membership inference would give 6.082089029 GPU-s
  and 44.86583596% [D], which is a separate inferred attribution.

The previously reported after-native metric retains its definition: exclusive
native boundary plus the existing 5 ms uncertainty band through request end.
It is 47.01413861% here [D], not the full recursion-window busy. Baseline global
admission is off and has no `m7v2/` ranges, so an exactly matched semantic-window
baseline cannot be reconstructed with this definition. None of these numbers
establishes a 54% busy gate or any end-to-end performance qualification.

## Minimal next matched preset

After the owner's P1 node/stage measurement and calibration table, use the
existing frozen all-P1 composed candidate with only
`STWO_RV64_RECURSION_LANES_PER_DEVICE: 2 -> 1` and candidate
`recursion_max_pending_authorities: 21 -> 17` [proposed]. Keep 22G, global
admission, sessions, all P1 flags, sparse truth and the physical guard; preserve
the established auto-arena baseline and its pending limit. The floor follows
`ready_dag.zig:124-132`: `max(9+2*lanes, carryBound+2*lanes+1)` for two logical
lanes. `rv64_m7_integration_stack.py:103-104` keeps the existing fullstack guard.
No bypass runner, new gate or two-lane rerun is proposed.

Label this **all-P1 single-lane composed A/B**, not composition-only timing or
an isolated flag gain. It tests whether reducing overlap helps under the
established comparison contract; sessions, arena and footprint policies remain
combined arm differences. Preserve native wall, whole GPU duration/union,
semantic full-recursion-window busy, after-native busy, byte parity and fresh
receivers. The source-only P3/P5 candidates remain off for this comparison.

Evidence hashes [M]: baseline SQLite
`04573fd8c0eed3955332e9accbf2441befa68f4af1f338decf60f7d5add6b531`;
candidate SQLite
`f07f5ff68d7a616eb8de977696b7c9ead7b972f6d9015b28201e1ac93c9e83e5`;
candidate receipt
`630fd1a01e9451886dabff50642dfb627ffc5987732acf9d90e44e4e32972e62`.
