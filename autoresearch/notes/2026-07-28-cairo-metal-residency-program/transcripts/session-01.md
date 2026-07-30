# Session 01 — Phase 0: Metal residency baseline and design

Reasoning-first. Implementation model: Claude Opus 4.5. Orchestration:
Claude Fable 5. Budget: 120 minutes. Head: `cfad207b`, clean.

## Order of work, and why

The deliverables have a dependency the brief does not state: the design cannot
be priced without the baseline, and the baseline runs are wall-clock-bound and
must run on a quiet host. So the builds went first and in the background, the
machinery survey was fanned out to parallel read-only agents, and I read the
four mandatory context notes while both proceeded. The two long poles then
overlapped instead of serializing.

Host hygiene note recorded at the time: `pgrep` during the Metal build found an
unrelated `zig build registry-parity` running from a *different* worktree
(`~/code/cryptography/stwo-zig-extra/stwo-zig`). It had exited before the first
timed sample. `loadavg` is reported per workload in the note rather than
asserted to be clean.

## Two protocol decisions taken before any measurement

**Caches off.** The preprocessed artifact caches (campaign 1 inc 9, campaign 2
inc 2.1) are default-on in the product. Profiling with them on would have priced
residency against a baseline that already contains a landed lever, and campaign
1 explicitly recorded that a cache-hit lane compares a warmed serving process
against a cold Rust one. So: `STWO_CAIRO_PREPROCESSED_CACHE=0` everywhere, and
the cache credited as its own separate line in the projection. This turned out
to matter more than expected — it is the difference between a 6.94x and a 3.13x
device requirement, i.e. it decided a design conclusion, not just a number.

**A CPU run per workload as a placement oracle.** The brief asks for a
host-vs-device attribution table. I could have assigned stages to buckets from
the capability contract and the notes. Instead each workload got one CPU run so
the assignment could be *measured*: a stage whose Metal and CPU times agree is
host work. This cost four extra runs and bought three things — it reproduced
`capabilities.zig:23-27` from timing alone (so the table rests on evidence), it
found two facts the contract does not contain, and it supplied the device-speedup
estimate that the whole Amdahl analysis needs.

## Raw numbers

Exploratory probe first, to learn the stage schema before committing to a
harness. Two schema corrections were needed: `timing.execute_ns` not
`execution_ns`, and `backend_evidence` not `backend`. First harness run died on
the former; fixed and rerun.

```
### all-opcodes  loadavg=(3.37, 2.58, 2.45)
  warmup metal prove=1264.776 sha=79ae76e1ac0c
  metal r0 prove= 1273.169 wall= 1.367 sha=79ae76e1ac0c
  metal r1 prove= 1295.992 wall= 1.395 sha=79ae76e1ac0c
  cpu   r0 prove= 1494.885 wall= 1.984 sha=79ae76e1ac0c
### pedersen-aggregator  loadavg=(5.02, 2.94, 2.58)
  warmup metal prove=1446.931 sha=99ce64aac828
  metal r0 prove= 1434.482 wall= 1.525 sha=99ce64aac828
  metal r1 prove= 1471.999 wall= 1.571 sha=99ce64aac828
  cpu   r0 prove= 1672.860 wall= 1.761 sha=99ce64aac828
### arithmetic-2m  loadavg=(6.14, 3.21, 2.68)
  warmup metal prove=1971.643 sha=25e5719f4c57
  metal r0 prove= 1940.441 wall= 2.684 sha=25e5719f4c57
  metal r1 prove= 1945.614 wall= 2.705 sha=25e5719f4c57
  cpu   r0 prove= 2826.533 wall= 3.591 sha=25e5719f4c57
### memory-7m  loadavg=(6.29, 3.33, 2.73)
  warmup metal prove=4491.234 sha=e3317e55a5db
  metal r0 prove= 4498.212 wall= 6.639 sha=e3317e55a5db
  metal r1 prove= 4727.149 wall= 6.917 sha=e3317e55a5db
  cpu   r0 prove= 6667.627 wall= 8.864 sha=e3317e55a5db
```

Two-run spread 1.003-1.051x. Every CPU/Metal pair byte-identical. 74-79
dispatches, `cpu_fallbacks: 0`, `accelerated_without_fallbacks` on all four.
Three campaign digests reproduced exactly; the `test_data` pedersen row is a new
digest (`99ce64aac8281e6b…`) since the corpus `pedersen.json` still
`SegmentPointerOverflow`s.

Placement oracle output (Metal/CPU per stage) is in the note §1.2. It came out
cleanly bimodal — five stages at 0.92-1.21 and six at 0.23-0.59 — which is a
stronger separation than I expected and makes the bucketing unambiguous.

## The number that reframed the deliverable

The brief says "clear >=1.6x on the portfolio geomean". I nearly projected
against 1.6x. But 1.6x *faster than Rust* is not 1.6x faster than *now*: campaign
2 closed with Metal at 1.105x slower than Rust, so the required Metal
improvement is 1.105 x 1.6 = **1.768x**. Everything downstream depends on this,
because 1.768x is above where the three phases land at the measured device
speedup and 1.6x is below it. The same evidence supports "the program works" or
"the program is short by 8%" depending on which number you use.

## Deriving a device estimate instead of asserting one

An Amdahl table with the migrated stages at zero is an upper bound, not a
projection, and the brief explicitly asks for device-time estimates "derived
from device throughput on comparable native kernels". The honest source at this
commit is the stages that have *already* been migrated: `main_trace_commit`
2.36x, `interaction_trace_commit` 2.50x, `preprocessed_materialize_and_commit`
2.39x. Taking the two trace commits gives S = 2.43x.

I want to be explicit that S is conservative in a statable way rather than
vaguely: those ratios *include* the host→device column upload that residency
removes, and a Merkle commit is hash-bound where composition is multiply-bound.
The upper bracket is the fused raw-quotient kernel's measured 6.37x. So S and 2S
bracket a range with measured endpoints at both ends.

Result: ideal residency + caches = 2.502x (not Amdahl-blocked); at S + caches =
1.632x (short of 1.768x by 8.3%); required device speedup = 3.13x with caches,
6.94x without. That last pair is the most decision-relevant output of the whole
increment — it converts "productize the cache" from campaign 2's fill-in work
into a precondition.

## The survey finding I did not expect

The three fan-out survey agents did not return inside the budget, so I ran the
load-bearing questions directly. The first grep overturned the brief's premise.

I went looking for the predicate that makes the resident path "SN2-only rather
than live-geometry" and found that **every `sn_pie_2_*` reference in `src/` is
inside a `test` block** — verified by resolving the nearest enclosing
declaration for each hit, not by eyeballing. Then: `arena_binding.zig` (2,502
lines, the resident orchestrator) has no non-test consumer except a benchmark
and the planner tool, and the product prove path
(`prover/transaction.zig`) is 71 lines that import neither it nor anything under
`resident/`.

So there is no SN2-only *product* path to generalize. There is a ~4,800-line
resident subsystem that no proof executes, and a product that is the generic
host frontend with a Metal PCS backend. That is a much better starting position
than the brief assumed, and it changes Phase 1 from "write resident kernels" to
"wire an existing subsystem onto live geometry".

The SN2-ness then localized to exactly one thing:
`schedule: []const std.json.Value` in the two resident entry-point signatures.
Meanwhile `CairoProofPlan.init(allocator, components)` and
`StagedArenaPlanner.derive(allocator, specs)` are already geometry-parameterized
— so the planner is not the blocker, the schedule derivation is. And the SN2
vectors can serve as the derivation's regression oracle, which turns the fixture
from a constraint into a free correctness check.

## Fiat-Shamir, confirmed rather than assumed

`transaction.zig` 243→250→253→255→267: base commit, root mixed into the channel,
grind, `drawLookupElements`, then `interaction_trace.build(..., z, alpha, ...)`.
The host-visible value that must return from the device before interaction can
start is the base Merkle root — 32 bytes, not a plane. So it constrains
scheduling (three epochs minimum), not placement, as the brief hypothesized.

The non-obvious consequence: this is the argument that witness and interaction
must move *together*. Witness-on-device with interaction-on-host would have to
download the lookup planes across that boundary, and campaign 2 already priced
those at 3,420 MB on memory-7m. That is a design constraint derived from the
transcript, not a preference.

I also noted `Engine.commit` / `Engine.flushPendingCommit` are already
backend-dispatched comptime hooks — so residency needs three more hooks of an
existing kind, not a new dispatch mechanism, and the host default keeps the CPU
lane byte-identical by construction.

## What I would flag to the orchestrator as weakest

The buffer/transfer inventory is open. It is the thing that would tighten S, and
S is what the entire feasibility question turns on. Everything else in the note
is either measured here or cited to a prior increment; that one item is a hole I
am naming rather than filling. The other honest gap: four rows, not seven, and
the two unmeasured mid-size rows are where I would least confidently extrapolate.
